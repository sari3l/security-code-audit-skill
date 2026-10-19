import {
  discoverConnectors,
  mapOperationArguments,
  publicConnector,
  selectRemoteTool,
} from "./connectors.mjs";
import { openConnectorSession, ConnectorFailure } from "./remote-mcp.mjs";
import {
  mergeAndScoreCandidates,
  normalizeFetchResult,
  normalizeSearchResult,
} from "./results.mjs";

function now() {
  return new Date().toISOString();
}

function redactSecret(value, secret) {
  if (!secret) return value;
  if (typeof value === "string") return value.split(secret).join("[REDACTED]");
  if (Array.isArray(value)) return value.map((item) => redactSecret(item, secret));
  if (!value || typeof value !== "object") return value;
  return Object.fromEntries(
    Object.entries(value).map(([key, child]) => [key, redactSecret(child, secret)]),
  );
}

function redactedErrorMessage(error, secret) {
  const message = error instanceof Error ? error.message : String(error);
  return redactSecret(message, secret).slice(0, 1000);
}

function baseContext(anchorBundle) {
  return {
    schema_version: "requirements-context.v1",
    generated_at: now(),
    status: "not_configured",
    anchor_summary: {
      change_references: (anchorBundle.change_references ?? []).map((item) => item.canonical),
      git: {
        branch: anchorBundle.git?.branch ?? null,
        base_commit: anchorBundle.git?.base_commit ?? null,
        head_commit: anchorBundle.git?.head_commit ?? null,
      },
      explicit_ids: anchorBundle.explicit_ids ?? [],
      components: anchorBundle.components ?? [],
      symbols: anchorBundle.symbols ?? [],
      routes: anchorBundle.routes ?? [],
      query_count: anchorBundle.query_plan?.length ?? 0,
    },
    query_plan: anchorBundle.query_plan ?? [],
    connector_statuses: [],
    query_log: [],
    documents: [],
    conflicts: [],
    handling: {
      source_trust: "untrusted_external_context",
      may_narrow_audit_scope: false,
      no_match_proves_no_requirement: false,
      credentials_stored: false,
      full_documents_stored: false,
    },
  };
}

function connectorSelection(discovery, connectorIds) {
  const requested = Array.isArray(connectorIds) && connectorIds.length > 0 ? new Set(connectorIds) : null;
  return discovery.connectors.filter((connector) => connector.enabled && (!requested || requested.has(connector.id)));
}

function connectorStatus(connector, status, details = {}) {
  return {
    connector_id: connector.id,
    display_name: connector.display_name,
    status,
    endpoint: connector.transport.url,
    ...details,
  };
}

function aggregateStatus(context) {
  const statuses = new Set(context.connector_statuses.map((item) => item.status));
  if (context.documents.length > 0 && context.query_log.some((item) => item.status === "failed")) {
    return "partial";
  }
  if (context.documents.length > 0 && statuses.size === 1 && statuses.has("available")) return "available";
  if (context.documents.length > 0) return "partial";
  if (statuses.has("missing_auth")) return "missing_auth";
  if (
    statuses.has("unavailable") ||
    statuses.has("missing_tool") ||
    statuses.has("timeout") ||
    statuses.has("invalid_connector")
  ) return "unavailable";
  if (statuses.has("available")) return "no_match";
  return "not_configured";
}

export function describeConnectors({ pluginRoot, environment = process.env } = {}) {
  const discovery = discoverConnectors(pluginRoot, environment);
  const enabledConnectors = discovery.connectors.filter((connector) => connector.enabled);
  const status =
    enabledConnectors.length === 0
      ? "not_configured"
      : enabledConnectors.some((connector) => environment[connector.transport.auth.env_var])
        ? "configured"
        : "missing_auth";
  return {
    schema_version: "requirement-connectors.v1",
    status,
    connectors: discovery.connectors.map((connector) => publicConnector(connector, environment)),
    errors: discovery.errors,
    security: {
      discovery_scope: "plugin_local_connectors_only",
      executable_connectors_allowed: false,
      credentials_returned: false,
    },
  };
}

export async function searchRequirements(
  { anchor_bundle: anchorBundle, connector_ids: connectorIds },
  {
    pluginRoot,
    environment = process.env,
    sessionFactory = openConnectorSession,
  } = {},
) {
  if (!anchorBundle || typeof anchorBundle !== "object") {
    throw new Error("anchor_bundle is required");
  }
  const context = baseContext(anchorBundle);
  const discovery = discoverConnectors(pluginRoot, environment);
  const connectors = connectorSelection(discovery, connectorIds);
  context.connector_errors = discovery.errors;
  context.connector_statuses.push(
    ...discovery.errors.map((error) => ({
      connector_id: error.connector_id,
      status: "invalid_connector",
      code: error.code,
      message: error.message,
    })),
  );
  if (connectors.length === 0) {
    context.status = aggregateStatus(context);
    return context;
  }

  const candidates = [];
  for (const connector of connectors) {
    const envVar = connector.transport.auth.env_var;
    if (!environment[envVar]) {
      context.connector_statuses.push(
        connectorStatus(connector, "missing_auth", {
          code: "missing_auth",
          auth_env_var: envVar,
          message: `${envVar} is not configured`,
        }),
      );
      continue;
    }

    try {
      await sessionFactory(
        connector,
        async (session) => {
          const operation = connector.operations.search;
          const toolName = selectRemoteTool(operation, session.tools);
          if (!toolName) {
            context.connector_statuses.push(
              connectorStatus(connector, "missing_tool", {
                code: "missing_search_tool",
                advertised_tools: session.tools.map((tool) => tool.name).sort(),
                expected_tools: operation.tool_candidates,
              }),
            );
            return;
          }

          let completed = 0;
          const failureCodes = [];
          const queryLimit = connector.limits?.max_queries ?? 4;
          const resultLimit = connector.limits?.max_results_per_query ?? 8;
          const queryEntries = (anchorBundle.query_plan ?? []).slice(0, queryLimit);
          for (const queryEntry of queryEntries) {
            const startedAt = Date.now();
            try {
              const result = await session.callTool({
                name: toolName,
                arguments: mapOperationArguments(operation, {
                  query: queryEntry.query,
                  limit: resultLimit,
                }),
              });
              const normalized = redactSecret(
                normalizeSearchResult(result, queryEntry.query, connector.id),
                environment[envVar],
              ).slice(0, resultLimit);
              candidates.push(...normalized);
              completed += 1;
              context.query_log.push({
                connector_id: connector.id,
                query: queryEntry.query,
                source: queryEntry.source,
                status: "completed",
                result_count: normalized.length,
                duration_ms: Date.now() - startedAt,
              });
            } catch (error) {
              failureCodes.push(error.code ?? "tool_error");
              context.query_log.push({
                connector_id: connector.id,
                query: queryEntry.query,
                source: queryEntry.source,
                status: "failed",
                code: error.code ?? "tool_error",
                message: redactedErrorMessage(error, environment[envVar]),
                duration_ms: Date.now() - startedAt,
              });
            }
          }
          const attempted = queryEntries.length;
          const terminalStatus =
            attempted > 0 && completed === 0
              ? failureCodes.every((code) => code === "timeout")
                ? "timeout"
                : "unavailable"
              : "available";
          context.connector_statuses.push(
            connectorStatus(connector, terminalStatus, {
              search_tool: toolName,
              queries_attempted: attempted,
              queries_completed: completed,
              queries_failed: failureCodes.length,
            }),
          );
        },
        environment,
      );
    } catch (error) {
      const failure =
        error instanceof ConnectorFailure
          ? error
          : new ConnectorFailure("unavailable", error instanceof Error ? error.message : String(error));
      const failureStatus = ["missing_auth", "timeout"].includes(failure.code)
        ? failure.code
        : "unavailable";
      context.connector_statuses.push(
        connectorStatus(connector, failureStatus, {
          code: failure.code,
          message: redactedErrorMessage(failure, environment[envVar]),
        }),
      );
    }
  }

  context.documents = mergeAndScoreCandidates(candidates, anchorBundle);
  context.status = aggregateStatus(context);
  return context;
}

export async function fetchRequirement(
  { connector_id: connectorId, document_id: documentId },
  {
    pluginRoot,
    environment = process.env,
    sessionFactory = openConnectorSession,
  } = {},
) {
  const discovery = discoverConnectors(pluginRoot, environment);
  const connector = discovery.connectors.find((item) => item.enabled && item.id === connectorId);
  if (!connector) {
    return {
      schema_version: "requirement-document.v1",
      status: "not_configured",
      connector_id: connectorId,
      document_id: documentId,
    };
  }
  const operation = connector.operations.fetch;
  if (!operation) {
    return {
      schema_version: "requirement-document.v1",
      status: "missing_tool",
      connector_id: connectorId,
      document_id: documentId,
      message: "connector does not declare a fetch operation",
    };
  }

  try {
    return await sessionFactory(
      connector,
      async (session) => {
        const toolName = selectRemoteTool(operation, session.tools);
        if (!toolName) {
          return {
            schema_version: "requirement-document.v1",
            status: "missing_tool",
            connector_id: connectorId,
            document_id: documentId,
            advertised_tools: session.tools.map((tool) => tool.name).sort(),
            expected_tools: operation.tool_candidates,
          };
        }
        const result = await session.callTool({
          name: toolName,
          arguments: mapOperationArguments(operation, { document_id: documentId }),
        });
        return {
          schema_version: "requirement-document.v1",
          status: "available",
          connector_id: connectorId,
          document_id: documentId,
          document: redactSecret(
            normalizeFetchResult(result, documentId, connectorId),
            environment[connector.transport.auth.env_var],
          ),
          handling: {
            source_trust: "untrusted_external_context",
            content_must_be_verified: true,
          },
        };
      },
      environment,
    );
  } catch (error) {
    const status = ["missing_auth", "timeout"].includes(error.code)
      ? error.code
      : "unavailable";
    return {
      schema_version: "requirement-document.v1",
      status,
      connector_id: connectorId,
      document_id: documentId,
      code: error.code ?? "unavailable",
      message: redactedErrorMessage(
        error,
        environment[connector.transport.auth.env_var],
      ),
    };
  }
}
