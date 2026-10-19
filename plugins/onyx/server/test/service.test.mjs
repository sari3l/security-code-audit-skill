import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { ConnectorFailure } from "../lib/remote-mcp.mjs";
import { describeConnectors, fetchRequirement, searchRequirements } from "../lib/service.mjs";

function makePluginRoot() {
  const parent = fs.mkdtempSync(path.join(os.tmpdir(), "audit-service-"));
  const root = path.join(parent, "onyx");
  fs.mkdirSync(root);
  fs.writeFileSync(
    path.join(root, "plugin.json"),
    JSON.stringify({
      schemaVersion: "1.0",
      id: "onyx",
      displayName: "Onyx Requirements",
      enabled: true,
      capabilities: ["requirements-context"],
      entrypoints: { mcp: "./.mcp.json" },
      config: "./config.json",
      lifecycle: {
        after: "architecture-and-change-recon",
        before: "security-semantic-review",
        failure: "continue",
      },
    }),
  );
  fs.writeFileSync(
    path.join(root, "config.json"),
    JSON.stringify({
      configEnv: "ONYX_AUDIT_CONFIG",
      url: "https://requirements.example.test/mcp",
      tokenEnv: "ONYX_AUDIT_TOKEN",
      searchTool: "search_documents",
      fetchTool: "fetch_document",
      arguments: {
        query: "query",
        limit: "limit",
        documentId: "id",
      },
    }),
  );
  return root;
}

const anchorBundle = {
  explicit_ids: ["SEC-482"],
  components: ["payment-service"],
  symbols: ["approveRefund"],
  routes: ["/refunds/:id/approve"],
  data_entities: ["refunds"],
  configuration_keys: [],
  change_themes: ["finance approval"],
  project_names: ["payments"],
  architecture_context: { business_flows: ["large refund approval"] },
  query_plan: [
    { query: "SEC-482", source: "explicit_id", weight: 100, anchors: ["SEC-482"] },
    {
      query: "payment-service finance approval",
      source: "component_theme",
      weight: 75,
      anchors: ["payment-service", "finance approval"],
    },
  ],
};

const mergeRequestAnchorBundle = {
  ...anchorBundle,
  explicit_ids: [],
  project_names: ["panacea-backend"],
  change_references: [
    {
      kind: "gitlab_merge_request",
      raw: "merge_requests/1412",
      canonical: "panacea-backend/merge_requests/1412",
      project: "panacea-backend",
      iid: "1412",
    },
  ],
  query_plan: [
    {
      query: "panacea-backend MR1412 requirement_skills.md",
      source: "change_reference_requirement",
      weight: 110,
      anchors: ["panacea-backend/merge_requests/1412"],
    },
  ],
};

test("reports connector readiness without returning the token", () => {
  const registry = describeConnectors({
    pluginRoot: makePluginRoot(),
    environment: { ONYX_AUDIT_TOKEN: "top-secret" },
  });
  assert.equal(registry.connectors[0].auth.configured, true);
  assert.equal(registry.status, "configured");
  assert.ok(!JSON.stringify(registry).includes("top-secret"));
});

test("reports missing_auth during discovery so callers can skip the connector workflow", () => {
  const registry = describeConnectors({
    pluginRoot: makePluginRoot(),
    environment: {},
  });
  assert.equal(registry.status, "missing_auth");
  assert.equal(registry.connectors[0].enabled, true);
  assert.equal(registry.connectors[0].auth.configured, false);
});

test("uses the user config selected by the service environment", () => {
  const pluginRoot = makePluginRoot();
  const userConfigPath = path.join(path.dirname(pluginRoot), "onyx.json");
  fs.writeFileSync(
    userConfigPath,
    JSON.stringify({ url: "https://custom-onyx.example.test/mcp" }),
  );
  const registry = describeConnectors({
    pluginRoot,
    environment: {
      ONYX_AUDIT_CONFIG: userConfigPath,
      ONYX_AUDIT_TOKEN: "top-secret",
    },
  });
  assert.equal(registry.status, "configured");
  assert.equal(registry.connectors[0].endpoint, "https://custom-onyx.example.test/mcp");
  assert.equal(registry.connectors[0].auth.configured, true);
  assert.ok(!JSON.stringify(registry).includes("top-secret"));
});

test("queries the first advertised tool and scores explicit-ID matches high", async () => {
  const calls = [];
  const context = await searchRequirements(
    { anchor_bundle: anchorBundle },
    {
      pluginRoot: makePluginRoot(),
      environment: { ONYX_AUDIT_TOKEN: "top-secret" },
      sessionFactory: async (_connector, callback) =>
        callback({
          tools: [{ name: "search_documents" }],
          callTool: async (request) => {
            calls.push(request);
            return {
              structuredContent: {
                results: [
                  {
                    id: "doc-482",
                    title: "SEC-482 Large refund approval",
                    snippet: "payment-service approveRefund requires a finance reviewer",
                    status: "approved",
                    url: "https://requirements.example.test/docs/doc-482",
                  },
                ],
              },
            };
          },
        }),
    },
  );

  assert.equal(context.status, "available");
  assert.equal(calls.length, 2);
  assert.equal(calls[0].name, "search_documents");
  assert.equal(context.documents.length, 1);
  assert.equal(context.documents[0].relevance.confidence, "high");
  assert.ok(context.documents[0].relevance.matched_anchors.some((match) => match.value === "SEC-482"));
  assert.ok(!JSON.stringify(context).includes("top-secret"));
});

test("reports partial when documents are returned but another query fails", async () => {
  let callCount = 0;
  const context = await searchRequirements(
    { anchor_bundle: anchorBundle },
    {
      pluginRoot: makePluginRoot(),
      environment: { ONYX_AUDIT_TOKEN: "top-secret" },
      sessionFactory: async (_connector, callback) =>
        callback({
          tools: [{ name: "search_documents" }],
          callTool: async () => {
            callCount += 1;
            if (callCount === 2) throw new ConnectorFailure("timeout", "search timed out");
            return {
              structuredContent: {
                results: [{ id: "doc-482", title: "SEC-482 Large refund approval" }],
              },
            };
          },
        }),
    },
  );
  assert.equal(context.status, "partial");
  assert.equal(context.documents.length, 1);
  assert.equal(context.connector_statuses[0].status, "available");
  assert.equal(context.connector_statuses[0].queries_completed, 1);
  assert.equal(context.connector_statuses[0].queries_failed, 1);
});

test("promotes an exact project/MR URL and demotes a same-project MR collision", async () => {
  const context = await searchRequirements(
    { anchor_bundle: mergeRequestAnchorBundle },
    {
      pluginRoot: makePluginRoot(),
      environment: { ONYX_AUDIT_TOKEN: "top-secret" },
      sessionFactory: async (_connector, callback) =>
        callback({
          tools: [{ name: "search_documents" }],
          callTool: async () => ({
            structuredContent: {
              results: [
                {
                  id: "mr-1412-requirement",
                  title: "MR1412 requirement_skills.md",
                  url: "https://requirements.example.test/panacea-backend/MR1412/requirement_skills.md",
                },
                {
                  id: "mr-1411-index",
                  title: "MR1411 index",
                  url: "https://requirements.example.test/panacea-backend/MR1411",
                },
              ],
            },
          }),
        }),
    },
  );
  assert.equal(context.documents[0].id, "mr-1412-requirement");
  assert.equal(context.documents[0].relevance.confidence, "high");
  assert.equal(context.documents[0].relevance.change_reference_match.status, "exact");
  assert.equal(context.documents[1].id, "mr-1411-index");
  assert.equal(context.documents[1].relevance.confidence, "low");
  assert.equal(context.documents[1].relevance.change_reference_match.status, "conflict");
});

test("returns missing_auth without opening a remote session", async () => {
  const context = await searchRequirements(
    { anchor_bundle: anchorBundle },
    {
      pluginRoot: makePluginRoot(),
      environment: {},
      sessionFactory: async () => {
        throw new Error("must not connect");
      },
    },
  );
  assert.equal(context.status, "missing_auth");
  assert.equal(context.connector_statuses[0].status, "missing_auth");
});

test("redacts an authentication token echoed by a remote connector", async () => {
  const context = await searchRequirements(
    { anchor_bundle: anchorBundle },
    {
      pluginRoot: makePluginRoot(),
      environment: { ONYX_AUDIT_TOKEN: "top-secret" },
      sessionFactory: async (_connector, callback) =>
        callback({
          tools: [{ name: "search_documents" }],
          callTool: async () => ({
            structuredContent: {
              results: [{ id: "echo", title: "SEC-482 top-secret", snippet: "top-secret" }],
            },
          }),
        }),
    },
  );
  assert.ok(JSON.stringify(context).includes("[REDACTED]"));
  assert.ok(!JSON.stringify(context).includes("top-secret"));
});

test("redacts an authentication token echoed in remote search errors", async () => {
  const context = await searchRequirements(
    { anchor_bundle: anchorBundle },
    {
      pluginRoot: makePluginRoot(),
      environment: { ONYX_AUDIT_TOKEN: "top-secret" },
      sessionFactory: async (_connector, callback) =>
        callback({
          tools: [{ name: "search_documents" }],
          callTool: async () => {
            throw new ConnectorFailure("unavailable", "remote echoed top-secret");
          },
        }),
    },
  );
  assert.ok(JSON.stringify(context).includes("[REDACTED]"));
  assert.ok(!JSON.stringify(context).includes("top-secret"));
});

test("contains remote availability failures and preserves the audit continuation contract", async () => {
  const context = await searchRequirements(
    { anchor_bundle: anchorBundle },
    {
      pluginRoot: makePluginRoot(),
      environment: { ONYX_AUDIT_TOKEN: "top-secret" },
      sessionFactory: async () => {
        throw new ConnectorFailure("unavailable", "endpoint did not respond");
      },
    },
  );
  assert.equal(context.status, "unavailable");
  assert.equal(context.handling.may_narrow_audit_scope, false);
  assert.equal(context.documents.length, 0);
});

test("preserves timeout as the connector terminal status", async () => {
  const context = await searchRequirements(
    { anchor_bundle: anchorBundle },
    {
      pluginRoot: makePluginRoot(),
      environment: { ONYX_AUDIT_TOKEN: "top-secret" },
      sessionFactory: async () => {
        throw new ConnectorFailure("timeout", "endpoint timed out");
      },
    },
  );
  assert.equal(context.status, "unavailable");
  assert.equal(context.connector_statuses[0].status, "timeout");
  assert.equal(context.handling.credentials_stored, false);
  assert.equal(context.handling.full_documents_stored, false);
});

test("does not report no_match when every remote search call times out", async () => {
  const context = await searchRequirements(
    { anchor_bundle: anchorBundle },
    {
      pluginRoot: makePluginRoot(),
      environment: { ONYX_AUDIT_TOKEN: "top-secret" },
      sessionFactory: async (_connector, callback) =>
        callback({
          tools: [{ name: "search_documents" }],
          callTool: async () => {
            throw new ConnectorFailure("timeout", "search timed out");
          },
        }),
    },
  );
  assert.equal(context.status, "unavailable");
  assert.equal(context.connector_statuses[0].status, "timeout");
  assert.equal(context.connector_statuses[0].queries_completed, 0);
  assert.equal(context.connector_statuses[0].queries_failed, anchorBundle.query_plan.length);
});

test("surfaces invalid connector declarations as terminal statuses", async () => {
  const root = makePluginRoot();
  const connectorPath = path.join(root, "config.json");
  const connector = JSON.parse(fs.readFileSync(connectorPath, "utf8"));
  connector.command = "run-me";
  fs.writeFileSync(connectorPath, JSON.stringify(connector));

  const context = await searchRequirements(
    { anchor_bundle: anchorBundle },
    { pluginRoot: root, environment: { ONYX_AUDIT_TOKEN: "top-secret" } },
  );
  assert.equal(context.status, "unavailable");
  assert.equal(context.connector_statuses[0].status, "invalid_connector");
});

test("fetches a document through the configured fetch operation", async () => {
  const result = await fetchRequirement(
    { connector_id: "onyx", document_id: "doc-482" },
    {
      pluginRoot: makePluginRoot(),
      environment: { ONYX_AUDIT_TOKEN: "top-secret" },
      sessionFactory: async (_connector, callback) =>
        callback({
          tools: [{ name: "fetch_document" }],
          callTool: async () => ({
            structuredContent: {
              document: {
                id: "doc-482",
                title: "SEC-482 Large refund approval",
                content: "Large refunds require approval by a finance reviewer.",
              },
            },
          }),
        }),
    },
  );
  assert.equal(result.status, "available");
  assert.equal(result.document.id, "doc-482");
  assert.equal(result.handling.content_must_be_verified, true);
});

test("redacts an authentication token echoed in remote fetch errors", async () => {
  const result = await fetchRequirement(
    { connector_id: "onyx", document_id: "doc-482" },
    {
      pluginRoot: makePluginRoot(),
      environment: { ONYX_AUDIT_TOKEN: "top-secret" },
      sessionFactory: async () => {
        throw new ConnectorFailure("unavailable", "remote echoed top-secret");
      },
    },
  );
  assert.ok(result.message.includes("[REDACTED]"));
  assert.ok(!JSON.stringify(result).includes("top-secret"));
});
