import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const CONNECTOR_ID = /^[a-z][a-z0-9-]{0,63}$/;
const ENV_NAME = /^[A-Z][A-Z0-9_]{1,127}$/;
const TOOL_NAME = /^[A-Za-z][A-Za-z0-9_.:-]{0,127}$/;
const EXECUTABLE_FIELDS = new Set([
  "args",
  "command",
  "executable",
  "handler",
  "hook",
  "script",
]);
const CREDENTIAL_FIELDS = new Set([
  "access_token",
  "api_key",
  "api_secret",
  "authorization",
  "client_secret",
  "cookie",
  "credentials",
  "password",
  "refresh_token",
  "secret",
  "token",
]);
const DEFAULTS = Object.freeze({
  maxQueries: 4,
  maxResultsPerQuery: 8,
  maxFetches: 4,
  connectMs: 15000,
  toolMs: 35000,
});
const MAX_USER_CONFIG_BYTES = 256 * 1024;

export const DEFAULT_PLUGIN_ROOT = path.resolve(
  fileURLToPath(new URL("../../", import.meta.url)),
);

function isPlainObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function containsNamedField(value, names) {
  if (Array.isArray(value)) return value.some((child) => containsNamedField(child, names));
  if (!isPlainObject(value)) return false;
  return Object.entries(value).some(
    ([key, child]) =>
      names.has(key.toLowerCase().replaceAll("-", "_")) || containsNamedField(child, names),
  );
}

function assertAllowedKeys(object, allowed, label, errors) {
  if (!isPlainObject(object)) {
    errors.push(`${label} must be an object`);
    return;
  }
  for (const key of Object.keys(object)) {
    if (!allowed.has(key)) errors.push(`${label}.${key} is not supported`);
  }
}

function isDeclarativeArgumentValue(value) {
  if (value === null || ["boolean", "number", "string"].includes(typeof value)) return true;
  return (
    Array.isArray(value) &&
    value.length <= 50 &&
    value.every((item) => item === null || ["boolean", "number", "string"].includes(typeof item))
  );
}

function isInside(root, candidate) {
  const relative = path.relative(root, candidate);
  return relative !== "" && !relative.startsWith("..") && !path.isAbsolute(relative);
}

function resolvePluginFile(pluginRoot, relativePath, label) {
  if (typeof relativePath !== "string" || !relativePath.startsWith("./")) {
    throw new Error(`${label} must be a ./-prefixed path`);
  }
  const unresolved = path.resolve(pluginRoot, relativePath);
  const resolved = fs.realpathSync(unresolved);
  if (!isInside(pluginRoot, resolved) || !fs.statSync(resolved).isFile()) {
    throw new Error(`${label} must resolve to a file inside the plugin directory`);
  }
  return resolved;
}

function readJsonObject(filePath, label) {
  const stat = fs.statSync(filePath);
  if (!stat.isFile()) throw new Error(`${label} must be a regular JSON file`);
  if (stat.size > MAX_USER_CONFIG_BYTES) {
    throw new Error(`${label} exceeds the 256 KiB size limit`);
  }
  const payload = JSON.parse(fs.readFileSync(filePath, "utf8"));
  if (!isPlainObject(payload)) throw new Error(`${label} must contain a JSON object`);
  return payload;
}

function mergeConnectorConfig(defaultConfig, overrideConfig) {
  for (const field of ["configEnv", "tokenEnv"]) {
    if (Object.hasOwn(overrideConfig, field) && overrideConfig[field] !== defaultConfig[field]) {
      throw new Error(`user config cannot override ${field}`);
    }
  }
  const merged = { ...defaultConfig, ...overrideConfig };
  if (isPlainObject(defaultConfig.arguments) && isPlainObject(overrideConfig.arguments)) {
    merged.arguments = { ...defaultConfig.arguments, ...overrideConfig.arguments };
  }
  if (
    isPlainObject(defaultConfig.staticArguments) &&
    isPlainObject(overrideConfig.staticArguments)
  ) {
    merged.staticArguments = {
      ...defaultConfig.staticArguments,
      ...overrideConfig.staticArguments,
    };
    for (const operation of ["search", "fetch"]) {
      if (
        isPlainObject(defaultConfig.staticArguments[operation]) &&
        isPlainObject(overrideConfig.staticArguments[operation])
      ) {
        merged.staticArguments[operation] = {
          ...defaultConfig.staticArguments[operation],
          ...overrideConfig.staticArguments[operation],
        };
      }
    }
  }
  return merged;
}

function loadConnectorConfig(configPath, environment) {
  const defaultConfig = readJsonObject(configPath, "plugin config");
  const configEnv = defaultConfig.configEnv;
  if (configEnv === undefined) return defaultConfig;
  if (typeof configEnv !== "string" || !ENV_NAME.test(configEnv)) {
    throw new Error("configEnv must be an uppercase environment variable name");
  }

  const userConfigPath = environment[configEnv];
  if (!userConfigPath) return defaultConfig;
  if (!path.isAbsolute(userConfigPath)) {
    throw new Error(`${configEnv} must point to an absolute JSON file path`);
  }
  const resolvedUserConfigPath = fs.realpathSync(userConfigPath);
  const overrideConfig = readJsonObject(resolvedUserConfigPath, `${configEnv} user config`);
  return mergeConnectorConfig(defaultConfig, overrideConfig);
}

export function validateConnector(payload) {
  const errors = [];
  assertAllowedKeys(
    payload,
    new Set([
      "$schema",
      "configEnv",
      "url",
      "tokenEnv",
      "searchTool",
      "fetchTool",
      "arguments",
      "staticArguments",
      "enabled",
    ]),
    "config",
    errors,
  );
  if (!isPlainObject(payload)) return errors;

  if (containsNamedField(payload, EXECUTABLE_FIELDS)) {
    errors.push("connector config cannot contain executable fields");
  }
  if (containsNamedField(payload, CREDENTIAL_FIELDS)) {
    errors.push("connector config cannot contain inline credentials");
  }

  try {
    const endpoint = new URL(payload.url);
    if (endpoint.protocol !== "https:") errors.push("url must use HTTPS");
    if (endpoint.username || endpoint.password) {
      errors.push("url cannot contain embedded credentials");
    }
    if (
      [...endpoint.searchParams.keys()].some((key) =>
        CREDENTIAL_FIELDS.has(key.toLowerCase().replaceAll("-", "_")),
      )
    ) {
      errors.push("url cannot contain credential query parameters");
    }
    if (endpoint.hash) errors.push("url cannot contain a fragment");
  } catch {
    errors.push("url must be an absolute HTTPS URL");
  }

  if (payload.$schema !== undefined && typeof payload.$schema !== "string") {
    errors.push("$schema must be a string when provided");
  }
  if (
    payload.configEnv !== undefined &&
    (typeof payload.configEnv !== "string" || !ENV_NAME.test(payload.configEnv))
  ) {
    errors.push("configEnv must be an uppercase environment variable name when provided");
  }

  if (typeof payload.tokenEnv !== "string" || !ENV_NAME.test(payload.tokenEnv)) {
    errors.push("tokenEnv must be an uppercase environment variable name");
  }
  if (typeof payload.searchTool !== "string" || !TOOL_NAME.test(payload.searchTool)) {
    errors.push("searchTool must be a valid MCP tool name");
  }
  if (
    payload.fetchTool !== undefined &&
    (typeof payload.fetchTool !== "string" || !TOOL_NAME.test(payload.fetchTool))
  ) {
    errors.push("fetchTool must be a valid MCP tool name when provided");
  }
  if (payload.enabled !== undefined && typeof payload.enabled !== "boolean") {
    errors.push("enabled must be a boolean");
  }

  if (payload.arguments !== undefined) {
    assertAllowedKeys(
      payload.arguments,
      new Set(["query", "limit", "documentId"]),
      "config.arguments",
      errors,
    );
    if (isPlainObject(payload.arguments)) {
      for (const [field, value] of Object.entries(payload.arguments)) {
        if (value !== null && (typeof value !== "string" || !TOOL_NAME.test(value))) {
          errors.push(`config.arguments.${field} must be a remote argument name or null`);
        }
      }
    }
  }
  if (payload.staticArguments !== undefined) {
    assertAllowedKeys(
      payload.staticArguments,
      new Set(["search", "fetch"]),
      "config.staticArguments",
      errors,
    );
    if (isPlainObject(payload.staticArguments)) {
      for (const [operation, argumentsObject] of Object.entries(payload.staticArguments)) {
        if (!isPlainObject(argumentsObject)) {
          errors.push(`config.staticArguments.${operation} must be an object`);
          continue;
        }
        for (const [name, value] of Object.entries(argumentsObject)) {
          if (!TOOL_NAME.test(name) || !isDeclarativeArgumentValue(value)) {
            errors.push(
              `config.staticArguments.${operation}.${name} must be a safe declarative argument`,
            );
          }
        }
      }
    }
  }
  return errors;
}

export function normalizeConnector(payload, plugin) {
  const argumentNames = payload.arguments ?? {};
  const argumentName = (field, defaultName) =>
    Object.hasOwn(argumentNames, field) ? argumentNames[field] : defaultName;
  const searchArgumentMap = Object.fromEntries(
    [
      ["query", argumentName("query", "query")],
      ["limit", argumentName("limit", "limit")],
    ].filter(([, remoteName]) => remoteName !== null),
  );
  const operations = {
    search: {
      tool_candidates: [payload.searchTool],
      argument_map: searchArgumentMap,
      static_arguments: payload.staticArguments?.search ?? {},
    },
  };
  if (payload.fetchTool) {
    const fetchArgumentMap = Object.fromEntries(
      [["document_id", argumentName("documentId", "id")]].filter(
        ([, remoteName]) => remoteName !== null,
      ),
    );
    operations.fetch = {
      tool_candidates: [payload.fetchTool],
      argument_map: fetchArgumentMap,
      static_arguments: payload.staticArguments?.fetch ?? {},
    };
  }
  return {
    id: plugin.id,
    display_name: plugin.displayName,
    description: `Requirement documents from ${plugin.displayName}.`,
    enabled: plugin.enabled && (payload.enabled ?? true),
    transport: {
      type: "streamable_http",
      url: payload.url,
      auth: {
        type: "bearer_env",
        env_var: payload.tokenEnv,
      },
    },
    operations,
    limits: {
      max_queries: DEFAULTS.maxQueries,
      max_results_per_query: DEFAULTS.maxResultsPerQuery,
      max_fetches: DEFAULTS.maxFetches,
    },
    timeouts: {
      connect_ms: DEFAULTS.connectMs,
      tool_ms: DEFAULTS.toolMs,
    },
    manifest_path: plugin.manifestPath,
    config_path: plugin.configPath,
  };
}

export function discoverConnectors(pluginRoot = DEFAULT_PLUGIN_ROOT, environment = process.env) {
  const connectors = [];
  const errors = [];
  let canonicalRoot;
  let pluginId = path.basename(pluginRoot);
  try {
    canonicalRoot = fs.realpathSync(pluginRoot);
    const manifestPath = resolvePluginFile(canonicalRoot, "./plugin.json", "plugin manifest");
    const manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8"));
    if (!isPlainObject(manifest)) throw new Error("plugin.json must be an object");
    pluginId = typeof manifest.id === "string" ? manifest.id : pluginId;
    const manifestErrors = [];
    if (manifest.schemaVersion !== "1.0") manifestErrors.push("schemaVersion must be 1.0");
    if (typeof manifest.id !== "string" || !CONNECTOR_ID.test(manifest.id)) {
      manifestErrors.push("plugin id must use lowercase kebab-case");
    } else if (
      ![path.basename(canonicalRoot), path.basename(path.dirname(canonicalRoot))].includes(
        manifest.id,
      )
    ) {
      manifestErrors.push("plugin id must match its directory name");
    }
    if (typeof manifest.displayName !== "string" || !manifest.displayName.trim()) {
      manifestErrors.push("plugin displayName is required");
    }
    if (typeof manifest.enabled !== "boolean") manifestErrors.push("plugin enabled must be boolean");
    if (!Array.isArray(manifest.capabilities) || !manifest.capabilities.includes("requirements-context")) {
      manifestErrors.push("plugin must declare the requirements-context capability");
    }
    if (
      manifest.lifecycle?.after !== "architecture-and-change-recon" ||
      manifest.lifecycle?.before !== "security-semantic-review" ||
      manifest.lifecycle?.failure !== "continue"
    ) {
      manifestErrors.push("requirements-context lifecycle must run after recon, before semantic review, with continue failure policy");
    }
    if (manifestErrors.length > 0) throw new Error(manifestErrors.join("; "));

    const configPath = resolvePluginFile(canonicalRoot, manifest.config, "plugin config");
    const config = loadConnectorConfig(configPath, environment);
    const validationErrors = validateConnector(config);
    if (validationErrors.length > 0) throw new Error(validationErrors.join("; "));
    connectors.push(
      normalizeConnector(config, {
        id: manifest.id,
        displayName: manifest.displayName,
        enabled: manifest.enabled,
        manifestPath,
        configPath,
      }),
    );
  } catch (error) {
    errors.push({ connector_id: pluginId, code: "invalid_connector", message: error.message });
  }
  return { connectors, errors };
}

export function publicConnector(connector, environment = process.env) {
  const envVar = connector.transport.auth.env_var;
  return {
    id: connector.id,
    display_name: connector.display_name,
    description: connector.description,
    enabled: connector.enabled,
    transport: connector.transport.type,
    endpoint: connector.transport.url,
    auth: {
      type: connector.transport.auth.type,
      env_var: envVar,
      configured: Boolean(environment[envVar]),
    },
    operations: Object.keys(connector.operations),
  };
}

export function mapOperationArguments(operation, values) {
  const mapped = { ...(operation.static_arguments ?? {}) };
  for (const [stableName, remoteName] of Object.entries(operation.argument_map)) {
    if (values[stableName] !== undefined) mapped[remoteName] = values[stableName];
  }
  return mapped;
}

export function selectRemoteTool(operation, advertisedTools) {
  const available = new Set(advertisedTools.map((tool) => tool.name));
  return operation.tool_candidates.find((candidate) => available.has(candidate)) ?? null;
}
