import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import {
  discoverConnectors,
  mapOperationArguments,
  normalizeConnector,
  validateConnector,
} from "../lib/connectors.mjs";

function config(overrides = {}) {
  return {
    url: "https://requirements.example.test/mcp",
    tokenEnv: "TEST_REQUIREMENTS_TOKEN",
    searchTool: "search_documents",
    fetchTool: "fetch_document",
    ...overrides,
  };
}

function manifest(overrides = {}) {
  return {
    schemaVersion: "1.0",
    id: "test-source",
    displayName: "Test Source",
    enabled: true,
    capabilities: ["requirements-context"],
    entrypoints: { mcp: "./.mcp.json" },
    config: "./config.json",
    lifecycle: {
      after: "architecture-and-change-recon",
      before: "security-semantic-review",
      failure: "continue",
    },
    ...overrides,
  };
}

function makePlugin({ pluginManifest = manifest(), pluginConfig = config() } = {}) {
  const parent = fs.mkdtempSync(path.join(os.tmpdir(), "audit-connectors-"));
  const root = path.join(parent, "test-source");
  fs.mkdirSync(root);
  fs.writeFileSync(path.join(root, "plugin.json"), JSON.stringify(pluginManifest));
  fs.writeFileSync(path.join(root, "config.json"), JSON.stringify(pluginConfig));
  return root;
}

function makeInstalledPlugin() {
  const parent = fs.mkdtempSync(path.join(os.tmpdir(), "audit-installed-connectors-"));
  const root = path.join(parent, "onyx", "0.1.0+codex.test");
  fs.mkdirSync(root, { recursive: true });
  fs.writeFileSync(
    path.join(root, "plugin.json"),
    JSON.stringify(manifest({ id: "onyx", displayName: "Onyx Requirements" })),
  );
  fs.writeFileSync(path.join(root, "config.json"), JSON.stringify(config()));
  return root;
}

test("discovers connector config through the Code Audit plugin manifest", () => {
  const discovery = discoverConnectors(makePlugin());
  assert.equal(discovery.errors.length, 0);
  assert.equal(discovery.connectors.length, 1);
  assert.equal(discovery.connectors[0].id, "test-source");
  assert.equal(discovery.connectors[0].display_name, "Test Source");
  assert.equal(discovery.connectors[0].limits.max_queries, 4);
  assert.equal(discovery.connectors[0].timeouts.connect_ms, 15000);
  assert.equal(discovery.connectors[0].timeouts.tool_ms, 35000);
  assert.deepEqual(discovery.connectors[0].operations.search.argument_map, {
    query: "query",
    limit: "limit",
  });
});

test("loads an absolute user config and deep-merges declarative argument overrides", () => {
  const root = makePlugin({
    pluginConfig: config({
      configEnv: "TEST_REQUIREMENTS_CONFIG",
      arguments: { query: "query", limit: null },
      staticArguments: { search: { skip_query_expansion: true } },
    }),
  });
  const userConfigPath = path.join(path.dirname(root), "user-config.json");
  fs.writeFileSync(
    userConfigPath,
    JSON.stringify({
      url: "https://custom-requirements.example.test/mcp",
      arguments: { query: "search_query" },
      staticArguments: { search: { language: "en" } },
    }),
  );

  const discovery = discoverConnectors(root, {
    TEST_REQUIREMENTS_CONFIG: userConfigPath,
  });
  assert.equal(discovery.errors.length, 0);
  assert.equal(discovery.connectors[0].transport.url, "https://custom-requirements.example.test/mcp");
  assert.deepEqual(discovery.connectors[0].operations.search.argument_map, {
    query: "search_query",
  });
  assert.deepEqual(discovery.connectors[0].operations.search.static_arguments, {
    skip_query_expansion: true,
    language: "en",
  });
});

test("rejects relative user config paths", () => {
  const root = makePlugin({
    pluginConfig: config({ configEnv: "TEST_REQUIREMENTS_CONFIG" }),
  });
  const discovery = discoverConnectors(root, {
    TEST_REQUIREMENTS_CONFIG: "./user-config.json",
  });
  assert.equal(discovery.connectors.length, 0);
  assert.match(discovery.errors[0].message, /absolute JSON file path/);
});

test("applies connector safety validation after user config merging", () => {
  const root = makePlugin({
    pluginConfig: config({ configEnv: "TEST_REQUIREMENTS_CONFIG" }),
  });
  const userConfigPath = path.join(path.dirname(root), "unsafe-user-config.json");
  fs.writeFileSync(userConfigPath, JSON.stringify({ token: "must-not-be-inline" }));

  const discovery = discoverConnectors(root, {
    TEST_REQUIREMENTS_CONFIG: userConfigPath,
  });
  assert.equal(discovery.connectors.length, 0);
  assert.match(discovery.errors[0].message, /inline credentials/);
});

test("does not let user config change host-forwarded environment variable names", () => {
  const root = makePlugin({
    pluginConfig: config({ configEnv: "TEST_REQUIREMENTS_CONFIG" }),
  });
  const userConfigPath = path.join(path.dirname(root), "alternate-token-env.json");
  fs.writeFileSync(userConfigPath, JSON.stringify({ tokenEnv: "UNFORWARDED_TOKEN" }));

  const discovery = discoverConnectors(root, {
    TEST_REQUIREMENTS_CONFIG: userConfigPath,
  });
  assert.equal(discovery.connectors.length, 0);
  assert.match(discovery.errors[0].message, /cannot override tokenEnv/);
});

test("requires plugin id to match its directory", () => {
  const discovery = discoverConnectors(
    makePlugin({ pluginManifest: manifest({ id: "other-name" }) }),
  );
  assert.equal(discovery.connectors.length, 0);
  assert.match(discovery.errors[0].message, /match its directory/);
});

test("accepts the Codex plugin-name/version cache layout", () => {
  const discovery = discoverConnectors(makeInstalledPlugin());
  assert.equal(discovery.errors.length, 0);
  assert.equal(discovery.connectors.length, 1);
  assert.equal(discovery.connectors[0].id, "onyx");
});

test("requires the requirements lifecycle gate", () => {
  const discovery = discoverConnectors(
    makePlugin({
      pluginManifest: manifest({
        lifecycle: {
          after: "audit-start",
          before: "security-semantic-review",
          failure: "continue",
        },
      }),
    }),
  );
  assert.equal(discovery.connectors.length, 0);
  assert.match(discovery.errors[0].message, /lifecycle/);
});

test("rejects executable connector fields", () => {
  const errors = validateConnector(config({ command: "curl" }));
  assert.ok(errors.some((message) => message.includes("executable")));
  assert.ok(errors.some((message) => message.includes("config.command")));
});

test("rejects embedded and inline connector credentials", () => {
  const errors = validateConnector(
    config({
      url: "https://audit:secret@requirements.example.test/mcp",
      token: "top-secret",
    }),
  );
  assert.ok(errors.some((message) => message.includes("embedded credentials")));
  assert.ok(errors.some((message) => message.includes("inline credentials")));
});

test("rejects credential-bearing URL query parameters", () => {
  const errors = validateConnector(
    config({ url: "https://requirements.example.test/mcp?access_token=top-secret" }),
  );
  assert.ok(errors.some((message) => message.includes("credential query parameters")));
});

test("rejects URL fragments", () => {
  const errors = validateConnector(
    config({ url: "https://requirements.example.test/mcp#private-fragment" }),
  );
  assert.ok(errors.some((message) => message.includes("fragment")));
});

test("maps only declared stable arguments", () => {
  const normalized = normalizeConnector(
    config({ arguments: { query: "q", limit: "top_k", documentId: "document_id" } }),
    {
      id: "test-source",
      displayName: "Test Source",
      enabled: true,
      manifestPath: "/plugin.json",
      configPath: "/config.json",
    },
  );
  assert.deepEqual(
    mapOperationArguments(normalized.operations.search, {
      query: "SEC-42",
      limit: 8,
      token: "secret",
    }),
    { q: "SEC-42", top_k: 8 },
  );
  assert.deepEqual(
    mapOperationArguments(normalized.operations.fetch, { document_id: "doc-42" }),
    { document_id: "doc-42" },
  );
});

test("supports search-only connectors, omitted arguments, and safe static arguments", () => {
  const payload = config({
    arguments: { limit: null },
    staticArguments: { search: { skip_query_expansion: true } },
  });
  delete payload.fetchTool;
  assert.deepEqual(validateConnector(payload), []);

  const normalized = normalizeConnector(payload, {
    id: "test-source",
    displayName: "Test Source",
    enabled: true,
    manifestPath: "/plugin.json",
    configPath: "/config.json",
  });
  assert.deepEqual(
    mapOperationArguments(normalized.operations.search, {
      query: "SEC-42",
      limit: 8,
    }),
    { skip_query_expansion: true, query: "SEC-42" },
  );
  assert.equal(normalized.operations.fetch, undefined);
});

test("rejects credential-bearing or structured static arguments", () => {
  const errors = validateConnector(
    config({
      staticArguments: {
        search: {
          token: "top-secret",
          nested: { unsafe: true },
        },
      },
    }),
  );
  assert.ok(errors.some((message) => message.includes("inline credentials")));
  assert.ok(errors.some((message) => message.includes("safe declarative argument")));
});
