import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";


const pluginRoot = path.resolve(fileURLToPath(new URL("../../", import.meta.url)));


test("bundled stdio server exposes five tools and the MCP App resource", { timeout: 15000 }, async () => {
  const transport = new StdioClientTransport({
    command: process.execPath,
    args: [path.join(pluginRoot, "server", "bundle.mjs")],
    cwd: pluginRoot,
    stderr: "pipe",
  });
  const client = new Client(
    { name: "requirements-context-smoke-test", version: "0.1.0" },
    { capabilities: {} },
  );

  try {
    await client.connect(transport);
    const tools = await client.listTools();
    assert.deepEqual(
      tools.tools.map((tool) => tool.name).sort(),
      [
        "build_requirement_anchors",
        "discover_requirement_connectors",
        "fetch_requirement_document",
        "render_requirement_context",
        "search_requirement_context",
      ],
    );
    const renderTool = tools.tools.find((tool) => tool.name === "render_requirement_context");
    assert.equal(
      renderTool._meta.ui.resourceUri,
      "ui://security-code-audit/requirements-context-v1.html",
    );
    assert.equal(
      renderTool._meta["ui/resourceUri"],
      "ui://security-code-audit/requirements-context-v1.html",
    );

    const discovery = await client.callTool({ name: "discover_requirement_connectors", arguments: {} });
    assert.equal(discovery.structuredContent.connector_registry.status, "not_configured");
    assert.equal(discovery.structuredContent.connector_registry.connectors[0].id, "onyx");
    assert.equal(discovery.structuredContent.connector_registry.connectors[0].enabled, false);
    assert.equal(
      discovery.structuredContent.connector_registry.connectors[0].endpoint,
      "https://onyx.example.com/mcp",
    );
    assert.equal(discovery.structuredContent.connector_registry.connectors[0].auth.configured, false);

    const targetParent = fs.mkdtempSync(path.join(os.tmpdir(), "requirements-context-stdio-"));
    const targetRoot = path.join(targetParent, "sample-project");
    fs.mkdirSync(targetRoot);
    const built = await client.callTool({
      name: "build_requirement_anchors",
      arguments: {
        target_root: targetRoot,
        change_references: ["merge_requests/1412"],
        architecture_context: { components: ["identity-service"] },
      },
    });
    const anchorBundle = built.structuredContent.anchor_bundle;
    assert.equal(anchorBundle.git.available, false);
    assert.equal(anchorBundle.change_references[0].canonical, "sample-project/merge_requests/1412");
    assert.equal(
      anchorBundle.query_plan[0].query,
      "sample-project MR1412 requirement_skills.md",
    );
    assert.equal(anchorBundle.query_plan[3].query, "merge_requests/1412");

    const searched = await client.callTool({
      name: "search_requirement_context",
      arguments: { anchor_bundle: anchorBundle },
    });
    assert.equal(searched.structuredContent.context.status, "not_configured");
    assert.equal(searched.structuredContent.context.handling.may_narrow_audit_scope, false);

    const fetched = await client.callTool({
      name: "fetch_requirement_document",
      arguments: { connector_id: "onyx", document_id: "missing-auth-smoke" },
    });
    assert.equal(fetched.structuredContent.result.status, "not_configured");

    const rendered = await client.callTool({
      name: "render_requirement_context",
      arguments: { context: searched.structuredContent.context },
    });
    assert.equal(rendered.structuredContent.context.status, "not_configured");

    const resources = await client.listResources();
    assert.equal(resources.resources.length, 1);
    assert.equal(resources.resources[0].uri, "ui://security-code-audit/requirements-context-v1.html");
    assert.equal(resources.resources[0].mimeType, "text/html;profile=mcp-app");
    assert.equal(resources.resources[0]._meta.ui.prefersBorder, false);
    const resource = await client.readResource({ uri: resources.resources[0].uri });
    assert.match(resource.contents[0].text, /<h1>Requirement Context<\/h1>/);
    assert.equal(resource.contents[0].mimeType, "text/html;profile=mcp-app");
    assert.equal(resource.contents[0]._meta.ui.prefersBorder, false);
  } finally {
    await client.close();
  }
});
