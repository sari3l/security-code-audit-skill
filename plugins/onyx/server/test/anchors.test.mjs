import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { buildQueryPlan, collectChangeAnchors } from "../lib/anchors.mjs";

function git(root, ...args) {
  return execFileSync("git", ["-C", root, ...args], { encoding: "utf8" });
}

test("builds layered anchors from architecture, branch, commits, paths, routes, and symbols", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "audit-anchors-"));
  git(root, "init", "-b", "main");
  git(root, "config", "user.email", "audit@example.test");
  git(root, "config", "user.name", "Audit Test");
  fs.mkdirSync(path.join(root, "services", "payments"), { recursive: true });
  fs.writeFileSync(path.join(root, "services", "payments", "routes.js"), "export const health = true;\n");
  git(root, "add", ".");
  git(root, "commit", "-m", "initial project");
  git(root, "checkout", "-b", "feature/SEC-482-refund-approval");
  fs.writeFileSync(
    path.join(root, "services", "payments", "routes.js"),
    [
      "export const health = true;",
      "export async function approveRefund(request) {",
      "  return router.post('/refunds/:id/approve', request);",
      "}",
      "",
    ].join("\n"),
  );
  git(root, "add", ".");
  git(root, "commit", "-m", "SEC-482 require finance approval for large refunds");

  const anchors = collectChangeAnchors({
    target_root: root,
    base_ref: "main",
    architecture_context: {
      components: ["payment-service"],
      business_flows: ["large refund approval"],
      declared_roles: ["finance reviewer"],
      invariants: ["large refunds require finance approval"],
    },
  });

  assert.deepEqual(anchors.explicit_ids, ["SEC-482"]);
  assert.ok(anchors.symbols.includes("approveRefund"));
  assert.ok(anchors.routes.includes("/refunds/:id/approve"));
  assert.ok(anchors.components.includes("payments"));
  assert.ok(anchors.components.includes("payment-service"));
  assert.equal(anchors.privacy.full_diff_included, false);
  assert.equal(anchors.privacy.source_code_included, false);
  assert.equal(anchors.query_plan[0].source, "explicit_id");
  assert.equal(anchors.query_plan[0].query, "SEC-482");
});

test("uses architecture and project fallback outside git", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "audit-no-git-"));
  const anchors = collectChangeAnchors({
    target_root: root,
    architecture_context: { components: ["identity-service"] },
  });
  assert.equal(anchors.git.available, false);
  assert.ok(anchors.query_plan.some((entry) => entry.query.includes("identity-service")));
});

test("redacts credential-like values from commit and architecture anchors", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "audit-secret-anchors-"));
  git(root, "init", "-b", "main");
  git(root, "config", "user.email", "audit@example.test");
  git(root, "config", "user.name", "Audit Test");
  fs.writeFileSync(path.join(root, "app.js"), "export const initial = true;\n");
  git(root, "add", ".");
  git(root, "commit", "-m", "initial project");
  fs.writeFileSync(path.join(root, "app.js"), "export const changed = true;\n");
  git(root, "add", ".");
  git(root, "commit", "-m", "SEC-999 rotate api_key=supersecret123");

  const anchors = collectChangeAnchors({
    target_root: root,
    base_ref: "HEAD^",
    architecture_context: { summary: "Authorization: Bearer abcdefghijklmnop" },
  });
  const serialized = JSON.stringify(anchors);
  assert.ok(serialized.includes("SEC-999"));
  assert.ok(serialized.includes("[REDACTED]"));
  assert.ok(!serialized.includes("supersecret123"));
  assert.ok(!serialized.includes("abcdefghijklmnop"));
});

test("normalizes common GitLab merge request references into project-scoped queries", () => {
  const inputs = [
    "panacea-backend/merge_requests/1412",
    "https://gitlab.example.test/group/panacea-backend/-/merge_requests/1412?private_token=discarded#notes",
    "panacea-backend MR1412",
    "MR1412",
    "!1412",
    "merge_requests/1412",
  ];

  for (const changeReference of inputs) {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), "panacea-backend-"));
    const projectRoot = path.join(root, "panacea-backend");
    fs.mkdirSync(projectRoot);
    const anchors = collectChangeAnchors({
      target_root: projectRoot,
      change_references: [changeReference],
      architecture_context: {},
    });
    assert.equal(anchors.change_references.length, 1, changeReference);
    assert.equal(
      anchors.change_references[0].canonical,
      "panacea-backend/merge_requests/1412",
      changeReference,
    );
    assert.deepEqual(
      anchors.query_plan.slice(0, 3).map((entry) => entry.query),
      [
        "panacea-backend MR1412 requirement_skills.md",
        "panacea-backend MR1412 design_skills.md",
        "panacea-backend MR1412",
      ],
      changeReference,
    );
    assert.ok(!JSON.stringify(anchors).includes("private_token=discarded"), changeReference);
  }
});

test("preserves a raw merge request path as a bounded fallback query", () => {
  const plan = buildQueryPlan({
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
  });
  assert.equal(plan[3].query, "merge_requests/1412");
  assert.equal(plan[3].source, "change_reference_raw");
});

test("automatically discovers an MR reference from the current Git branch", () => {
  const parent = fs.mkdtempSync(path.join(os.tmpdir(), "audit-auto-mr-"));
  const root = path.join(parent, "panacea-backend");
  fs.mkdirSync(root);
  git(root, "init", "-b", "main");
  git(root, "config", "user.email", "audit@example.test");
  git(root, "config", "user.name", "Audit Test");
  fs.writeFileSync(path.join(root, "app.py"), "INITIAL = True\n");
  git(root, "add", ".");
  git(root, "commit", "-m", "initial project");
  git(root, "checkout", "-b", "review/merge_requests/1412");
  fs.writeFileSync(path.join(root, "app.py"), "CHANGED = True\n");
  git(root, "add", ".");
  git(root, "commit", "-m", "harden task execution");

  const anchors = collectChangeAnchors({
    target_root: root,
    base_ref: "main",
    architecture_context: {},
  });

  assert.equal(anchors.change_references[0].canonical, "panacea-backend/merge_requests/1412");
  assert.equal(anchors.change_references[0].source, "git_recon");
  assert.equal(anchors.query_plan[0].query, "panacea-backend MR1412 requirement_skills.md");
});

test("uses remote project, HEAD commit, and branch when no MR number is visible", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "audit-commit-fallback-"));
  git(root, "init", "-b", "main");
  git(root, "config", "user.email", "audit@example.test");
  git(root, "config", "user.name", "Audit Test");
  git(root, "remote", "add", "origin", "git@gitlab.example.test:platform/panacea-backend.git");
  fs.writeFileSync(path.join(root, "app.py"), "INITIAL = True\n");
  git(root, "add", ".");
  git(root, "commit", "-m", "initial project");
  git(root, "checkout", "-b", "release/lee");
  fs.writeFileSync(path.join(root, "app.py"), "CHANGED = True\n");
  git(root, "add", ".");
  git(root, "commit", "-m", "harden task execution");

  const anchors = collectChangeAnchors({
    target_root: root,
    base_ref: "main",
    architecture_context: {},
  });

  assert.deepEqual(anchors.change_references, []);
  assert.equal(anchors.project_names[0], "panacea-backend");
  assert.equal(anchors.query_plan[0].source, "git_head_commit_requirement");
  assert.ok(anchors.query_plan[0].query.includes(anchors.git.head_commit));
  assert.equal(anchors.query_plan[1].source, "git_head_commit_design");
  assert.ok(anchors.query_plan.some((entry) => entry.source === "git_branch"));
});
