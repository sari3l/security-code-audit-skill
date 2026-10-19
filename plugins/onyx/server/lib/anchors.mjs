import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";

const MAX_GIT_OUTPUT = 1024 * 1024;
const MAX_DIFF_BYTES = 512 * 1024;
const MAX_CHANGED_FILES = 300;
const MAX_VALUES_PER_FAMILY = 60;
const MAX_DISCOVERED_CHANGE_REFERENCES = 20;
const ISSUE_ID_PATTERN = /\b(?:[A-Z][A-Z0-9]{1,15}-\d{1,10}|RFC[-_ ]?\d{2,10})\b/g;
const PROJECT_SLUG_PATTERN = /^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$/;
const GENERIC_PATH_PARTS = new Set([
  "api",
  "app",
  "apps",
  "cmd",
  "common",
  "config",
  "core",
  "internal",
  "lib",
  "pkg",
  "server",
  "service",
  "services",
  "src",
  "test",
  "tests",
]);
const STOP_WORDS = new Set([
  "add",
  "added",
  "and",
  "change",
  "changed",
  "changes",
  "code",
  "fix",
  "fixed",
  "for",
  "from",
  "into",
  "merge",
  "minor",
  "refactor",
  "redacted",
  "remove",
  "removed",
  "the",
  "this",
  "update",
  "updated",
  "with",
]);
const SECRET_PATTERNS = [
  /\bbearer\s+[A-Za-z0-9._~+/=-]{8,}/gi,
  /\bauthorization\s*[:=]\s*\S+/gi,
  /\b(?:api[_-]?key|access[_-]?token|refresh[_-]?token|client[_-]?secret|password)\s*[:=]\s*["']?[^\s"',}]{4,}/gi,
  /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g,
  /\b(?:gh[pousr]_[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16})\b/g,
];

function sanitizeAnchorText(value) {
  let sanitized = String(value ?? "").replace(/\u0000/g, "").trim();
  for (const pattern of SECRET_PATTERNS) {
    pattern.lastIndex = 0;
    sanitized = sanitized.replace(pattern, "[REDACTED]");
  }
  return sanitized;
}

function unique(items, limit = MAX_VALUES_PER_FAMILY) {
  const seen = new Set();
  const output = [];
  for (const raw of items) {
    const value = sanitizeAnchorText(raw);
    if (!value || seen.has(value)) continue;
    seen.add(value);
    output.push(value);
    if (output.length >= limit) break;
  }
  return output;
}

function runGit(root, args, options = {}) {
  const result = spawnSync("git", ["-C", root, ...args], {
    encoding: "utf8",
    timeout: options.timeout ?? 5000,
    maxBuffer: options.maxBuffer ?? MAX_GIT_OUTPUT,
    windowsHide: true,
  });
  return {
    ok: result.status === 0,
    stdout: result.stdout ?? "",
    stderr: result.stderr ?? "",
  };
}

function verifyCommit(root, reference) {
  if (!reference) return null;
  const result = runGit(root, ["rev-parse", "--verify", `${reference}^{commit}`]);
  return result.ok ? result.stdout.trim() : null;
}

function resolveBase(root, explicitBase, head) {
  const explicit = verifyCommit(root, explicitBase);
  if (explicit) return { reference: explicitBase, commit: explicit, source: "explicit" };

  const candidates = [];
  const remoteHead = runGit(root, ["symbolic-ref", "--quiet", "--short", "refs/remotes/origin/HEAD"]);
  if (remoteHead.ok) candidates.push(remoteHead.stdout.trim());
  candidates.push("origin/main", "origin/master", "main", "master");

  for (const candidate of unique(candidates)) {
    const commit = verifyCommit(root, candidate);
    if (!commit || commit === head) continue;
    const mergeBase = runGit(root, ["merge-base", head, commit]);
    if (mergeBase.ok && mergeBase.stdout.trim()) {
      return { reference: candidate, commit: mergeBase.stdout.trim(), source: "auto_default_branch" };
    }
  }

  const parent = verifyCommit(root, `${head}^`);
  if (parent) return { reference: `${head}^`, commit: parent, source: "head_parent" };
  return { reference: null, commit: null, source: "none" };
}

function parseNameStatus(output, source) {
  const tokens = output.split("\0").filter(Boolean);
  const rows = [];
  for (let index = 0; index < tokens.length; ) {
    const status = tokens[index++];
    if (!status) continue;
    if (status.startsWith("R") || status.startsWith("C")) {
      const oldPath = tokens[index++];
      const newPath = tokens[index++];
      if (newPath) rows.push({ path: newPath, old_path: oldPath, status, source });
    } else {
      const filePath = tokens[index++];
      if (filePath) rows.push({ path: filePath, status, source });
    }
  }
  return rows;
}

function collectChangedFiles(root, baseCommit, head) {
  const rows = [];
  if (baseCommit) {
    const committed = runGit(root, ["diff", "--name-status", "-z", `${baseCommit}...${head}`]);
    if (committed.ok) rows.push(...parseNameStatus(committed.stdout, "committed"));
  }
  const worktree = runGit(root, ["diff", "--name-status", "-z", "HEAD"]);
  if (worktree.ok) rows.push(...parseNameStatus(worktree.stdout, "worktree"));
  const untracked = runGit(root, ["ls-files", "--others", "--exclude-standard", "-z"]);
  if (untracked.ok) {
    rows.push(
      ...untracked.stdout
        .split("\0")
        .filter(Boolean)
        .map((filePath) => ({ path: filePath, status: "?", source: "untracked" })),
    );
  }

  const byPath = new Map();
  for (const row of rows) {
    if (!byPath.has(row.path)) byPath.set(row.path, row);
    else byPath.set(row.path, { ...byPath.get(row.path), ...row, source: "multiple" });
  }
  return [...byPath.values()]
    .sort((left, right) => left.path.localeCompare(right.path))
    .slice(0, MAX_CHANGED_FILES);
}

function collectDiff(root, baseCommit, head) {
  const chunks = [];
  if (baseCommit) {
    const committed = runGit(
      root,
      ["diff", "--no-ext-diff", "--unified=0", `${baseCommit}...${head}`],
      { maxBuffer: MAX_DIFF_BYTES },
    );
    if (committed.ok) chunks.push(committed.stdout);
  }
  const worktree = runGit(root, ["diff", "--no-ext-diff", "--unified=0", "HEAD"], {
    maxBuffer: MAX_DIFF_BYTES,
  });
  if (worktree.ok) chunks.push(worktree.stdout);
  return chunks.join("\n").slice(0, MAX_DIFF_BYTES);
}

function collectCommits(root, baseCommit, head) {
  if (!baseCommit) return [];
  const result = runGit(root, [
    "log",
    "--no-merges",
    "--max-count=30",
    "--format=%H%x1f%s%x1f%b%x1e",
    `${baseCommit}..${head}`,
  ]);
  if (!result.ok) return [];
  return result.stdout
    .split("\x1e")
    .map((record) => record.trim())
    .filter(Boolean)
    .map((record) => {
      const [commit, subject = "", body = ""] = record.split("\x1f");
      return { commit, subject: subject.trim(), body: body.trim().slice(0, 1000) };
    });
}

function addedLines(diff) {
  return diff
    .split("\n")
    .filter((line) => line.startsWith("+") && !line.startsWith("+++"))
    .map((line) => line.slice(1));
}

function extractMatches(lines, patterns) {
  const found = [];
  for (const line of lines) {
    for (const pattern of patterns) {
      pattern.lastIndex = 0;
      for (const match of line.matchAll(pattern)) {
        if (match[1]) found.push(match[1]);
      }
    }
  }
  return unique(found);
}

function extractSymbols(lines) {
  return extractMatches(lines, [
    /^\s*(?:async\s+)?def\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(/g,
    /^\s*class\s+([A-Za-z_][A-Za-z0-9_]*)/g,
    /^\s*(?:export\s+)?(?:async\s+)?function\s+([A-Za-z_$][\w$]*)\s*\(/g,
    /^\s*(?:export\s+)?class\s+([A-Za-z_$][\w$]*)/g,
    /^\s*func\s+(?:\([^)]*\)\s*)?([A-Za-z_][A-Za-z0-9_]*)\s*\(/g,
    /^\s*(?:public|private|protected|internal)?\s*(?:static\s+)?(?:async\s+)?[\w<>,\[\]?]+\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(/g,
  ]);
}

function extractRoutes(lines) {
  const routes = [];
  const routePatterns = [
    /\b(?:GET|POST|PUT|PATCH|DELETE|OPTIONS|HEAD)\s+([/][^\s"'`]+)/gi,
    /\.(?:get|post|put|patch|delete|options|head)\s*\(\s*["'`]([^"'`]+)["'`]/gi,
    /@(?:app|router|blueprint)\.(?:get|post|put|patch|delete|route)\s*\(\s*["']([^"']+)["']/gi,
    /(?:Route|RequestMapping|GetMapping|PostMapping|PutMapping|PatchMapping|DeleteMapping)\s*\(\s*["']([^"']+)["']/g,
  ];
  for (const line of lines) {
    for (const pattern of routePatterns) {
      pattern.lastIndex = 0;
      for (const match of line.matchAll(pattern)) routes.push(match[1]);
    }
  }
  return unique(routes);
}

function extractDataEntities(lines) {
  return extractMatches(lines, [
    /\b(?:from|join|into|update|table)\s+["'`]?([A-Za-z_][A-Za-z0-9_.-]*)/gi,
    /\b(?:collection|table_name|__tablename__)\s*[=:]\s*["']([A-Za-z_][A-Za-z0-9_.-]*)["']/gi,
  ]);
}

function extractConfigurationKeys(lines) {
  return extractMatches(lines, [
    /\b(?:process\.env\.|os\.environ\[["']|getenv\(["'])([A-Z][A-Z0-9_]{2,})/g,
    /^\s*[+]?\s*([A-Z][A-Z0-9_]{2,})\s*[=:]/g,
    /\b(?:feature[_-]?flag|flag)\s*[(:=]\s*["']([A-Za-z][A-Za-z0-9_.-]+)["']/gi,
  ]);
}

function componentsFromPaths(changedFiles) {
  const components = [];
  for (const row of changedFiles) {
    const parts = row.path.split("/").filter(Boolean);
    const candidates = parts.filter(
      (part, index) =>
        index < 4 &&
        !GENERIC_PATH_PARTS.has(part.toLowerCase()) &&
        !part.startsWith(".") &&
        !part.includes(".") &&
        part.length > 1,
    );
    if (candidates.length > 0) components.push(candidates[0]);
  }
  return unique(components, 30);
}

function themesFromCommits(commits) {
  const phrases = commits.map((commit) => sanitizeAnchorText(commit.subject)).filter(Boolean);
  const words = [];
  for (const phrase of phrases) {
    words.push(
      ...phrase
        .toLowerCase()
        .replace(/[^a-z0-9_-]+/g, " ")
        .split(/\s+/)
        .filter((word) => word.length > 2 && !STOP_WORDS.has(word) && !ISSUE_ID_PATTERN.test(word)),
    );
    ISSUE_ID_PATTERN.lastIndex = 0;
  }
  return unique([...phrases, ...words], 30);
}

function readProjectNames(root) {
  const names = [];
  const remote = runGit(root, ["remote", "get-url", "origin"]);
  if (remote.ok) {
    const remotePath = remote.stdout
      .trim()
      .replace(/^[^@]+@[^:]+:/, "")
      .replace(/^[a-z][a-z0-9+.-]*:\/\/[^/]+\//i, "")
      .replace(/\/+$/, "")
      .replace(/\.git$/i, "");
    if (remotePath) names.push(remotePath.split("/").filter(Boolean).at(-1));
  }
  names.push(path.basename(root));
  const packagePath = path.join(root, "package.json");
  try {
    const payload = JSON.parse(fs.readFileSync(packagePath, "utf8"));
    if (typeof payload.name === "string") names.push(payload.name);
  } catch {
    // Optional project metadata.
  }
  const goModPath = path.join(root, "go.mod");
  try {
    const moduleLine = fs.readFileSync(goModPath, "utf8").match(/^module\s+(.+)$/m);
    if (moduleLine) names.push(moduleLine[1].trim().split("/").at(-1));
  } catch {
    // Optional project metadata.
  }
  return unique(names, 5);
}

function normalizeArchitectureContext(input = {}) {
  const normalized = {};
  for (const field of [
    "business_domains",
    "business_flows",
    "components",
    "declared_roles",
    "invariants",
    "trust_boundaries",
  ]) {
    normalized[field] = unique(Array.isArray(input[field]) ? input[field] : [], 30);
  }
  if (typeof input.summary === "string" && input.summary.trim()) {
    normalized.summary = sanitizeAnchorText(input.summary).slice(0, 1000);
  }
  return normalized;
}

function extractExplicitIds(values) {
  const ids = [];
  for (const value of values) {
    ISSUE_ID_PATTERN.lastIndex = 0;
    for (const match of String(value ?? "").matchAll(ISSUE_ID_PATTERN)) {
      ids.push(match[0].toUpperCase().replace(/[_ ]/g, "-"));
    }
  }
  return unique(ids, 30);
}

function safeChangeReference(value) {
  const sanitized = sanitizeAnchorText(value).slice(0, 2000);
  try {
    const parsed = new URL(sanitized);
    if (!["http:", "https:"].includes(parsed.protocol)) return sanitized;
    parsed.username = "";
    parsed.password = "";
    parsed.search = "";
    parsed.hash = "";
    return parsed.href;
  } catch {
    return sanitized;
  }
}

function parseGitLabMergeRequest(value, fallbackProject) {
  const raw = safeChangeReference(value);
  if (!raw) return null;

  const pathMatch = raw.match(
    /(?:^|\/)(?<project>[A-Za-z0-9][A-Za-z0-9_.-]{0,127})(?:\/-)?\/merge_requests\/(?<iid>\d{1,10})(?:\/|$)/i,
  );
  const barePathMatch = raw.match(/^\/?merge_requests\/(?<iid>\d{1,10})\/?$/i);
  const shortMatch = raw.match(
    /^(?:(?<project>[A-Za-z0-9][A-Za-z0-9_.-]{0,127})\s+)?(?:MR\s*!?#?\s*|!)(?<iid>\d{1,10})$/i,
  );
  const match = pathMatch ?? barePathMatch ?? shortMatch;
  if (!match?.groups?.iid) return null;

  const parsedProject = match.groups.project;
  const project = PROJECT_SLUG_PATTERN.test(parsedProject ?? "")
    ? parsedProject
    : PROJECT_SLUG_PATTERN.test(fallbackProject ?? "")
      ? fallbackProject
      : "";
  const iid = String(Number(match.groups.iid));
  if (!iid || iid === "0") return null;
  const canonical = project ? `${project}/merge_requests/${iid}` : `merge_requests/${iid}`;
  return {
    kind: "gitlab_merge_request",
    raw,
    canonical,
    project: project || null,
    iid,
    aliases: unique(
      [
        raw,
        canonical,
        project ? `${project} MR${iid}` : `MR${iid}`,
        project ? `${project} MR ${iid}` : `MR ${iid}`,
        project ? `${project} !${iid}` : `!${iid}`,
      ],
      10,
    ),
  };
}

function normalizeChangeReferences(values, fallbackProject) {
  if (!Array.isArray(values)) return [];
  const references = [];
  const seen = new Set();
  for (const value of values.slice(0, 20)) {
    if (typeof value !== "string") continue;
    const reference = parseGitLabMergeRequest(value, fallbackProject);
    if (!reference || seen.has(reference.canonical.toLowerCase())) continue;
    seen.add(reference.canonical.toLowerCase());
    references.push(reference);
  }
  return references;
}

function discoverGitLabMergeRequestReferences(root, branch, commits, head, fallbackProject) {
  const candidates = [];

  for (const value of [branch, ...commits.flatMap((commit) => [commit.subject, commit.body])]) {
    const text = String(value ?? "");
    const pathMatches = text.match(/merge_requests\/\d{1,10}/gi) ?? [];
    const shortMatches = text.match(/(?:[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\s+)?MR\s*!?#?\s*\d{1,10}|!\d{1,10}/gi) ?? [];
    candidates.push(...pathMatches, ...shortMatches);
  }

  if (head) {
    const refs = runGit(root, [
      "for-each-ref",
      "--format=%(refname)",
      "--points-at",
      head,
      "refs/merge-requests",
      "refs/remotes/origin/merge-requests",
    ]);
    if (refs.ok) {
      for (const ref of refs.stdout.split("\n")) {
        const match = ref.match(/(?:^|\/)merge-requests\/(?<iid>\d{1,10})(?:\/head|\/merge)?$/i);
        if (match?.groups?.iid) candidates.push(`merge_requests/${match.groups.iid}`);
      }
    }
  }

  return normalizeChangeReferences(
    candidates.slice(0, MAX_DISCOVERED_CHANGE_REFERENCES),
    fallbackProject,
  ).map((reference) => ({ ...reference, source: "git_recon" }));
}

function mergeChangeReferences(explicitReferences, discoveredReferences) {
  const byCanonical = new Map();
  for (const reference of [...explicitReferences, ...discoveredReferences]) {
    const key = reference.canonical.toLowerCase();
    if (!byCanonical.has(key)) byCanonical.set(key, reference);
  }
  return [...byCanonical.values()].slice(0, MAX_DISCOVERED_CHANGE_REFERENCES);
}

function addQuery(queries, seen, query, source, weight, anchors) {
  const normalized = query.replace(/\s+/g, " ").trim().slice(0, 240);
  const key = normalized.toLowerCase();
  if (!normalized || seen.has(key) || queries.length >= 16) return;
  seen.add(key);
  queries.push({ query: normalized, source, weight, anchors: unique(anchors, 12) });
}

export function buildQueryPlan(anchorBundle) {
  const queries = [];
  const seen = new Set();
  const project = anchorBundle.project_names?.[0] ?? "";
  const explicitIds = anchorBundle.explicit_ids ?? [];
  const components = unique([
    ...(anchorBundle.components ?? []),
    ...(anchorBundle.architecture_context?.components ?? []),
  ]);
  const themes = anchorBundle.change_themes ?? [];
  const changeReferences = anchorBundle.change_references ?? [];

  for (const reference of changeReferences) {
    const identity = reference.project ? `${reference.project} MR${reference.iid}` : `MR${reference.iid}`;
    addQuery(
      queries,
      seen,
      `${identity} requirement_skills.md`,
      "change_reference_requirement",
      110,
      [reference.canonical],
    );
  }
  for (const reference of changeReferences) {
    const identity = reference.project ? `${reference.project} MR${reference.iid}` : `MR${reference.iid}`;
    addQuery(
      queries,
      seen,
      `${identity} design_skills.md`,
      "change_reference_design",
      108,
      [reference.canonical],
    );
  }
  for (const reference of changeReferences) {
    const identity = reference.project ? `${reference.project} MR${reference.iid}` : `MR${reference.iid}`;
    addQuery(queries, seen, identity, "change_reference", 105, [reference.canonical]);
  }
  for (const reference of changeReferences) {
    addQuery(queries, seen, reference.raw, "change_reference_raw", 102, [reference.canonical]);
  }

  for (const id of explicitIds) {
    addQuery(queries, seen, id, "explicit_id", 100, [id]);
    if (project) addQuery(queries, seen, `${project} ${id}`, "project_explicit_id", 98, [project, id]);
  }
  if (changeReferences.length === 0 && project && anchorBundle.git?.head_commit) {
    const head = anchorBundle.git.head_commit;
    addQuery(
      queries,
      seen,
      `${project} ${head} requirement_skills.md`,
      "git_head_commit_requirement",
      98,
      [project, head],
    );
    addQuery(
      queries,
      seen,
      `${project} ${head} design_skills.md`,
      "git_head_commit_design",
      97,
      [project, head],
    );
    addQuery(queries, seen, `${project} ${head}`, "git_head_commit", 96, [project, head]);
  }
  if (changeReferences.length === 0 && project && anchorBundle.git?.branch) {
    addQuery(
      queries,
      seen,
      `${project} ${anchorBundle.git.branch}`,
      "git_branch",
      90,
      [project, anchorBundle.git.branch],
    );
  }
  for (const component of components.slice(0, 4)) {
    for (const theme of themes.slice(0, 3)) {
      addQuery(queries, seen, `${component} ${theme}`, "component_theme", 75, [component, theme]);
    }
  }
  for (const route of (anchorBundle.routes ?? []).slice(0, 4)) {
    addQuery(queries, seen, `${project} ${route}`, "route", 72, [project, route]);
  }
  for (const symbol of (anchorBundle.symbols ?? []).slice(0, 5)) {
    addQuery(queries, seen, `${project} ${symbol}`, "symbol", 68, [project, symbol]);
  }
  for (const entity of (anchorBundle.data_entities ?? []).slice(0, 3)) {
    addQuery(queries, seen, `${project} ${entity}`, "data_entity", 62, [project, entity]);
  }
  for (const flow of (anchorBundle.architecture_context?.business_flows ?? []).slice(0, 3)) {
    addQuery(queries, seen, `${project} ${flow}`, "business_flow", 58, [project, flow]);
  }
  if (queries.length === 0) {
    for (const component of components.slice(0, 3)) {
      addQuery(queries, seen, `${project} ${component}`, "component_fallback", 45, [project, component]);
    }
  }
  if (queries.length === 0 && project) {
    addQuery(queries, seen, project, "project_fallback", 30, [project]);
  }
  return queries;
}

export function collectChangeAnchors({
  target_root: targetRoot,
  base_ref: baseRef,
  change_references: changeReferences,
  architecture_context,
}) {
  if (typeof targetRoot !== "string" || !targetRoot.trim()) {
    throw new Error("target_root is required");
  }
  const resolvedRoot = fs.realpathSync(targetRoot);
  if (!fs.statSync(resolvedRoot).isDirectory()) throw new Error("target_root must be a directory");

  const topLevel = runGit(resolvedRoot, ["rev-parse", "--show-toplevel"]);
  const isGit = topLevel.ok;
  const gitRoot = isGit ? fs.realpathSync(topLevel.stdout.trim()) : resolvedRoot;
  const headResult = isGit ? runGit(gitRoot, ["rev-parse", "HEAD"]) : { ok: false, stdout: "" };
  const head = headResult.ok ? headResult.stdout.trim() : null;
  const branchResult = isGit ? runGit(gitRoot, ["branch", "--show-current"]) : { ok: false, stdout: "" };
  const branch = branchResult.ok ? branchResult.stdout.trim() : "";
  const base = isGit && head ? resolveBase(gitRoot, baseRef, head) : { reference: null, commit: null, source: "not_git" };
  const changedFiles = isGit && head ? collectChangedFiles(gitRoot, base.commit, head) : [];
  const diff = isGit && head ? collectDiff(gitRoot, base.commit, head) : "";
  const commits = isGit && head ? collectCommits(gitRoot, base.commit, head) : [];
  const lines = addedLines(diff);
  const architectureContext = normalizeArchitectureContext(architecture_context);
  const projectNames = readProjectNames(gitRoot);
  const explicitChangeReferences = normalizeChangeReferences(changeReferences, projectNames[0]).map(
    (reference) => ({ ...reference, source: "audit_scope" }),
  );
  const discoveredChangeReferences = isGit
    ? discoverGitLabMergeRequestReferences(gitRoot, branch, commits, head, projectNames[0])
    : [];
  const normalizedChangeReferences = mergeChangeReferences(
    explicitChangeReferences,
    discoveredChangeReferences,
  );
  const symbols = extractSymbols(lines);
  const routes = extractRoutes(lines);
  const dataEntities = extractDataEntities(lines);
  const configurationKeys = extractConfigurationKeys(lines);
  const pathComponents = componentsFromPaths(changedFiles);
  const components = unique([...architectureContext.components, ...pathComponents], 40);
  const changeThemes = themesFromCommits(commits);
  const explicitIds = extractExplicitIds([
    branch,
    ...commits.flatMap((commit) => [commit.subject, commit.body]),
    ...changedFiles.flatMap((row) => [row.path, row.old_path]),
  ]);

  const anchorBundle = {
    schema_version: "requirement-anchors.v1",
    target_root: resolvedRoot,
    repository_root: gitRoot,
    git: {
      available: isGit,
      branch: sanitizeAnchorText(branch) || null,
      base_ref: base.reference,
      base_commit: base.commit,
      base_resolution: base.source,
      head_commit: head,
      commit_count: commits.length,
    },
    project_names: projectNames,
    change_references: normalizedChangeReferences,
    explicit_ids: explicitIds,
    change_themes: changeThemes,
    components,
    symbols,
    routes,
    data_entities: dataEntities,
    configuration_keys: configurationKeys,
    changed_files: changedFiles.map((row) => ({
      ...row,
      path: sanitizeAnchorText(row.path),
      ...(row.old_path ? { old_path: sanitizeAnchorText(row.old_path) } : {}),
    })),
    commits: commits.map((commit) => ({
      commit: commit.commit,
      subject: sanitizeAnchorText(commit.subject),
    })),
    architecture_context: architectureContext,
    privacy: {
      full_diff_included: false,
      source_code_included: false,
      secrets_included: false,
    },
  };
  anchorBundle.query_plan = buildQueryPlan(anchorBundle);
  return anchorBundle;
}
