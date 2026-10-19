import { createHash } from "node:crypto";

const CANDIDATE_KEYS = new Set([
  "content",
  "document_id",
  "id",
  "name",
  "snippet",
  "text",
  "title",
  "url",
]);
const ARRAY_KEYS = new Set(["documents", "hits", "items", "matches", "records", "results"]);
const CREDENTIAL_URL_FIELDS = new Set([
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

function clampText(value, limit) {
  if (typeof value !== "string") return "";
  return value.replace(/\u0000/g, "").trim().slice(0, limit);
}

function firstString(object, keys, limit = 500) {
  for (const key of keys) {
    const value = object?.[key];
    if (typeof value === "string" && value.trim()) return clampText(value, limit);
    if (typeof value === "number") return String(value);
  }
  return "";
}

function safeExternalUrl(value) {
  const text = clampText(value, 2000);
  if (!text) return "";
  try {
    const parsed = new URL(text);
    if (!["http:", "https:"].includes(parsed.protocol)) return "";
    if (parsed.username || parsed.password) return "";
    const parameterNames = [
      ...parsed.searchParams.keys(),
      ...new URLSearchParams(parsed.hash.slice(1)).keys(),
    ];
    if (
      parameterNames.some((key) =>
        CREDENTIAL_URL_FIELDS.has(key.toLowerCase().replaceAll("-", "_")),
      )
    ) {
      return "";
    }
    return parsed.href;
  } catch {
    return "";
  }
}

function stableId(candidate) {
  const identity = candidate.id || candidate.url || `${candidate.title}\n${candidate.snippet}`;
  return `requirement-${createHash("sha256").update(identity).digest("hex").slice(0, 16)}`;
}

function looksLikeCandidate(object) {
  if (!object || typeof object !== "object" || Array.isArray(object)) return false;
  const keys = Object.keys(object);
  const hits = keys.filter((key) => CANDIDATE_KEYS.has(key)).length;
  return hits >= 2 || (hits >= 1 && keys.some((key) => /document|requirement|source/i.test(key)));
}

function normalizeCandidate(object, query, connectorId) {
  const candidate = {
    id: firstString(object, ["document_id", "doc_id", "id", "uuid"], 200),
    title: firstString(object, ["title", "name", "subject", "heading"], 500),
    url: safeExternalUrl(firstString(object, ["url", "web_url", "source_url", "link"], 2000)),
    snippet: firstString(object, ["snippet", "summary", "description", "text", "content"], 4000),
    content: firstString(object, ["content", "body", "text", "markdown"], 64000),
    status: firstString(object, ["status", "state", "document_status"], 100),
    owner: firstString(object, ["owner", "author", "created_by"], 300),
    updated_at: firstString(object, ["updated_at", "modified_at", "last_updated", "date"], 100),
    connector_id: connectorId,
    query_matches: [query],
    untrusted_external_content: true,
  };
  if (!candidate.title) candidate.title = candidate.id || "Untitled requirement document";
  if (!candidate.id) candidate.id = stableId(candidate);
  return candidate;
}

function collectObjects(value, depth = 0, output = []) {
  if (depth > 5 || output.length >= 100) return output;
  if (Array.isArray(value)) {
    for (const child of value) collectObjects(child, depth + 1, output);
    return output;
  }
  if (!value || typeof value !== "object") return output;
  if (looksLikeCandidate(value)) output.push(value);
  for (const [key, child] of Object.entries(value)) {
    if (ARRAY_KEYS.has(key) || (depth < 2 && typeof child === "object")) {
      collectObjects(child, depth + 1, output);
    }
  }
  return output;
}

function resultText(result) {
  if (!Array.isArray(result?.content)) return "";
  return result.content
    .filter((item) => item?.type === "text" && typeof item.text === "string")
    .map((item) => item.text)
    .join("\n")
    .slice(0, 64000);
}

export function normalizeSearchResult(result, query, connectorId) {
  const objects = collectObjects(result?.structuredContent ?? result);
  if (objects.length > 0) {
    return objects.map((object) => normalizeCandidate(object, query, connectorId));
  }

  const text = resultText(result);
  if (!text) return [];
  return [
    normalizeCandidate(
      {
        title: `Search response for ${query}`,
        text,
      },
      query,
      connectorId,
    ),
  ];
}

export function normalizeFetchResult(result, documentId, connectorId) {
  const objects = collectObjects(result?.structuredContent ?? result);
  if (objects.length > 0) {
    const candidate = normalizeCandidate(objects[0], `fetch:${documentId}`, connectorId);
    if (!candidate.id || candidate.id.startsWith("requirement-")) candidate.id = documentId;
    return candidate;
  }
  const text = resultText(result);
  return {
    id: documentId,
    title: documentId,
    url: "",
    snippet: text.slice(0, 4000),
    content: text,
    status: "",
    owner: "",
    updated_at: "",
    connector_id: connectorId,
    query_matches: [`fetch:${documentId}`],
    untrusted_external_content: true,
  };
}

function searchable(candidate) {
  return [candidate.id, candidate.title, candidate.url, candidate.snippet, candidate.content, candidate.status]
    .join("\n")
    .toLowerCase();
}

function familyValues(anchorBundle) {
  const headCommit = anchorBundle.git?.head_commit ?? "";
  const gitIdentities = headCommit ? [headCommit, headCommit.slice(0, 12)] : [];
  return [
    ["explicit_id", anchorBundle.explicit_ids ?? [], 60],
    ["git_commit", gitIdentities, 45],
    ["git_branch", anchorBundle.git?.branch ? [anchorBundle.git.branch] : [], 35],
    ["route", anchorBundle.routes ?? [], 20],
    ["symbol", anchorBundle.symbols ?? [], 15],
    ["component", anchorBundle.components ?? [], 12],
    ["data_entity", anchorBundle.data_entities ?? [], 10],
    ["configuration_key", anchorBundle.configuration_keys ?? [], 10],
    ["business_flow", anchorBundle.architecture_context?.business_flows ?? [], 10],
    ["change_theme", anchorBundle.change_themes ?? [], 5],
    ["project", anchorBundle.project_names ?? [], 3],
  ];
}

function candidateMergeRequestPath(candidate) {
  const url = safeExternalUrl(candidate.url);
  if (!url) return null;
  try {
    const segments = new URL(url).pathname.split("/").filter(Boolean);
    for (let index = 1; index < segments.length; index += 1) {
      const compact = segments[index].match(/^MR(?<iid>\d{1,10})$/i);
      if (compact?.groups?.iid) {
        return { project: segments[index - 1], iid: String(Number(compact.groups.iid)) };
      }
      if (
        segments[index].toLowerCase() === "merge_requests" &&
        /^\d{1,10}$/.test(segments[index + 1] ?? "")
      ) {
        const projectIndex = segments[index - 1] === "-" ? index - 2 : index - 1;
        return {
          project: segments[projectIndex] ?? "",
          iid: String(Number(segments[index + 1])),
        };
      }
    }
  } catch {
    return null;
  }
  return null;
}

function matchChangeReferences(candidate, anchorBundle) {
  const candidatePath = candidateMergeRequestPath(candidate);
  const references = anchorBundle.change_references ?? [];
  const matches = [];
  let status = "none";
  for (const reference of references) {
    if (reference.kind !== "gitlab_merge_request" || !candidatePath) continue;
    const sameProject =
      !reference.project || candidatePath.project.toLowerCase() === reference.project.toLowerCase();
    if (sameProject && candidatePath.iid === reference.iid) {
      status = "exact";
      matches.push({
        kind: reference.kind,
        canonical: reference.canonical,
        match: "exact_url_path",
      });
    } else if (sameProject && status !== "exact") {
      status = "conflict";
    }
  }
  return { status, matches, candidate_path: candidatePath };
}

export function scoreCandidate(candidate, anchorBundle) {
  const haystack = searchable(candidate);
  const matched = [];
  let score = 0;
  const changeReferenceMatch = matchChangeReferences(candidate, anchorBundle);
  if (changeReferenceMatch.status === "exact") {
    score += 80;
    matched.push(
      ...changeReferenceMatch.matches.map((match) => ({
        family: "change_reference",
        value: match.canonical,
        match: match.match,
      })),
    );
  }
  for (const [family, values, weight] of familyValues(anchorBundle)) {
    let familyMatches = 0;
    for (const value of values) {
      const normalized = String(value).trim().toLowerCase();
      if (normalized.length < 2 || !haystack.includes(normalized)) continue;
      matched.push({ family, value: String(value) });
      familyMatches += 1;
    }
    score += weight * Math.min(familyMatches, family === "explicit_id" ? 2 : 3);
  }
  if (changeReferenceMatch.status === "conflict") score = Math.min(score, 20);
  score = Math.min(score, 100);
  return {
    ...candidate,
    relevance: {
      score,
      confidence: score >= 70 ? "high" : score >= 40 ? "medium" : "low",
      matched_anchors: matched,
      change_reference_match: changeReferenceMatch,
    },
  };
}

export function mergeAndScoreCandidates(candidates, anchorBundle) {
  const merged = new Map();
  for (const candidate of candidates) {
    const key = `${candidate.connector_id}:${candidate.id || candidate.url || candidate.title}`;
    const existing = merged.get(key);
    if (!existing) {
      merged.set(key, candidate);
      continue;
    }
    merged.set(key, {
      ...existing,
      ...candidate,
      snippet: candidate.snippet.length > existing.snippet.length ? candidate.snippet : existing.snippet,
      content: candidate.content.length > existing.content.length ? candidate.content : existing.content,
      query_matches: [...new Set([...existing.query_matches, ...candidate.query_matches])],
    });
  }
  return [...merged.values()]
    .map((candidate) => scoreCandidate(candidate, anchorBundle))
    .sort(
      (left, right) =>
        right.relevance.score - left.relevance.score || left.title.localeCompare(right.title),
    );
}
