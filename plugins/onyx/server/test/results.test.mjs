import assert from "node:assert/strict";
import test from "node:test";

import { normalizeSearchResult } from "../lib/results.mjs";


test("keeps only credential-free HTTP and HTTPS document URLs", () => {
  const candidates = normalizeSearchResult(
    {
      structuredContent: {
        results: [
          { id: "safe", title: "Safe", url: "https://requirements.example.test/doc" },
          { id: "script", title: "Script", url: "javascript:alert(1)" },
          { id: "credential", title: "Credential", url: "https://user:secret@example.test/doc" },
          { id: "query", title: "Query", url: "https://example.test/doc?access_token=secret" },
          { id: "fragment", title: "Fragment", url: "https://example.test/doc#token=secret" },
        ],
      },
    },
    "SEC-482",
    "onyx",
  );
  assert.equal(
    candidates.find((candidate) => candidate.id === "safe").url,
    "https://requirements.example.test/doc",
  );
  assert.equal(candidates.find((candidate) => candidate.id === "script").url, "");
  assert.equal(candidates.find((candidate) => candidate.id === "credential").url, "");
  assert.equal(candidates.find((candidate) => candidate.id === "query").url, "");
  assert.equal(candidates.find((candidate) => candidate.id === "fragment").url, "");
});
