#!/usr/bin/env python3
"""HaloMem mem0 sidecar — out-of-process retriever cartridge.

Stdlib-only HTTP server (http.server + json). Contract (see CONTRACTS-M2.md):

    POST /plan {"query": str, "candidates": [{"ref": str, "content": str}],
                "budget": int, "k": int}
        -> {"refs": [{"ref": str, "score": float}]}
    GET  /healthz -> {"ok": true, "mode": "mem0" | "fallback"}

Ranking modes:
  * "mem0"     — used when the `mem0ai` package is importable AND
                 OPENAI_API_KEY is set: candidates are loaded into an
                 in-memory Mem0 store and ranked by Mem0 search.
  * "fallback" — deterministic token-overlap (BM25-ish) ranking. No keys, no
                 network, fully reproducible; makes the sidecar runnable with
                 zero configuration.

The sidecar only ever REORDERS the candidates it was sent — it never invents
refs (and the kernel-side driver drops any alien ref anyway).

Run:  python server.py --port 8790
"""

import argparse
import json
import math
import os
import re
import sys
import threading
import uuid
from collections import OrderedDict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# ---------------------------------------------------------------------------
# Optional real-mem0 path
# ---------------------------------------------------------------------------

_MEM0_AVAILABLE = False
try:  # pragma: no cover - depends on optional install
    if os.environ.get("OPENAI_API_KEY"):
        from mem0 import Memory  # type: ignore  # provided by `pip install mem0ai`

        _MEM0_AVAILABLE = True
except Exception:  # ImportError or any misconfiguration -> fallback mode
    _MEM0_AVAILABLE = False

MODE = "mem0" if _MEM0_AVAILABLE else "fallback"

BM25_K1 = 1.5
BM25_B = 0.75
_TOKEN_RE = re.compile(r"[a-z0-9]+")


def _tokenize(text):
    return _TOKEN_RE.findall(text.lower())


def rank_fallback(query, candidates, k):
    """Deterministic BM25-ish token-overlap ranking, scores normalized 0..1.

    Ties break on ref (ascending) so identical inputs always produce
    identical output order.
    """
    query_terms = sorted(set(_tokenize(query)))
    if not query_terms or not candidates:
        return []

    doc_tokens = [_tokenize(c["content"]) for c in candidates]
    n = len(candidates)
    avgdl = (sum(len(t) for t in doc_tokens) / n) or 1.0

    tf_per_doc = []
    for toks in doc_tokens:
        tf = {}
        for t in toks:
            tf[t] = tf.get(t, 0) + 1
        tf_per_doc.append(tf)

    df = {
        term: sum(1 for tf in tf_per_doc if term in tf) for term in query_terms
    }

    scored = []
    for i, cand in enumerate(candidates):
        dl = len(doc_tokens[i])
        score = 0.0
        for term in query_terms:
            tf = tf_per_doc[i].get(term, 0)
            if tf == 0:
                continue
            idf = math.log(1.0 + (n - df[term] + 0.5) / (df[term] + 0.5))
            score += (idf * tf * (BM25_K1 + 1.0)) / (
                tf + BM25_K1 * (1.0 - BM25_B + BM25_B * dl / avgdl)
            )
        if score > 0.0:
            scored.append((cand["ref"], score))

    if not scored:
        return []

    scored.sort(key=lambda rs: (-rs[1], rs[0]))
    scored = scored[: max(k, 0)]
    top = scored[0][1] or 1.0
    return [{"ref": ref, "score": score / top} for ref, score in scored]


def rank_mem0(query, candidates, k):  # pragma: no cover - needs mem0ai + key
    """Real Mem0 ranking: ingest candidates, search, clean up.

    NOTE: `Memory()` is PERSISTENT by default (on-disk vector store + SQLite
    history), not in-memory. To keep every /plan call hermetic — no
    cross-request crowding, no history-dependent scores — each request
    ingests under a UNIQUE user_id and deletes those memories afterwards.
    """
    memory = Memory()
    request_user = "halomem-%s" % uuid.uuid4().hex
    try:
        ref_by_id = {}
        for cand in candidates:
            added = memory.add(
                cand["content"], user_id=request_user, metadata={"ref": cand["ref"]}
            )
            for item in added.get("results", []):
                ref_by_id[item.get("id")] = cand["ref"]

        results = memory.search(query, user_id=request_user, limit=k)
        known = {c["ref"] for c in candidates}
        refs = []
        seen = set()
        for item in results.get("results", []):
            ref = (item.get("metadata") or {}).get("ref") or ref_by_id.get(
                item.get("id")
            )
            if ref is None or ref not in known or ref in seen:
                continue
            seen.add(ref)
            refs.append({"ref": ref, "score": float(item.get("score") or 0.0)})
        return refs
    finally:
        try:
            memory.delete_all(user_id=request_user)
        except Exception as exc:
            print(
                "[mem0-sidecar] cleanup of %s failed: %s" % (request_user, exc),
                file=sys.stderr,
            )


def rank(query, candidates, k):
    if MODE == "mem0":
        try:
            return rank_mem0(query, candidates, k)
        except Exception as exc:  # keyed-but-broken -> stay useful
            print(
                "[mem0-sidecar] mem0 ranking failed (%s); using fallback" % exc,
                file=sys.stderr,
            )
    return rank_fallback(query, candidates, k)


# ---------------------------------------------------------------------------
# Request validation
# ---------------------------------------------------------------------------


def validate_plan(payload):
    """Return (query, candidates, k) or raise ValueError with a client message."""
    if not isinstance(payload, dict):
        raise ValueError("body must be a JSON object")
    query = payload.get("query")
    if not isinstance(query, str) or not query.strip():
        raise ValueError("'query' must be a non-empty string")
    candidates = payload.get("candidates")
    if not isinstance(candidates, list):
        raise ValueError("'candidates' must be an array")
    for i, cand in enumerate(candidates):
        if (
            not isinstance(cand, dict)
            or not isinstance(cand.get("ref"), str)
            or not isinstance(cand.get("content"), str)
        ):
            raise ValueError(
                "'candidates[%d]' must be {ref: string, content: string}" % i
            )
    k = payload.get("k", 8)
    if not isinstance(k, int) or isinstance(k, bool) or k < 0:
        raise ValueError("'k' must be a non-negative integer")
    budget = payload.get("budget", None)
    if budget is not None and (
        not isinstance(budget, (int, float)) or isinstance(budget, bool)
    ):
        raise ValueError("'budget' must be a number when present")
    return query, candidates, k


# ---------------------------------------------------------------------------
# Request-id dedupe (idempotent /plan)
# ---------------------------------------------------------------------------
#
# The kernel driver retries a timed-out /plan with the SAME
# x-halomem-request-id. In real-mem0 mode the first attempt keeps executing
# server-side after the client aborts, so re-running it would double the
# LLM/embedding spend. Duplicate ids therefore coalesce: the retry waits for
# the in-flight computation (bounded), and completed responses are served
# from a small LRU cache.

_PLAN_CACHE_MAX = 256
_PLAN_WAIT_SECONDS = 600.0

_plan_lock = threading.Lock()
_plan_inflight = {}  # request_id -> threading.Event
_plan_cache = OrderedDict()  # request_id -> (status, payload)


def run_plan_deduped(request_id, compute):
    """Run `compute() -> (status, payload)` once per request_id.

    Duplicate ids wait for the original computation and return its cached
    result. No request_id (None) -> just compute.
    """
    if not request_id:
        return compute()

    while True:
        with _plan_lock:
            cached = _plan_cache.get(request_id)
            if cached is not None:
                _plan_cache.move_to_end(request_id)
                return cached
            event = _plan_inflight.get(request_id)
            if event is None:
                event = threading.Event()
                _plan_inflight[request_id] = event
                break  # we own the computation
        # Someone else is computing this id — wait for them.
        if not event.wait(_PLAN_WAIT_SECONDS):
            return (503, {"error": "duplicate request still in flight"})
        # Loop back to pick the cached result up.

    try:
        result = compute()
    except Exception as exc:  # cache the failure too — retries must not re-run
        result = (500, {"error": "ranking failed: %s" % exc})
    with _plan_lock:
        _plan_cache[request_id] = result
        while len(_plan_cache) > _PLAN_CACHE_MAX:
            _plan_cache.popitem(last=False)
        _plan_inflight.pop(request_id, None)
    event.set()
    return result


# ---------------------------------------------------------------------------
# HTTP plumbing
# ---------------------------------------------------------------------------


class Handler(BaseHTTPRequestHandler):
    server_version = "halomem-mem0/0.1"

    def _send_json(self, status, obj):
        body = json.dumps(obj).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/healthz":
            self._send_json(200, {"ok": True, "mode": MODE})
        else:
            self._send_json(404, {"error": "not found"})

    def do_POST(self):
        if self.path != "/plan":
            self._send_json(404, {"error": "not found"})
            return
        try:
            length = int(self.headers.get("Content-Length") or 0)
            raw = self.rfile.read(length) if length > 0 else b""
            payload = json.loads(raw.decode("utf-8") or "null")
        except (ValueError, UnicodeDecodeError):
            self._send_json(400, {"error": "invalid JSON body"})
            return
        try:
            query, candidates, k = validate_plan(payload)
        except ValueError as exc:
            self._send_json(400, {"error": str(exc)})
            return

        def compute():
            try:
                refs = rank(query, candidates, k)
            except Exception as exc:  # never 500 on rankable input if avoidable
                return (500, {"error": "ranking failed: %s" % exc})
            return (200, {"refs": refs})

        request_id = self.headers.get("X-Halomem-Request-Id")
        status, obj = run_plan_deduped(request_id, compute)
        self._send_json(status, obj)

    def log_message(self, fmt, *args):  # quiet by default
        if os.environ.get("HALOMEM_MEM0_VERBOSE"):
            super().log_message(fmt, *args)


def main():
    parser = argparse.ArgumentParser(description="HaloMem mem0 sidecar")
    parser.add_argument("--port", type=int, default=8790)
    parser.add_argument("--host", default="127.0.0.1")
    args = parser.parse_args()

    server = ThreadingHTTPServer((args.host, args.port), Handler)
    print(
        "[mem0-sidecar] listening on http://%s:%d (mode=%s)"
        % (args.host, args.port, MODE)
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
