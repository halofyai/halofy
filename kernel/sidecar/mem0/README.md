# Halofy mem0 sidecar

Out-of-process retriever cartridge for the Halofy kernel. The kernel's
`Mem0Driver` (`src/driver/mem0.ts`) ships ACL-scoped candidates (max 200) to
this sidecar over HTTP and gets back a reordering. The sidecar can only
reorder what it was sent — refs outside the sent set are dropped kernel-side.

## Run

Python 3.9+, standard library only — no install required:

```bash
python server.py --port 8790
```

Then point the kernel at it:

```bash
export HALOMEM_MEM0_URL=http://localhost:8790
```

(Windows PowerShell: `$env:HALOMEM_MEM0_URL = "http://localhost:8790"`.)

The kernel mounts the mem0 driver only when `HALOMEM_MEM0_URL` is set; the
`Mem0Driver` constructor throws `DriverUnavailableError` without it.

## Ranking modes

- **fallback** (default): deterministic BM25-ish token-overlap ranking.
  Zero keys, zero network, reproducible — the sidecar works out of the box.
- **mem0**: used automatically when the `mem0ai` package is importable AND
  `OPENAI_API_KEY` is set. Optional install:

  ```bash
  pip install mem0ai
  export OPENAI_API_KEY=sk-...
  ```

Check which mode is active:

```bash
curl http://localhost:8790/healthz
# {"ok": true, "mode": "fallback"}
```

## HTTP contract

```
POST /plan
  {"query": "...", "candidates": [{"ref": "...", "content": "..."}],
   "budget": 2000, "k": 8}
  -> 200 {"refs": [{"ref": "...", "score": 0.93}, ...]}
  -> 400 {"error": "..."} on malformed input

GET /healthz
  -> 200 {"ok": true, "mode": "mem0" | "fallback"}
```

Driver behavior on failure: 1.5s timeout per attempt, one retry, then
`DriverUnavailableError` — the kernel falls back to the baseline driver and
audits the fallback.

Set `HALOMEM_MEM0_VERBOSE=1` to enable per-request access logs.
