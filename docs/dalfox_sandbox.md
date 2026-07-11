# Dalfox in the RedSee sandbox

`docker/sandbox/Dockerfile` installs [Dalfox](https://github.com/hahwul/dalfox) v2.13.0
(pinned, downloaded from the official GitHub release, sha256-verified) alongside sqlmap.
It runs through the exact same `engine.sandbox.run_in_sandbox` path — same non-root user
(uid 10001), same `--cap-drop=ALL`/`--read-only`/no-new-privileges, same egress-restricted
network, same fail-closed isolation self-test. No sandbox hardening was changed to add it.

**Why v2.13.0, not the latest v3.x:** Dalfox v3.0.0 (2026-05-25) is a full CLI rewrite —
no `version`/`url` subcommands, different flags (`-V`, `scan`, `--no-color` only). v2.13.0
(2026-05-07) is the last release with the classic, widely-documented interface
(`dalfox version`, `dalfox url TARGET`) and the `[POC]`/`[V]` output format below.

## Verifying the image

```bash
bash docker/sandbox/build.sh

docker run --rm redsee-sandbox:latest dalfox version   # prints "v2.13.0"
docker run --rm redsee-sandbox:latest sqlmap --version  # sqlmap still present
docker run --rm redsee-sandbox:latest id                 # uid=10001(redsee) — still non-root
```

`PYTHONPATH=. python -m pytest tests/test_sandbox.py -v` still passes unmodified
(`engine/sandbox.py` was not touched — this was an image-only change).

## Ground-truth manual check (through the real sandbox path)

Run through `engine.sandbox.run_in_sandbox` — the same call path `modules/sqli.py` uses,
just with `dalfox url ... --no-color` as the argv instead of `sqlmap ...`:

```python
from engine.scope import load_scope_config
from engine.sandbox import run_in_sandbox

scope = load_scope_config()
url = "http://redsees.com:3000/rest/products/search?q=apple"
sr = run_in_sandbox(["dalfox", "url", url, "--no-color"], target_url=url,
                    config=scope, timeout_sec=120)
print(sr.exit_code, sr.stdout, sr.stderr)
```

**Result against Juice Shop (`redsees.com:3000`, up at time of test): a true negative,
not a false positive suppressed.** `exit_code=0`, `stdout` empty, `stderr` (the full,
real captured run):

```
 🎯  Target                 http://redsees.com:3000/rest/products/search?q=apple
 🏁  Method                 GET
 ...
[I] Found 1 testing points in DOM-based parameter mining
[I] Access-Control-Allow-Origin is *
[I] Content-Type is application/json; charset=utf-8
[I] X-Frame-Options is SAMEORIGIN
[I] Reflected q param =>
[*] [duration: 42.04s][issues: 0] Finish Scan!
```

**Why this is a correct negative, not a scanner limitation being papered over:**
Juice Shop's actual XSS challenge (`<iframe src="javascript:alert(...)">` via the search
bar) is **DOM-based**: the payload is only ever interpreted client-side by Angular after
the SPA has loaded — it never becomes a distinguishable server request, so no
non-headless, request/response-based scanner (Dalfox included, without its optional
headless-Chromium verification, which this minimal image intentionally does not include)
can detect it. Manually confirmed here that Juice Shop's other server-rendered surface is
also not exploitable: `/rest/products/search?q=` returns properly-escaped JSON (not
vulnerable), and the Express "Unexpected path" 500 error page HTML-escapes (`&lt;`/`&gt;`)
any literal `<`/`>` in the reflected URL (also not vulnerable) — confirmed by hand with
`curl` before concluding Dalfox's "0 issues" is correct, not a missed finding.

Per-project convention, the repo's established ground truth for classic **server-side**
reflected XSS is **DVWA's `/vulnerabilities/xss_r/`** (already used by
`tests/test_xss.py`) — not Juice Shop. A follow-up task can point this same
`run_in_sandbox(["dalfox", "url", ...])` call at that endpoint (with DVWA up) to capture
a live positive run; this was intentionally deferred here rather than starting a second
demo container as part of an image-only task.

## What a POSITIVE detection looks like (for the next prompt's parser)

No live positive capture exists yet (see above), so this section is the **authoritative
format straight from Dalfox v2.13.0's own source** (`internal/printing/logger.go` +
`internal/printing/poc.go` at tag `v2.13.0`), not a guess:

- Every non-PoC log line is prefixed by a bracketed level tag and written to **stderr**:
  `[I]` info, `[W]` weak/heuristic signal, `[V]` confirmed vulnerability, `[*]` system,
  `[G]` grep match, `[E]` error. This matches exactly what was captured above (`[I]`/`[*]`
  lines, stderr, nothing on stdout for the negative case).
- On a **confirmed** finding, Dalfox emits (in order):
  1. `[V] Triggered XSS Payload (found dialog in headless)` — or, for a DOM-object match:
     `[V] Triggered XSS Payload (found DOM Object): <param>=<payload>` (stderr)
  2. An indented `    <evidence>` line (no bracket tag — the raw PoC evidence/context; stderr)
  3. **`[POC][<Type>][<Method>][<InjectType>] <Data>`** — written to **stdout** (not
     stderr), e.g. `[POC][G][GET][inHTML-none] http://target/search?q=<payload>`.
     This is the line a parser should grep stdout for: `Type` is a short scan-type code
     (e.g. `G` = GET-mode), `Method` is the HTTP method, `InjectType` names the injection
     context (`inHTML-none`, `inJS`, `inATTR`, ...), and `Data` is the full PoC
     URL/request. With `--format json`/`--format jsonl` (not used above), the same PoC is
     instead printed as a JSON object on stdout.
- A **clean** run (as captured above) never emits a `[V]` or `[POC]` line — `stdout` stays
  empty and the run ends with `[*] [duration: ...][issues: 0] Finish Scan!` on stderr.
  A parser should treat "vulnerable" as `stdout` containing at least one `[POC]` line
  (or `[V]` on stderr), never the mere presence of `[I]`/reflection-detected chatter.
