# hardening/ — this fork's own work

Everything this fork adds lives in this one folder. **No upstream file is
changed on this branch**: outside `hardening/`, the tree is identical to
[BaaRai/ARTEX](https://github.com/BaaRai/ARTEX).

| Branch | Content |
|---|---|
| `main` | upstream ARTEX, untouched. Only ever synced from upstream. |
| `hardened` | upstream ARTEX + this folder. |

`git diff main hardened --stat` lists only paths under `hardening/`.

## AI review

After forking, the code was reviewed and hardened with an AI assistant (Claude
Fable 5.2, by Anthropic) on 2026-11-21. The full record is in
[HARDENING.md](HARDENING.md).

- The code-trust review covers upstream commit `22ae88a` (v0.7.0): no backdoor,
  telemetry or data-exfiltration path was found. The bundled tools were compared
  with their upstream releases, and the published v0.7.0 binaries for Linux and
  Windows were rebuilt from source byte for byte.
- Upstream commits after `22ae88a` were only scanned for new network calls,
  command execution and dependency changes.
- An AI review is not a professional security audit and not a guarantee. What
  was and was not verified is listed in section 6 of [HARDENING.md](HARDENING.md).

## What is in here

| Path | What it is |
|---|---|
| `HARDENING.md` | Review findings, design, limits, verification record |
| `docker-compose.hardened.yml` | Compose overlay: network firewall, DNS filter, named volumes |
| `egress-fw/` | The firewall sidecar image |
| `allowlist/` | Go package: in-program control-plane host allowlist |
| `patches/` | The only changes to upstream code, kept as patch files |
| `build/` | Hash-locked bbot requirements, npm pins and their verifier |
| `build.sh` | Builds the hardened image from the committed tree + patches |
| `sandbox/` | Isolated Docker test harness and the hijacked-model probe |
| `env.example` | The settings this folder adds |

## Why there are patches

Two things cannot be done without editing upstream files, so they are kept as
patches instead of edits:

- `patches/0001-egress-allowlist.patch` wires `allowlist/` into the LLM, model
  list, web search, notification, SMTP, S3 archive, MCP and update-check clients,
  and adds a test next to each of them.
- `patches/0002-dockerfile-pins.patch` pins the base images by digest, installs
  bbot with `pip --require-hashes`, and verifies the Playwright npm packages.

`build.sh` applies them to a temporary copy of the tree and builds from that
copy. The checkout is never modified. When a patch stops applying after an
upstream update, `build.sh` fails at that patch; refresh it against the new
upstream code.

## Use

```
cat hardening/env.example >> .env        # then edit .env
hardening/build.sh
docker compose -f docker-compose.yml -f hardening/docker-compose.hardened.yml up -d --no-build
```

Two settings need your values before real use:

- `ARTEX_EGRESS_ALLOW`: the host of the LLM provider you use.
- `ARTEX_FW_TARGETS`: the systems you are authorised to test. Empty means the
  scanner can reach nothing.

Without `build.sh` (a plain upstream image) the overlay still works: the network
firewall, DNS filter and named volumes apply; only the in-program allowlist and
the tighter build pins are missing.

**On Windows, always build with `build.sh`, not `docker compose build`.** A
Windows checkout has CRLF line endings, and `docker compose build` embeds the SQL
migration files that way. Their checksums then differ from an image built with LF
endings (`build.sh`, and every upstream release), and a database created by one
kind of image refuses to start with the other: `migration 0001 ...: checksum
changed since it was applied`. Stay with one kind; `build.sh` gives the same
bytes as upstream.

## Test

```
hardening/sandbox/run.sh                   # build, vet, test with the patches applied
APPLY_PATCHES=0 hardening/sandbox/run.sh   # the plain upstream tree
```

## Updating from upstream

```
git checkout main   && git pull upstream main && git push origin main
git checkout hardened && git merge main
hardening/sandbox/run.sh && hardening/build.sh
```

Because this branch changes no upstream file, the merge cannot conflict. Only
the patches can go stale.

## License

Upstream ARTEX is AGPL-3.0, and so is everything in this folder.
