# Contributing to ProtonWire

Read the specification set before changing behavior — the PRD is normative:

- `docs/PRD-proton-wire.md` — product requirements (the contract)
- `docs/ADR-0001-monorepo-core-and-clients.md` — architecture invariants
- `docs/spike-2026-08.md` — dependency decisions and MSRV evidence
- `docs/review-log.md` — every SDLC review's triage; nothing reviewed
  silently disappears, so check it before re-proposing something

## Workflow

1. **TDD is standing practice**: failing test first (run it, watch it fail
   for the right reason), then the minimal implementation, then refactor
   with the suite green.
2. Branch per coherent unit (`feat/...`, `fix/...`), commit per unit,
   conventional-commit style.
3. Each coherent unit passes the matching reviewer before it counts as
   done (rust-reviewer for Rust, sec-auditor for trust surfaces,
   qa-engineer against the PRD test plan, refactorer for structure,
   compliance-reviewer for control mapping, doc-writer for docs).
4. Findings land in `docs/review-log.md` — fixed now or tracked with a
   milestone.

## Development environment

All build and runtime tools come from the repo-scoped devshell
(`shell.nix`, pinned nixpkgs) — never from system-wide installs. With
direnv (recommended) it activates on entry:

```sh
direnv allow                        # core: rustc/cargo/rustfmt/clippy,
                                    # gcc, cargo-audit, git
PROTONWIRE_GUI=1 direnv allow       # + webkit2gtk stack for protonwire-gui
```

Without direnv: `nix-shell` / `nix-shell --arg gui true`.

The shell pins the verified toolchain (rustc 1.97.1); `rust-toolchain.toml`
is inert inside it (no rustup) and only serves rustup-based contributors
and CI, which installs its own pinned toolchains. A flake-based devshell
is blocked until Nix's libgit2 supports this repository's reftable ref
storage (tracked with the M8 packaging work).

## Local gates (must be green before push; run inside the devshell)

```sh
cargo fmt --all --check               # formatting
cargo clippy --all-targets -- -D warnings
cargo test                            # 27 test targets
cargo xtask all                       # parity manifest, groups, M49,
                                       # dep-graph, license inventory,
                                       # schema freshness
```
Toolchain floor: see `rust-toolchain.toml` and the spike record.

## Repo rules enforced by tooling

- `unsafe_code = deny` workspace-wide (the Tauri shell is the single,
  documented exception for its macro boundary).
- One root `Cargo.lock`, **committed** — it is the resolution authority
  for the pinned ProTUN/Muon engines (FR-127A). `cargo xtask dep-graph`
  fails if it is untracked; never add it to any gitignore.
- Dependency direction is machine-checked: clients never link the
  engines, core, or adapters; `clap`/`ratatui`/`tauri` never appear below
  the client boundary.
- Wire types live in `protonwire-frontend-api` only; after changing them,
  regenerate and commit `schemas/frontend/v1` (`cargo xtask schema-gen`).
- No wildcard dependency versions; new dependencies need a spike-record
  entry (stdlib-first policy).

## The GUI

`protonwire-gui` needs `libwebkit2gtk-4.1-dev`, `libgtk-3-dev`,
`librsvg2-dev`, and `libayatana-appindicator3-dev`; it is a workspace
member but not a default member, so plain `cargo build` skips it and CI
builds it in a dedicated job.

## Distribution is blocked

Do not publish binaries or source containing the Proton registry crates
until their license terms are cleared (`COPYING.md`, PRD OQ-2).
