# ProtonWire development shell — the repo-scoped source of every build
# tool (standing rule: no system-wide or ad-hoc tool installs).
#
#   nix-shell                    # rust toolchain + linker + audit + fmt/clippy
#   nix-shell --arg gui true     # + webkit2gtk stack, for protonwire-gui
#
# Classic nix-shell, deliberately: the repository uses git's reftable
# refstorage, which Nix's libgit2 (flake git+file fetching) cannot read
# yet — see docs/review-log.md. A flake replaces this when nixpkgs/nix
# catch up (tracked with the M8 packaging work).
{ gui ? false }:
let
  # nixos-unstable pinned 2026-08-15: rustc 1.97.1 / cargo 1.97.0 — the
  # verified workspace toolchain (docs/spike-2026-08.md). rustup users
  # get the same pair from the rust-toolchain.toml pin; inside this shell
  # the rustup shims are bypassed and rust-toolchain.toml is inert.
  nixpkgs = builtins.fetchTarball {
    url = "https://github.com/NixOS/nixpkgs/archive/0e251e24a4f24e036a084b6b4b2d2491af4167f4.tar.gz";
    sha256 = "118n3xlp9fyf52588yhxa0a5xyi0gchci09l0vblrm7m8zimvln8";
  };
  pkgs = import nixpkgs { };

  core = with pkgs; [
    rustc
    cargo
    rustfmt
    clippy
    gcc # linker for the engine chain's C code
    cargo-audit
    git
  ];

  # The Tauri GUI's system libraries; CI installs the deb equivalents in
  # its dedicated job, this shell makes `cargo check -p protonwire-gui`
  # work locally.
  gui-libs = with pkgs; [
    webkitgtk_4_1
    gtk3
    librsvg
    libayatana-appindicator
    pkg-config
  ];
in
pkgs.mkShell {
  name = "protonwire" + pkgs.lib.optionalString gui "-gui";
  packages = core ++ pkgs.lib.optionals gui gui-libs;
  shellHook = ''
    echo "protonwire devshell: $(rustc --version | cut -d' ' -f2)${
      pkgs.lib.optionalString gui " + webkit2gtk (protonwire-gui compiles here)"
    }"
    echo "gates: cargo fmt --all --check; cargo clippy --all-targets -- -D warnings; cargo test; cargo xtask all"
  '';
}
