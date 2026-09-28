{
  description = "Sapio passkey browser wallet: pinned Rust, WASM bindings and release tools";
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    flake-utils.url = "github:numtide/flake-utils";
  };
  outputs = { nixpkgs, rust-overlay, flake-utils, ... }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs { inherit system; overlays = [ rust-overlay.overlays.default ]; };
        rust = pkgs.rust-bin.stable."1.98.1".default.override {
          targets = [ "wasm32-unknown-unknown" ];
        };
      in {
        devShells.default = pkgs.mkShell {
          packages = with pkgs; [ rust stdenv.cc llvmPackages_21.clang llvmPackages_21.llvm wasm-bindgen-cli_0_2_114 python3 openssl git ];
        };
      });
}
