#!/usr/bin/env python3
"""Build the browser wallet offline and verify the unchanged SPK3 policy.

Run in the pinned development shell:
  nix develop --command python3 scripts/build.py

Fetch the locked Cargo dependencies separately before an offline build. Use
--check to rebuild into temporary storage and compare the generated browser
artifacts with web/pkg. This command never replaces the enclave predicate.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parent.parent
POLICY_SHA256 = "eaef7663d2c61d8bc43ad456baa583dcfa4a8ab95e26a18605783831f64a462b"
VERSIONS = {"rustc": "rustc 1.98.1 ", "clang": "clang version 21.1.8", "wasm-bindgen": "wasm-bindgen 0.2.114"}
OUTPUTS = ("sapio_passkey_wallet.js", "sapio_passkey_wallet_bg.wasm", "sapio_passkey_wallet.d.ts", "sapio_passkey_wallet_bg.wasm.d.ts")


def run(arguments, *, env=None):
    subprocess.run(arguments, cwd=ROOT, env=env, check=True)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--check", action="store_true", help="rebuild and compare existing web/pkg artifacts without replacing them")
    args = parser.parse_args()
    tools = {}
    for name, expected in VERSIONS.items():
        tools[name] = shutil.which(name)
        if not tools[name]:
            parser.error(f"{name} is missing; use the pinned Nix development shell")
        version = subprocess.check_output([tools[name], "--version"], text=True)
        if expected not in version:
            parser.error(f"expected {expected!r}; found {version.strip()!r}")
    for name in ("cargo", "llvm-ar"):
        tools[name] = shutil.which(name)
        if not tools[name]:
            parser.error(f"{name} is missing; use the pinned Nix development shell")
    for lock in (ROOT / "Cargo.lock", ROOT / "policy/Cargo.lock"):
        if not lock.is_file():
            parser.error(f"missing locked dependency graph: {lock.relative_to(ROOT)}")
    if digest(ROOT / "policy/passkey.wasm") != POLICY_SHA256:
        parser.error("SPK3 policy artifact changed; this wallet release must preserve existing policy identity")

    env = os.environ.copy()
    env.update(CARGO_INCREMENTAL="0", RUSTC=tools["rustc"], CARGO_NET_OFFLINE="true")
    env.pop("CARGO_ENCODED_RUSTFLAGS", None)
    target_root = Path(env.get("CARGO_TARGET_DIR", ROOT / "target"))
    if not target_root.is_absolute():
        target_root = ROOT / target_root
    target_root.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="passkey-build-", dir=target_root) as temporary:
        temporary = Path(temporary)
        policy_env = env.copy()
        policy_env["RUSTFLAGS"] = "-C link-arg=-zstack-size=65536 -C link-arg=--initial-memory=4194304 -C link-arg=--max-memory=4194304"
        policy_target = target_root / "policy"
        run([tools["cargo"], "build", "--manifest-path", "policy/Cargo.toml", "--locked", "--offline", "--release", "--target", "wasm32-unknown-unknown", "--target-dir", str(policy_target)], env=policy_env)
        policy = policy_target / "wasm32-unknown-unknown/release/sapio_passkey_predicate.wasm"
        if policy.stat().st_size > 65536 or digest(policy) != POLICY_SHA256:
            raise SystemExit("rebuilt SPK3 policy differs from the pinned funded policy; refusing to publish")

        cargo_home = Path(env.get("CARGO_HOME", Path.home() / ".cargo")).resolve()
        env.pop("RUSTFLAGS", None)
        env["CARGO_ENCODED_RUSTFLAGS"] = "\x1f".join([
            f"--remap-path-prefix={cargo_home}=/cargo",
            f"--remap-path-prefix={ROOT}=/sapio_passkey",
            "-Clink-arg=-zstack-size=262144",
            "-Clink-arg=--initial-memory=33554432",
            "-Clink-arg=--max-memory=67108864",
        ])
        env["CC_wasm32_unknown_unknown"] = tools["clang"]
        env["AR_wasm32_unknown_unknown"] = tools["llvm-ar"]
        resource = subprocess.check_output([tools["clang"], "-print-resource-dir"], text=True).strip()
        env["CFLAGS_wasm32_unknown_unknown"] = f"-ffreestanding -nostdlibinc -resource-dir={resource}"
        run([tools["cargo"], "build", "--locked", "--offline", "--release", "--target", "wasm32-unknown-unknown", "--target-dir", str(target_root), "-p", "sapio-passkey-wallet"], env=env)
        bindings = temporary / "pkg"
        run([tools["wasm-bindgen"], "--target", "web", "--out-dir", str(bindings), "--out-name", "sapio_passkey_wallet", str(target_root / "wasm32-unknown-unknown/release/sapio_passkey_wallet.wasm")])
        destination = ROOT / "web/pkg"
        manifest = {name: {"bytes": (bindings / name).stat().st_size, "sha256": digest(bindings / name)} for name in OUTPUTS}
        manifest["policy/passkey.wasm"] = {"bytes": policy.stat().st_size, "sha256": POLICY_SHA256}
        encoded = json.dumps(manifest, sort_keys=True, indent=2) + "\n"
        if args.check:
            for name in OUTPUTS:
                if not (destination / name).is_file() or (destination / name).read_bytes() != (bindings / name).read_bytes():
                    raise SystemExit(f"browser artifact differs or is missing: web/pkg/{name}")
            if (destination / "artifacts.json").read_text() != encoded:
                raise SystemExit("browser artifact manifest differs")
            print("SPK3 and browser artifacts reproduced byte-for-byte.")
        else:
            destination.mkdir(parents=True, exist_ok=True)
            for name in OUTPUTS:
                shutil.copyfile(bindings / name, destination / name)
            (destination / "artifacts.json").write_text(encoded)
            print(encoded, end="")


if __name__ == "__main__":
    main()
