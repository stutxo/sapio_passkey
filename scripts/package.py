#!/usr/bin/env python3
"""Package a self-contained static GitHub Pages wallet after scripts/build.py.

Production:
  python3 scripts/package.py --api-url https://api.your-domain --out dist

Local regtest (separate frontend/API ports exercise real CORS):
  python3 scripts/package.py --api-url http://localhost:8081 --allow-local-dev \
    --identity local-identity.json --identity-sha256 PRINTED_SHA256 --out dist

Serve dist with a static HTTP server; the gateway is a separate process. The API
URL must be the actual gateway origin, not an Esplora endpoint or raw signer TCP
address. This command does not deploy anything, fetch an identity or contact an
API. Choose the final frontend hostname before creating/funding a wallet.
"""
import argparse
import hashlib
import html
import ipaddress
import json
from pathlib import Path
import shutil
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parent.parent
PRESET_SHA256 = "2014810c930b4804bd1d52fae2b602578a9e5cccc29cb666f064356756154a1e"
POLICY_SHA256 = "eaef7663d2c61d8bc43ad456baa583dcfa4a8ab95e26a18605783831f64a462b"
ASSETS = ("app.js", "index.html", "style.css", "wallet.js")
BINDINGS = ("sapio_passkey_wallet.js", "sapio_passkey_wallet_bg.wasm")


def api_origin(value, development):
    parsed = urlsplit(value)
    if not parsed.hostname or parsed.username is not None or parsed.password is not None or parsed.path or parsed.query or parsed.fragment:
        raise ValueError("API URL must contain only scheme and authority, with no trailing slash")
    if value != value.lower() or any(c.isspace() for c in value):
        raise ValueError("API URL must be canonical lowercase ASCII")
    value.encode("ascii")
    if parsed.scheme != "https":
        if not (development and parsed.scheme == "http" and parsed.hostname in ("localhost", "127.0.0.1")):
            raise ValueError("API URL requires HTTPS except explicit localhost development")
    if parsed.port == 0 or parsed.port == (443 if parsed.scheme == "https" else 80):
        raise ValueError("omit the default port and never use port zero")
    if parsed.hostname not in ("localhost", "127.0.0.1"):
        try:
            ipaddress.ip_address(parsed.hostname)
        except ValueError:
            labels = parsed.hostname.split(".")
            if len(labels) < 2 or any(not label or len(label) > 63 or label.startswith("-") or label.endswith("-") or not all(c.isascii() and (c.isalnum() or c == "-") for c in label) for label in labels):
                raise ValueError("invalid API hostname")
    authority = parsed.hostname
    if ":" in authority:
        authority = f"[{authority}]"
    if parsed.port is not None:
        authority += f":{parsed.port}"
    if value != f"{parsed.scheme}://{authority}":
        raise ValueError("API URL must be canonical")
    return value


def identity_file(path, expected, development):
    if not expected or len(expected) != 64 or any(c not in "0123456789abcdef" for c in expected):
        raise ValueError("identity SHA-256 must be 64 lowercase hexadecimal characters")
    data = path.read_bytes()
    if len(data) > 1_000_000 or hashlib.sha256(data).hexdigest() != expected:
        raise ValueError("identity file does not match its independently pinned digest")
    identity = json.loads(data)
    if not isinstance(identity, dict) or identity.get("protocol") != "sapio-tee/program-oracle/1":
        raise ValueError("unsupported public signer identity")
    profile = identity.get("signing", {})
    if not isinstance(profile, dict) or profile.get("protocol") != "SignProgramV1":
        raise ValueError("signer does not advertise SignProgramV1")
    if identity.get("mode") == "nitro" and isinstance(identity.get("settings"), dict) and identity["settings"].get("network") == "signet":
        chain = "mutinynet"
    elif development and identity.get("mode") == "local-dev" and identity.get("settings") is None:
        chain = "regtest"
    else:
        raise ValueError("only Nitro signet or explicitly enabled local-dev regtest is supported")
    return identity, chain


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--api-url", required=True, help="canonical HTTPS gateway origin; never inferred or fetched")
    parser.add_argument("--out", type=Path, default=ROOT / "dist", help="new output directory (existing directories are never overwritten)")
    parser.add_argument("--identity", type=Path, help="independently verified public identity; defaults to the recorded Mutinynet preset")
    parser.add_argument("--identity-sha256", help="mandatory trusted digest when supplying a custom identity")
    parser.add_argument("--allow-local-dev", action="store_true", help="explicitly permit localhost HTTP and a local-dev regtest identity")
    args = parser.parse_args()
    try:
        api = api_origin(args.api_url, args.allow_local_dev)
        source = args.identity or ROOT / "config/mutinynet-identity.json"
        expected = args.identity_sha256 if args.identity else PRESET_SHA256
        identity, chain = identity_file(source, expected, args.allow_local_dev)
        if hashlib.sha256((ROOT / "policy/passkey.wasm").read_bytes()).hexdigest() != POLICY_SHA256:
            raise ValueError("SPK3 policy artifact has changed")
        for name in ASSETS:
            if not (ROOT / "web" / name).is_file():
                raise ValueError(f"missing frontend asset: {name}")
        build_manifest = json.loads((ROOT / "web/pkg/artifacts.json").read_text())
        for name in BINDINGS:
            data = (ROOT / "web/pkg" / name).read_bytes()
            if hashlib.sha256(data).hexdigest() != build_manifest[name]["sha256"] or len(data) != build_manifest[name]["bytes"]:
                raise ValueError(f"built artifact mismatch: {name}; run scripts/build.py")
        if build_manifest["policy/passkey.wasm"]["sha256"] != POLICY_SHA256:
            raise ValueError("browser build used another policy")
    except (OSError, ValueError, KeyError, TypeError) as error:
        parser.error(str(error))

    args.out.mkdir(parents=True, exist_ok=False)
    (args.out / "pkg").mkdir()
    for name in ASSETS:
        shutil.copyfile(ROOT / "web" / name, args.out / name)
    for name in BINDINGS:
        shutil.copyfile(ROOT / "web/pkg" / name, args.out / "pkg" / name)
    shutil.copyfile(ROOT / "policy/passkey.wasm", args.out / "passkey.wasm")
    shutil.copyfile(ROOT / "LICENSE", args.out / "LICENSE")
    config = {"version": 1, "identity": identity, "api_url": api, "chain": chain, "allow_local_dev": args.allow_local_dev}
    (args.out / "wallet-config.json").write_text(json.dumps(config, sort_keys=True, indent=2) + "\n")
    policy = f"default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self'; connect-src 'self' {api}; img-src 'self' data:; base-uri 'none'; form-action 'none'; object-src 'none'"
    index = (args.out / "index.html").read_text()
    if index.count("<head>") != 1:
        raise SystemExit("frontend must contain exactly one head element")
    index = index.replace("<head>", "<head>\n  <meta http-equiv=\"Content-Security-Policy\" content=\"" + html.escape(policy, quote=True) + "\">\n  <meta name=\"referrer\" content=\"no-referrer\">", 1)
    (args.out / "index.html").write_text(index)
    (args.out / ".nojekyll").write_text("")
    files = {}
    for path in sorted(args.out.rglob("*")):
        if path.is_file():
            data = path.read_bytes()
            files[str(path.relative_to(args.out))] = {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}
    manifest = {"version": 1, "chain": chain, "api_url": api, "files": files}
    (args.out / "bundle-manifest.json").write_text(json.dumps(manifest, sort_keys=True, indent=2) + "\n")
    print(f"Packaged {chain} wallet at {args.out}; API {api}. No deployment or network request performed.")


if __name__ == "__main__":
    main()
