#!/usr/bin/env python3
"""External HTTPS gateway for a static Pages passkey wallet (Python 3.11+).

POST /api/sign forwards the unchanged ProgramOracle wire envelope.
/esplora exposes only fixed-destination native Esplora routes, never a URL proxy.
No static files, cookies, redirects, compression, connection reuse or retries.
"""

import argparse
import asyncio
from http import HTTPStatus
import ipaddress
import json
import re
import socket
import ssl
import struct
from urllib.parse import urlsplit


MAX_MESSAGE = 1024 * 1024
MAX_HEADERS = 16 * 1024
MAX_CONNECTIONS = 4
TIMEOUT = 30
MUTINYNET_ESPLORA = "https://mutinynet.com/api"
TXID = r"[0-9a-f]{64}"
NUMBER = r"(?:0|[1-9][0-9]{0,9})"
ADDRESS = r"(?:tb1|bcrt1)[ac-hj-np-z02-9]{6,86}"
CHAIN_GET_ROUTE = re.compile(
    rf"/(?:blocks(?:/{NUMBER}|/tip/(?:height|hash))?|block-height/{NUMBER}|"
    rf"block/{TXID}/(?:status|header)|"
    rf"scripthash/{TXID}/txs(?:/chain/{TXID}|/mempool)?|"
    rf"address/{ADDRESS}/(?:utxo|txs(?:/chain/{TXID})?)|"
    rf"tx/{TXID}(?:/hex|/status|/outspends|/outspend/{NUMBER})?|fee-estimates)"
)
TOKEN = r"[!#$%&'*+.^_`|~0-9A-Za-z-]+"
SECURITY_HEADERS = (
    "Cache-Control: no-store\r\n"
    "X-Content-Type-Options: nosniff\r\n"
    "Referrer-Policy: no-referrer\r\n"
    "Content-Security-Policy: default-src 'none'; frame-ancestors 'none'\r\n"
)


class HTTPError(Exception):
    def __init__(self, status):
        self.status = status


def require(condition, message):
    if not condition:
        raise ValueError(message)


def unique_object(pairs):
    value = {}
    for key, item in pairs:
        require(key not in value, "duplicate JSON field")
        value[key] = item
    return value


def invalid_constant(_value):
    raise ValueError("non-finite JSON value")


def json_value(data):
    # Validate, but do not reserialize the oracle's UTF-8 envelope.
    try:
        return json.loads(data.decode("utf-8"), object_pairs_hook=unique_object,
                          parse_constant=invalid_constant)
    except (UnicodeError, RecursionError) as error:
        raise ValueError("invalid JSON encoding or nesting") from error


def byte_array(value, maximum):
    return (isinstance(value, list) and len(value) <= maximum
            and all(type(item) is int and 0 <= item <= 255 for item in value))


def framed_psbt(value):
    # Wire framing only; the browser and enclave validate wallet semantics.
    return (byte_array(value, MAX_MESSAGE) and len(value) > 4
            and int.from_bytes(bytes(value[:4]), "big") == len(value) - 4)


def validate_request(data):
    value = json_value(data)
    require(isinstance(value, dict) and set(value) == {"SignProgramV1"},
            "unsupported oracle envelope")
    request = value["SignProgramV1"]
    require(isinstance(request, dict) and set(request) == {
        "instance", "input_index", "witness", "path", "psbt",
    }, "unsupported signing request")
    instance = request["instance"]
    require(isinstance(instance, dict) and set(instance) == {
        "evaluator", "program", "parameters",
    }, "unsupported instance envelope")
    require(isinstance(instance["evaluator"], str)
            and re.fullmatch(TXID, instance["evaluator"]) is not None,
            "invalid evaluator identifier")
    require(byte_array(instance["program"], 65_536)
            and byte_array(instance["parameters"], 65_536), "invalid instance bytes")
    require(type(request["input_index"]) is int and 0 <= request["input_index"] <= 0xFFFFFFFF,
            "invalid input index")
    require(byte_array(request["witness"], 65_536), "invalid witness bytes")
    require(request["path"] == "KeyPath", "unsupported spend path")
    require(framed_psbt(request["psbt"]), "invalid PSBT wire frame")


def validate_response(data):
    value = json_value(data)
    require(isinstance(value, dict) and len(value) == 1, "invalid oracle response")
    if "SignedV1" in value:
        require(framed_psbt(value["SignedV1"]), "invalid signed wire frame")
    else:
        require(set(value) == {"RejectedV1"} and isinstance(value["RejectedV1"], str),
                "unsupported oracle response")


def validate_origin(origin, allow_local_dev, *, allow_ip=False):
    require(isinstance(origin, str) and origin == origin.lower()
            and not any(ord(char) <= 32 or ord(char) >= 127 for char in origin),
            "origin must be canonical ASCII")
    parsed = urlsplit(origin)
    require(parsed.hostname is not None and parsed.username is None
            and parsed.password is None and not parsed.path and not parsed.query
            and not parsed.fragment and "?" not in origin and "#" not in origin,
            "origin must contain only scheme and authority, without a trailing slash")
    if allow_local_dev:
        require(parsed.scheme == "http" and parsed.hostname in ("localhost", "127.0.0.1"),
                "development requires an explicit http://localhost or http://127.0.0.1 origin")
    else:
        require(parsed.scheme == "https", "production requires an HTTPS origin")
        try:
            address = ipaddress.ip_address(parsed.hostname)
        except ValueError:
            require(re.fullmatch(r"(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
                                 r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", parsed.hostname)
                    and not parsed.hostname.endswith(".localhost"),
                    "production requires a DNS hostname or an API IP address")
        else:
            require(allow_ip, "the frontend origin requires a DNS hostname, not an IP")
            require(parsed.hostname == str(address), "API IP address must be canonical")
    expected_authority = f"[{parsed.hostname}]" if ":" in parsed.hostname else parsed.hostname
    if parsed.port is not None:
        require(1 <= parsed.port <= 65535 and parsed.port != (80 if allow_local_dev else 443),
                "invalid origin port; omit the default port")
        expected_authority += f":{parsed.port}"
    require(parsed.netloc == expected_authority, "origin authority must be canonical")
    return parsed.netloc


def validate_esplora_url(url, chain, allow_local_dev):
    require(chain in ("mutinynet", "regtest"), "unsupported chain")
    if chain == "mutinynet":
        require(url is None or url == MUTINYNET_ESPLORA,
                "Mutinynet Esplora is fixed to https://mutinynet.com/api")
        return urlsplit(MUTINYNET_ESPLORA)
    require(allow_local_dev and isinstance(url, str) and url,
            "regtest requires --allow-local-dev and an explicit --esplora-url")
    require(re.fullmatch(r"http://(?:localhost|127\.0\.0\.1|\[::1\])"
                         r"(?::[1-9][0-9]{0,4})?(?:/[a-zA-Z0-9_-]+)*", url),
            "regtest Esplora must be a canonical loopback HTTP URL")
    parsed = urlsplit(url)
    require(parsed.port != 0, "invalid Esplora port")
    return parsed


def parse_headers(lines):
    headers = {}
    for line in lines:
        key, value = line.split(":", 1)
        require(re.fullmatch(TOKEN, key)
                and all(32 <= ord(char) < 127 or char == "\t" for char in value),
                "invalid HTTP header")
        key = key.lower()
        require(key not in headers, "duplicate HTTP header")
        headers[key] = value.strip(" \t")
    return headers


async def esplora_exchange(endpoint, path, body=None):
    # A fresh direct connection: no proxy environment, redirects, cookies or retries.
    context = ssl.create_default_context() if endpoint.scheme == "https" else None
    if context is not None:
        context.minimum_version = ssl.TLSVersion.TLSv1_2
    host = endpoint.hostname
    connect_host = "127.0.0.1" if host == "localhost" else host
    reader, writer = await asyncio.open_connection(
        connect_host, endpoint.port or (443 if context else 80),
        ssl=context, server_hostname=host if context else None, limit=MAX_HEADERS)
    try:
        method = "GET" if body is None else "POST"
        header = (f"{method} {endpoint.path}{path} HTTP/1.1\r\nHost: {endpoint.netloc}\r\n"
                  "Connection: close\r\nAccept-Encoding: identity\r\nAccept: */*\r\n")
        if body is not None:
            header += f"Content-Type: text/plain\r\nContent-Length: {len(body)}\r\n"
        writer.write((header + "\r\n").encode("ascii"))
        if body is not None:
            writer.write(body)
        await writer.drain()
        raw = await reader.readuntil(b"\r\n\r\n")
        require(len(raw) <= MAX_HEADERS, "oversized Esplora headers")
        lines = raw[:-4].decode("ascii").split("\r\n")
        require(re.fullmatch(r"HTTP/1\.[01] [0-9]{3}(?: [\x20-\x7e]*)?", lines[0]),
                "invalid Esplora status")
        status = int(lines[0].split(" ")[1])
        require(200 <= status < 300 or 400 <= status < 600,
                "Esplora redirects and informational responses are forbidden")
        headers = parse_headers(lines[1:])
        require(headers.get("content-encoding", "identity").lower() == "identity",
                "compressed Esplora response")
        if "transfer-encoding" in headers:
            require(headers["transfer-encoding"].lower() == "chunked"
                    and "content-length" not in headers, "ambiguous Esplora framing")
            data = bytearray()
            framing_size = len(raw)
            while True:
                line = await reader.readuntil(b"\r\n")
                framing_size += len(line)
                require(framing_size <= MAX_HEADERS and
                        re.fullmatch(rb"[0-9a-fA-F]{1,8}\r\n", line), "invalid Esplora chunk")
                size = int(line[:-2], 16)
                if size == 0:
                    require(await reader.readexactly(2) == b"\r\n", "unexpected Esplora trailers")
                    break
                require(len(data) + size <= MAX_MESSAGE, "oversized Esplora response")
                data.extend(await reader.readexactly(size))
                require(await reader.readexactly(2) == b"\r\n", "invalid Esplora chunk ending")
            data = bytes(data)
        elif "content-length" in headers:
            length = headers["content-length"]
            require(re.fullmatch(r"[0-9]{1,7}", length) and int(length) <= MAX_MESSAGE,
                    "oversized Esplora response")
            data = await reader.readexactly(int(length))
        else:
            data = bytearray()
            while True:
                chunk = await reader.read(min(65_536, MAX_MESSAGE + 1 - len(data)))
                if not chunk:
                    break
                data.extend(chunk)
                require(len(data) <= MAX_MESSAGE, "oversized Esplora response")
            data = bytes(data)
        # Preserve native status (notably 404), bytes and pagination semantics.
        # The BDK/browser consumer validates chain data; this is not an SPV oracle.
        return status, data
    finally:
        writer.close()
        writer.transport.abort()


async def oracle_exchange(body, host, port):
    family = socket.AF_INET6 if ipaddress.ip_address(host).version == 6 else socket.AF_INET
    reader, writer = await asyncio.open_connection(host, port, family=family)
    try:
        writer.write(struct.pack(">I", len(body)))
        writer.write(body)
        await writer.drain()
        size = struct.unpack(">I", await reader.readexactly(4))[0]
        require(0 < size <= MAX_MESSAGE, "invalid oracle frame size")
        response = await reader.readexactly(size)
        validate_response(response)
        return response
    finally:
        writer.close()
        writer.transport.abort()


class Relay:
    def __init__(self, api_url, origin, upstream_host="127.0.0.1", upstream_port=8367,
                 mode="tls", chain="mutinynet", esplora_url=None):
        require(mode in ("tls", "https-proxy", "local-dev"), "invalid gateway mode")
        self.mode = mode
        self.origin = origin
        self.host = validate_origin(api_url, mode == "local-dev", allow_ip=True)
        validate_origin(origin, mode == "local-dev")
        self.upstream_host = str(ipaddress.ip_address(upstream_host))
        require(type(upstream_port) is int and 1 <= upstream_port <= 65535,
                "invalid upstream port")
        self.upstream_port = upstream_port
        self.chain = chain
        self.esplora = validate_esplora_url(esplora_url, chain, mode == "local-dev")
        self.active = 0

    def response(self, status, body=None, content_type="application/json", preflight=None):
        try:
            reason = HTTPStatus(status).phrase
        except ValueError:
            reason = "Upstream Response"
        if body is None:
            body = json.dumps({"error": reason}, separators=(",", ":")).encode()
        # A fixed ACAO is safe even for pre-header failures or a rejected Origin:
        # only the configured frontend can read errors. Never echo request data.
        header = (f"HTTP/1.1 {status} {reason}\r\nContent-Type: {content_type}\r\n"
                  f"Content-Length: {len(body)}\r\nConnection: close\r\n"
                  f"Access-Control-Allow-Origin: {self.origin}\r\n"
                  "Vary: Origin, Access-Control-Request-Method, Access-Control-Request-Headers\r\n"
                  + SECURITY_HEADERS)
        if preflight is not None:
            header += f"Access-Control-Allow-Methods: {preflight}\r\n"
            if preflight == "POST":
                header += "Access-Control-Allow-Headers: Content-Type\r\n"
        return (header + "\r\n").encode("ascii") + body

    async def respond(self, writer, status, body=None, content_type="application/json",
                      preflight=None):
        writer.write(self.response(status, body, content_type, preflight))
        await writer.drain()

    def route(self, path):
        if path == "/api/sign":
            return "POST", None, "application/json"
        if path == "/esplora/tx":
            return "POST", "/tx", "text/plain"
        relative = path.removeprefix("/esplora")
        if not path.startswith("/esplora/") or CHAIN_GET_ROUTE.fullmatch(relative) is None:
            raise HTTPError(404)
        parts = relative.split("/")
        if parts[1] == "address":
            prefix = "tb1" if self.chain == "mutinynet" else "bcrt1"
            if not parts[2].startswith(prefix) or len(parts[2]) > 90:
                raise HTTPError(400)
        for part in parts[2:]:
            if len(part) <= 10 and part.isdigit() and int(part) > 0xFFFFFFFF:
                raise HTTPError(400)
        text = (relative.startswith("/blocks/tip/") or parts[1] == "block-height"
                or parts[-1] in ("header", "hex"))
        return "GET", relative, "text/plain" if text else "application/json"

    async def request(self, reader, writer):
        try:
            raw = await reader.readuntil(b"\r\n\r\n")
        except asyncio.LimitOverrunError as error:
            raise HTTPError(431) from error
        if len(raw) > MAX_HEADERS:
            raise HTTPError(431)
        try:
            lines = raw[:-4].decode("ascii").split("\r\n")
            method, path, version = lines[0].split(" ")
            require(version == "HTTP/1.1" and path.startswith("/"), "invalid request line")
            headers = parse_headers(lines[1:])
        except ValueError as error:
            raise HTTPError(400) from error
        if headers.get("host") != self.host or headers.get("origin") != self.origin:
            raise HTTPError(403)
        if any(key in headers for key in ("authorization", "proxy-authorization", "cookie")):
            raise HTTPError(403)
        if self.mode == "https-proxy":
            peer = writer.get_extra_info("peername")
            if (not peer or not ipaddress.ip_address(peer[0]).is_loopback
                    or headers.get("x-forwarded-proto") != "https"):
                raise HTTPError(403)
        elif self.mode == "tls" and writer.get_extra_info("ssl_object") is None:
            raise HTTPError(403)
        if any(key in headers for key in ("transfer-encoding", "content-encoding", "expect", "upgrade")):
            raise HTTPError(400)
        allowed_method, upstream_path, content_type = self.route(path)
        if method == "OPTIONS":
            if headers.get("content-length", "0") != "0" or "content-type" in headers:
                raise HTTPError(400)
            if headers.get("access-control-request-method") != allowed_method:
                raise HTTPError(405)
            requested = headers.get("access-control-request-headers", "")
            requested_headers = [item.strip().lower() for item in requested.split(",")] if requested else []
            if (len(requested_headers) != len(set(requested_headers))
                    or set(requested_headers) != ({"content-type"} if allowed_method == "POST" else set())):
                raise HTTPError(403)
            if "access-control-request-private-network" in headers:
                raise HTTPError(403)
            return 204, b"", "application/json", allowed_method
        if any(key.startswith("access-control-request-") for key in headers):
            raise HTTPError(400)
        if method != allowed_method:
            raise HTTPError(405)
        body = None
        if method == "GET":
            if headers.get("content-length", "0") != "0":
                raise HTTPError(400)
        else:
            if headers.get("content-type", "").lower() not in (
                    content_type, content_type + "; charset=utf-8"):
                raise HTTPError(415)
            if "content-length" not in headers:
                raise HTTPError(411)
            length = headers["content-length"]
            if re.fullmatch(r"[1-9][0-9]{0,6}", length) is None:
                raise HTTPError(413 if length.isdigit() and len(length) > 6 else 400)
            if int(length) > MAX_MESSAGE:
                raise HTTPError(413)
            body = await reader.readexactly(int(length))
            try:
                if upstream_path is None:
                    validate_request(body)
                else:
                    require(len(body) % 2 == 0 and re.fullmatch(rb"[0-9a-fA-F]+", body),
                            "expected raw transaction hex")
            except ValueError as error:
                raise HTTPError(400) from error
        try:
            if upstream_path is None:
                response = await oracle_exchange(body, self.upstream_host, self.upstream_port)
                status = 200
            else:
                status, response = await esplora_exchange(self.esplora, upstream_path, body)
                if status >= 400:
                    content_type = "text/plain"
        except (OSError, ValueError, asyncio.IncompleteReadError,
                asyncio.LimitOverrunError) as error:
            raise HTTPError(502) from error
        return status, response, content_type, None

    async def connection(self, client, tls_context):
        writer = None
        response_started = False
        deadline = asyncio.get_running_loop().time() + TIMEOUT

        async def exchange():
            nonlocal writer, response_started
            loop = asyncio.get_running_loop()
            reader = asyncio.StreamReader(limit=MAX_HEADERS)
            protocol = asyncio.StreamReaderProtocol(reader)
            transport, _ = await loop.connect_accepted_socket(
                lambda: protocol, client, ssl=tls_context,
                ssl_handshake_timeout=TIMEOUT if tls_context is not None else None)
            writer = asyncio.StreamWriter(transport, protocol, reader, loop)
            response = await self.request(reader, writer)
            response_started = True
            await self.respond(writer, *response)

        try:
            try:
                # Admission already includes this socket, even before TLS Hello.
                # The single deadline covers TLS, headers, body and both peers.
                await asyncio.wait_for(exchange(), TIMEOUT)
            except asyncio.TimeoutError:
                if writer is not None and not response_started:
                    writer.write(self.response(504))
            except HTTPError as error:
                remaining = deadline - asyncio.get_running_loop().time()
                if writer is not None and remaining > 0:
                    await asyncio.wait_for(self.respond(writer, error.status), remaining)
            except asyncio.IncompleteReadError:
                remaining = deadline - asyncio.get_running_loop().time()
                if writer is not None and remaining > 0:
                    await asyncio.wait_for(self.respond(writer, 400), remaining)
        except (OSError, ValueError, asyncio.TimeoutError):
            pass
        finally:
            try:
                if writer is not None:
                    writer.close()
                    remaining = deadline - asyncio.get_running_loop().time()
                    try:
                        if remaining > 0:
                            await asyncio.wait_for(writer.wait_closed(), remaining)
                    except (OSError, asyncio.TimeoutError):
                        pass
            finally:
                if writer is not None:
                    writer.transport.abort()
                client.close()
                self.active -= 1


def open_listener(address, port):
    numeric = ipaddress.ip_address(address)
    listener = socket.socket(socket.AF_INET6 if numeric.version == 6 else socket.AF_INET)
    try:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.setblocking(False)
        listener.bind((str(numeric), port))
        listener.listen(MAX_CONNECTIONS)
        return listener
    except BaseException:
        listener.close()
        raise


async def accept_connections(listener, relay, tls_context=None):
    clients = set()
    loop = asyncio.get_running_loop()
    try:
        while True:
            client, _address = await loop.sock_accept(listener)
            if relay.active >= MAX_CONNECTIONS:
                # No queue or TLS handshake for excess clients. Plaintext peers
                # can receive a fixed CORS 503; TLS peers are closed immediately.
                if tls_context is None:
                    try:
                        client.send(relay.response(503))
                    except OSError:
                        pass
                client.close()
                continue
            relay.active += 1
            task = asyncio.create_task(relay.connection(client, tls_context))
            clients.add(task)
            task.add_done_callback(clients.discard)
    finally:
        listener.close()
        for task in clients:
            task.cancel()
        await asyncio.gather(*clients, return_exceptions=True)


def parser():
    value = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Run from the repository root, with an existing signer and Esplora backend:
  Direct HTTPS (provide your own certificates):
    python3 gateway/server.py --api-url https://api.example.com:8443 \\
      --origin https://owner.github.io --listen 0.0.0.0 --port 8443 \\
      --tls-cert /path/fullchain.pem --tls-key /path/privkey.pem
  Existing HTTPS reverse proxy (preserve Host; set X-Forwarded-Proto: https):
    python3 gateway/server.py --api-url https://api.example.com \\
      --origin https://owner.github.io --https-proxy --listen 127.0.0.1 --port 8081
  Explicit localhost development (frontend served separately on port 8000):
    python3 gateway/server.py --api-url http://localhost:8081 \\
      --origin http://localhost:8000 --allow-local-dev --chain regtest \\
      --esplora-url http://127.0.0.1:3002

The Pages wallet-config.json api_url must equal --api-url. --origin is an origin,
not a Pages path (https://owner.github.io, without /sapio_passkey/ or trailing /).
Only that exact Origin is accepted, including GET; no credentialed CORS.
GET /esplora/{blocks[/height],blocks/tip/{height,hash},block-height/height,
block/hash/{status,header},scripthash/hash/txs[/chain/txid|/mempool],
address/bech32/{utxo,txs[/chain/txid]},tx/txid[/hex|/status|/outspends|/outspend/vout],
fee-estimates}; POST /esplora/tx takes text/plain raw hex; POST /api/sign takes JSON.
All requests/responses: 1 MiB body, 16 KiB headers, 4 admitted sockets,
30 seconds total including TLS. Broadcasts and signing are never retried.
No installation, static file serving, health/setup API, or deployment actions.
""")
    value.add_argument("--api-url", required=True, help="exact public API origin (DNS name or certified IP); HTTPS except explicit localhost development")
    value.add_argument("--origin", required=True, help="exact allowed frontend origin; HTTPS except explicit localhost development")
    value.add_argument("--listen", default="127.0.0.1", help="numeric listen IP; proxy and development require loopback")
    value.add_argument("--port", type=int, default=8081, help="listen port (default: 8081)")
    value.add_argument("--tls-cert", help="PEM certificate/full chain for direct HTTPS; requires --tls-key")
    value.add_argument("--tls-key", help="PEM private TLS key for direct HTTPS; requires --tls-cert")
    value.add_argument("--https-proxy", action="store_true", help="explicit loopback-only HTTP behind HTTPS proxy; requires exact X-Forwarded-Proto: https")
    value.add_argument("--allow-local-dev", action="store_true", help="explicit HTTP localhost frontend/API development; never production")
    value.add_argument("--upstream-host", default="127.0.0.1", help="fixed numeric ProgramOracle IP (default: 127.0.0.1); no DNS or URL")
    value.add_argument("--upstream-port", type=int, default=8367, help="fixed ProgramOracle TCP port (default: 8367)")
    value.add_argument("--chain", choices=("mutinynet", "regtest"), default="mutinynet", help="selected chain (default: mutinynet); regtest requires --allow-local-dev")
    value.add_argument("--esplora-url", help="Mutinynet is fixed to https://mutinynet.com/api; regtest requires explicit loopback HTTP URL, optionally with a fixed path")
    return value


def configure(args):
    direct = args.tls_cert is not None or args.tls_key is not None
    require(bool(args.tls_cert) == bool(args.tls_key), "--tls-cert and --tls-key are required together")
    require(sum((direct, args.https_proxy, args.allow_local_dev)) == 1,
            "choose exactly one: --tls-cert/--tls-key, --https-proxy, or --allow-local-dev")
    address = ipaddress.ip_address(args.listen)
    require(direct or address.is_loopback, "proxy and development listeners must be loopback")
    require(1 <= args.port <= 65535, "invalid listening port")
    mode = "tls" if direct else "https-proxy" if args.https_proxy else "local-dev"
    relay = Relay(args.api_url, args.origin, args.upstream_host, args.upstream_port,
                  mode, args.chain, args.esplora_url)
    context = None
    if direct:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(args.tls_cert, args.tls_key)
    return relay, context


async def serve(args):
    relay, context = configure(args)
    listener = open_listener(args.listen, args.port)
    print(f"wallet gateway ready on {args.listen}:{args.port} ({relay.mode}); "
          f"API {args.api_url}; frontend {args.origin}; chain {args.chain}", flush=True)
    await accept_connections(listener, relay, context)


def main():
    arguments = parser()
    args = arguments.parse_args()
    try:
        asyncio.run(serve(args))
    except KeyboardInterrupt:
        pass
    except (OSError, ValueError) as error:
        arguments.exit(1, f"wallet gateway failed: {error}\n")


if __name__ == "__main__":
    main()
