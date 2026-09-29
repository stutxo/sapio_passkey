"""Gateway transport regressions using only isolated loopback fixtures.

Direct TLS coverage needs the openssl executable to create a temporary test
certificate; no live endpoint, package download or host installation is used.
"""

import asyncio
import json
from pathlib import Path
import shutil
import sqlite3
import ssl
import struct
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import server


PUBLIC_KEY = "036b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"
OTHER_PUBLIC_KEY = "02" + PUBLIC_KEY[2:]


def passkey(credential_id="aabb"):
    return {"credential_id": credential_id, "public_key": PUBLIC_KEY}


class PasskeyStoreTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = str(Path(self.directory.name) / "passkeys.sqlite3")

    def open_store(self):
        store = server.PasskeyStore(self.path)
        self.addCleanup(store.close)
        return store

    def test_persistent_immutable_registration_and_missing_lookup(self):
        store = self.open_store()
        self.assertEqual(store.register(passkey()), (201, passkey()))
        store.close()
        reopened = self.open_store()
        self.assertEqual(reopened.get("aabb"), passkey())
        self.assertEqual(reopened.register(passkey()), (200, passkey()))
        with self.assertRaises(server.HTTPError) as conflict:
            reopened.register(passkey() | {"public_key": OTHER_PUBLIC_KEY})
        self.assertEqual(conflict.exception.status, 409)
        self.assertEqual(reopened.get("aabb"), passkey())
        with self.assertRaises(server.HTTPError) as missing:
            reopened.get("bbcc")
        self.assertEqual(missing.exception.status, 404)

    def test_independent_connections_never_overwrite(self):
        first, second = self.open_store(), self.open_store()
        self.assertEqual(first.register(passkey())[0], 201)
        self.assertEqual(second.register(passkey())[0], 200)
        with self.assertRaises(server.HTTPError) as conflict:
            second.register(passkey() | {"public_key": OTHER_PUBLIC_KEY})
        self.assertEqual(conflict.exception.status, 409)
        self.assertEqual(first.get("aabb"), passkey())

    def test_malformed_disk_record_is_not_returned_or_replaced(self):
        store = self.open_store()
        with sqlite3.connect(self.path) as db:
            db.execute("INSERT INTO passkeys VALUES (?, ?)", ("aabb", "02" + "ff" * 32))
        for operation in (lambda: store.get("aabb"), lambda: store.register(passkey())):
            with self.assertRaises(server.HTTPError) as invalid:
                operation()
            self.assertEqual(invalid.exception.status, 503)
        with sqlite3.connect(self.path) as db:
            self.assertEqual(db.execute("SELECT public_key FROM passkeys").fetchone()[0],
                             "02" + "ff" * 32)

    def test_full_database_preserves_records_and_bounds_disk(self):
        with patch.object(server, "MAX_PASSKEY_PAGES", 8):
            store = self.open_store()
            first = passkey("00" * 1024)
            store.register(first)
            for number in range(1, 100):
                try:
                    store.register(passkey(number.to_bytes(1024, "big").hex()))
                except server.HTTPError as error:
                    self.assertEqual(error.status, 507)
                    break
            else:
                self.fail("bounded registry never filled")
            self.assertEqual(store.get(first["credential_id"]), first)
            self.assertEqual(store.register(first), (200, first))
            self.assertLessEqual(sum(path.stat().st_size for path in Path(self.directory.name).iterdir()),
                                 8 * server.PASSKEY_PAGE_SIZE * 4)
            store.close()
            self.assertEqual(self.open_store().get(first["credential_id"]), first)

    def test_locked_storage_fails_without_partial_registration(self):
        store = self.open_store()
        with sqlite3.connect(self.path) as lock:
            lock.execute("BEGIN IMMEDIATE")
            with self.assertRaises(server.HTTPError) as unavailable:
                store.register(passkey())
            self.assertEqual(unavailable.exception.status, 503)
        self.assertEqual(store.register(passkey()), (201, passkey()))

    def test_ephemeral_paths_are_rejected(self):
        for path in ("", ":memory:"):
            with self.subTest(path=path), self.assertRaises(ValueError):
                server.PasskeyStore(path)


def envelope():
    # Opaque bytes intentionally have no wallet/PSBT semantics. Those checks
    # belong to the enclave and browser, not the byte-preserving gateway.
    return {"SignProgramV1": {
        "instance": {"evaluator": "00" * 31 + "02", "program": [1], "parameters": []},
        "input_index": 0, "witness": [], "path": "KeyPath", "psbt": [0, 0, 0, 1, 255],
    }}


class TransportTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.received = []
        self.response = b' { "RejectedV1" : "fixture rejection" } \n'
        self.upstream_mode = "normal"
        self.peers = set()
        self.chain_requests = []
        self.chain_response = b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\n1"
        self.chain_silent = False

        async def esplora(reader, writer):
            self.peers.add(writer)
            try:
                head = await reader.readuntil(b"\r\n\r\n")
                lines = head.decode("ascii").split("\r\n")
                method, path, _version = lines[0].split(" ")
                headers = dict(line.split(": ", 1) for line in lines[1:] if line)
                body = await reader.readexactly(int(headers.get("Content-Length", "0")))
                self.chain_requests.append((method, path, headers, body))
                if self.chain_silent:
                    await reader.read()
                else:
                    writer.write(self.chain_response)
                    await writer.drain()
            except (ConnectionError, asyncio.IncompleteReadError):
                pass
            finally:
                writer.close()
                self.peers.discard(writer)

        async def oracle(reader, writer):
            self.peers.add(writer)
            try:
                size = struct.unpack(">I", await reader.readexactly(4))[0]
                self.received.append(await reader.readexactly(size))
                if self.upstream_mode == "oversized":
                    writer.write(struct.pack(">I", server.MAX_MESSAGE + 1))
                elif self.upstream_mode == "truncated":
                    writer.write(struct.pack(">I", 20) + b"{}")
                elif self.upstream_mode == "silent":
                    await reader.read()
                    return
                else:
                    writer.write(struct.pack(">I", len(self.response)) + self.response)
                await writer.drain()
            except (ConnectionError, asyncio.IncompleteReadError):
                pass
            finally:
                writer.close()
                self.peers.discard(writer)

        self.esplora = await asyncio.start_server(esplora, "127.0.0.1", 0)
        self.oracle = await asyncio.start_server(oracle, "127.0.0.1", 0)
        self.esplora_url = f"http://127.0.0.1:{self.esplora.sockets[0].getsockname()[1]}/api"
        self.directory = tempfile.TemporaryDirectory()
        self.passkey_db = str(Path(self.directory.name) / "passkeys.sqlite3")
        self.relay = server.Relay("http://localhost:8123", "http://localhost:8000",
                                  "127.0.0.1", self.oracle.sockets[0].getsockname()[1],
                                  "local-dev", "regtest", self.esplora_url,
                                  passkey_db=self.passkey_db)
        self.listener = server.open_listener("127.0.0.1", 0)
        self.port = self.listener.getsockname()[1]
        self.acceptor = asyncio.create_task(server.accept_connections(self.listener, self.relay))
        self.client_tls = None

    async def asyncTearDown(self):
        self.acceptor.cancel()
        await asyncio.gather(self.acceptor, return_exceptions=True)
        self.oracle.close()
        self.esplora.close()
        await self.esplora.wait_closed()
        await self.oracle.wait_closed()
        for writer in tuple(self.peers):
            writer.close()
        self.relay.close()
        self.directory.cleanup()

    def chain_reply(self, body, status=200, extra=b""):
        self.chain_response = (f"HTTP/1.1 {status} Fixture\r\nContent-Length: {len(body)}\r\n"
                               .encode() + extra + b"\r\n" + body)

    async def request(self, body=None, method="POST", path="/api/sign", headers=None):
        if body is None:
            body = json.dumps(envelope()).encode() if method == "POST" and path == "/api/sign" else b""
        values = {"Host": "localhost:8123", "Origin": "http://localhost:8000",
                  "Content-Length": str(len(body))}
        if method == "POST":
            values["Content-Type"] = ("application/json"
                                      if path in ("/api/sign", "/api/passkeys") else "text/plain")
        if headers:
            for key, value in headers.items():
                if value is None:
                    values.pop(key, None)
                else:
                    values[key] = value
        reader, writer = await asyncio.open_connection(
            "127.0.0.1", self.port, ssl=self.client_tls,
            server_hostname="127.0.0.1" if self.client_tls else None)
        try:
            header = f"{method} {path} HTTP/1.1\r\n" + "".join(
                f"{key}: {value}\r\n" for key, value in values.items()) + "\r\n"
            writer.write(header.encode() + body)
            await writer.drain()
            result = await asyncio.wait_for(reader.read(), 3)
            head, response = result.split(b"\r\n\r\n", 1)
            lines = head.decode("ascii").split("\r\n")
            returned_headers = dict(line.split(": ", 1) for line in lines[1:])
            self.assertEqual(int(returned_headers["Content-Length"]), len(response))
            return int(lines[0].split(" ")[1]), returned_headers, response
        finally:
            writer.close()
            await writer.wait_closed()

    def assert_cors(self, headers):
        self.assertEqual(headers["Access-Control-Allow-Origin"], self.relay.origin)
        self.assertIn("Origin", headers["Vary"].split(", "))
        self.assertNotIn("Access-Control-Allow-Credentials", headers)
        self.assertNotIn("Set-Cookie", headers)


    async def test_registry_roundtrip_idempotency_conflict_and_missing(self):
        body = json.dumps(passkey()).encode()
        for expected in (201, 200):
            status, headers, response = await self.request(body, path="/api/passkeys")
            self.assertEqual((status, json.loads(response)), (expected, passkey()))
            self.assert_cors(headers)
        conflict = json.dumps(passkey() | {"public_key": OTHER_PUBLIC_KEY}).encode()
        self.assertEqual((await self.request(conflict, path="/api/passkeys"))[0], 409)
        status, headers, response = await self.request(method="GET", path="/api/passkeys/aabb")
        self.assertEqual((status, json.loads(response)), (200, passkey()))
        self.assert_cors(headers)
        self.assertEqual((await self.request(method="GET", path="/api/passkeys/ccdd"))[0], 404)
        self.assertEqual(self.received, [])
        self.assertEqual(self.chain_requests, [])

    async def test_registry_rejects_malformed_and_oversized_registration(self):
        malformed = [
            {}, passkey() | {"extra": True}, passkey() | {"credential_id": ""},
            passkey("a"), passkey("AA"), passkey("aa" * 1025), passkey("../aa"),
            passkey() | {"credential_id": 123}, passkey() | {"public_key": PUBLIC_KEY.upper()},
            passkey() | {"public_key": "04" + PUBLIC_KEY[2:]},
            passkey() | {"public_key": "02" + "ff" * 32},
            passkey() | {"public_key": "02" + "00" * 31 + "01"},
            passkey() | {"public_key": None},
        ]
        bodies = [json.dumps(record).encode() for record in malformed]
        bodies += [b'{"credential_id":"aa","credential_id":"bb","public_key":null}',
                   b'{"credential_id":NaN}', b"\xff"]
        for body in bodies:
            with self.subTest(body=body[:100]):
                self.assertEqual((await self.request(body, path="/api/passkeys"))[0], 400)
        self.assertEqual((await self.request(b"{}", path="/api/passkeys",
                          headers={"Content-Length": str(server.MAX_PASSKEY_BODY + 1)}))[0], 413)
        maximum_record = passkey("ab" * 1024)
        status, _headers, response = await self.request(json.dumps(maximum_record).encode(),
                                                      path="/api/passkeys")
        self.assertEqual((status, json.loads(response)), (201, maximum_record))
        self.assertEqual((await self.request(method="GET", path="/api/passkeys/aabb"))[0], 404)

    async def test_registry_origin_and_route_boundaries(self):
        body = json.dumps(passkey()).encode()
        for path, method in (("/api/passkeys", "POST"), ("/api/passkeys/aabb", "GET")):
            for origin in (None, "null", "http://localhost:8000/", "https://evil.invalid"):
                status, headers, _response = await self.request(
                    body if method == "POST" else b"", method=method, path=path,
                    headers={"Origin": origin})
                self.assertEqual(status, 403)
                self.assert_cors(headers)
        self.assertEqual((await self.request(method="GET", path="/api/passkeys/aabb"))[0], 404)
        for path in ("/api/passkeys/", "/api/passkeys/AA", "/api/passkeys/a",
                     "/api/passkeys/aabb?x=y", "/api/passkeys/%61%61"):
            self.assertEqual((await self.request(method="GET", path=path))[0], 404)
        for method, path in (("GET", "/api/passkeys"), ("DELETE", "/api/passkeys/aabb"),
                             ("POST", "/api/passkeys/aabb"), ("PUT", "/api/passkeys")):
            self.assertEqual((await self.request(body, method=method, path=path))[0], 405)
    async def test_exact_oracle_bytes_both_directions_and_one_connection(self):
        body = (" \n" + json.dumps(envelope(), indent=2) + "\t").encode()
        for response in (self.response, b' { "SignedV1": [0,0,0,1,255] }\n'):
            self.response = response
            status, headers, returned = await self.request(body)
            self.assertEqual((status, returned), (200, response))
            self.assert_cors(headers)
            self.assertEqual(headers["Content-Type"], "application/json")
        self.assertEqual(self.received, [body, body])

    async def test_origin_and_api_host_are_independent_and_credentials_rejected(self):
        for headers in ({"Origin": "https://evil.invalid"}, {"Origin": None},
                        {"Origin": "null"}, {"Origin": "http://localhost:8000/"},
                        {"Host": "localhost:8000"}, {"Host": "evil.invalid"},
                        {"Host": None}, {"Cookie": "session=value"},
                        {"Authorization": "Bearer fixture"}, {"Proxy-Authorization": "fixture"}):
            with self.subTest(headers=headers):
                code, returned, _body = await self.request(headers=headers)
                self.assertEqual(code, 403)
                self.assert_cors(returned)
        self.assertEqual(self.received, [])
        self.assertEqual((await self.request())[0], 200)

    async def test_preflight_validates_origin_route_method_and_requested_headers(self):
        for path, method in (("/api/sign", "POST"), ("/esplora/tx", "POST"),
                             ("/esplora/blocks/tip/hash", "GET"), ("/api/passkeys", "POST"),
                             ("/api/passkeys/aabb", "GET")):
            request_headers = {"Access-Control-Request-Method": method}
            if method == "POST":
                request_headers["Access-Control-Request-Headers"] = "Content-Type"
            code, headers, body = await self.request(method="OPTIONS", path=path, headers=request_headers)
            self.assertEqual((code, body), (204, b""))
            self.assert_cors(headers)
            self.assertEqual(headers["Access-Control-Allow-Methods"], method)
            self.assertEqual(headers.get("Access-Control-Allow-Headers"),
                             "Content-Type" if method == "POST" else None)
        valid = {"Access-Control-Request-Method": "POST", "Access-Control-Request-Headers": "content-type"}
        for additions in ({"Origin": "https://evil.invalid"}, {"Origin": None},
                          {"Access-Control-Request-Method": "DELETE"},
                          {"Access-Control-Request-Method": None},
                          {"Access-Control-Request-Headers": "authorization, content-type"},
                          {"Access-Control-Request-Headers": "content-type,content-type"},
                          {"Access-Control-Request-Headers": ""},
                          {"Access-Control-Request-Headers": "*"},
                          {"Access-Control-Request-Private-Network": "true"},
                          {"Content-Type": "application/json"}, {"Content-Length": "1"}):
            with self.subTest(additions=additions):
                code, headers, _body = await self.request(method="OPTIONS", headers=valid | additions)
                self.assertIn(code, (400, 403, 405))
                self.assert_cors(headers)
                self.assertNotIn("Access-Control-Allow-Methods", headers)
        self.assertEqual((await self.request(method="OPTIONS", path="/setup", headers=valid))[0], 404)
        self.assertEqual(self.received, [])
        self.assertEqual(self.chain_requests, [])

    async def test_invalid_request_framing_and_payload_never_reach_oracle(self):
        malformed = [b'{"SignProgramV1":{},"SignProgramV1":{}}', b'{"Setup":{}}',
                     b'{"SignProgramV1":NaN}', b"\xff", "{}".encode("utf-16")]
        request = envelope()
        request["SignProgramV1"]["psbt"][3] = 2
        malformed.append(json.dumps(request).encode())
        request = envelope()
        request["SignProgramV1"]["instance"]["program"] = [True]
        malformed.append(json.dumps(request).encode())
        for body in malformed:
            code, headers, _response = await self.request(body)
            self.assertEqual(code, 400)
            self.assert_cors(headers)
        cases = [({"Content-Length": str(server.MAX_MESSAGE + 1)}, 413),
                 ({"Content-Length": None}, 411), ({"Content-Length": "01"}, 400),
                 ({"Transfer-Encoding": "chunked"}, 400), ({"Content-Encoding": "gzip"}, 400),
                 ({"Expect": "100-continue"}, 400), ({"Content-Type": "text/plain"}, 415),
                 ({"content-length": "2"}, 400),
                 ({"X-Padding": "x" * server.MAX_HEADERS}, 431)]
        for extra, expected in cases:
            with self.subTest(headers=extra):
                code, headers, _response = await self.request(headers=extra)
                self.assertEqual(code, expected)
                self.assert_cors(headers)
        self.assertEqual(self.received, [])

    async def test_bad_upstream_oracle_frames_fail_without_retry(self):
        for mode in ("oversized", "truncated"):
            self.upstream_mode = mode
            code, headers, _body = await self.request()
            self.assertEqual(code, 502)
            self.assert_cors(headers)
        self.upstream_mode = "normal"
        for response in (b'{"Setup":{}}', b'{"SignedV1":[0,0,0,2,255]}',
                         b'{"RejectedV1":"a","RejectedV1":"b"}'):
            self.response = response
            self.assertEqual((await self.request())[0], 502)
        self.assertEqual(len(self.received), 5)

    async def test_only_gateway_routes_are_served(self):
        for path in ("/", "/health", "/setup", "/public-key", "/wallet-config.json", "/app.js",
                     "/../server.py", "/%2e%2e/server.py", "/api/chain/tip", "/api/sign?url=x"):
            code, headers, _body = await self.request(method="GET", path=path)
            self.assertEqual(code, 404)
            self.assert_cors(headers)
        self.assertEqual((await self.request(method="GET"))[0], 405)
        self.assertEqual((await self.request(method="POST", path="/esplora/fee-estimates"))[0], 405)
        self.assertEqual(self.received, [])
        self.assertEqual(self.chain_requests, [])

    async def test_admission_is_bounded_before_headers_and_errors_have_cors(self):
        clients = [await asyncio.open_connection("127.0.0.1", self.port)
                   for _ in range(server.MAX_CONNECTIONS)]
        try:
            reader, writer = await asyncio.open_connection("127.0.0.1", self.port)
            try:
                response = await asyncio.wait_for(reader.read(), 2)
                self.assertTrue(response.startswith(b"HTTP/1.1 503 "))
                self.assertIn(b"Access-Control-Allow-Origin: http://localhost:8000\r\n", response)
            finally:
                writer.close()
                await writer.wait_closed()
            self.assertEqual(self.received, [])
        finally:
            for _reader, writer in clients:
                writer.close()
                await writer.wait_closed()

    async def test_total_deadline_releases_silent_upstream_and_admission(self):
        self.upstream_mode = "silent"
        with patch.object(server, "TIMEOUT", 0.1):
            code, headers, _body = await self.request()
            self.assertEqual(code, 504)
            self.assert_cors(headers)
        self.upstream_mode = "normal"
        self.assertEqual((await self.request())[0], 200)
        self.assertEqual(len(self.received), 2)

    async def test_proxy_https_requires_explicit_mode_and_exact_forwarded_proto(self):
        self.relay.origin = "https://owner.github.io"
        self.relay.host = "api.example.test"
        self.relay.mode = "https-proxy"
        headers = {"Host": self.relay.host, "Origin": self.relay.origin}
        for proto in (None, "http", "https,http", "HTTPS"):
            code, returned, _body = await self.request(headers=headers | {"X-Forwarded-Proto": proto})
            self.assertEqual(code, 403)
            self.assert_cors(returned)
        self.assertEqual(self.received, [])
        headers["X-Forwarded-Proto"] = "https"
        self.assertEqual((await self.request(headers=headers))[0], 200)
        # An XFP header cannot turn an insecure listener into direct TLS.
        self.relay.mode = "tls"
        self.assertEqual((await self.request(headers=headers))[0], 403)
        self.assertEqual(len(self.received), 1)

    async def test_bdk_routes_preserve_native_bytes_types_and_fixed_destination(self):
        txid, block = "12" * 32, "34" * 32
        cases = [
            ("blocks/tip/height", b"12\n", "text/plain"),
            ("blocks/tip/hash", block.encode(), "text/plain"),
            ("blocks", b"[ {\"id\":\"" + block.encode() + b"\"} ]", "application/json"),
            ("blocks/12", b"[]", "application/json"),
            ("block-height/12", block.encode(), "text/plain"),
            (f"block/{block}/status", b'{"in_best_chain":true,"height":12}', "application/json"),
            (f"block/{block}/header", b"00" * 80, "text/plain"),
            (f"scripthash/{txid}/txs", b"[ ]", "application/json"),
            (f"scripthash/{txid}/txs/chain/{block}", b"[]\n", "application/json"),
            (f"scripthash/{txid}/txs/mempool", b"[]", "application/json"),
            ("address/bcrt1qqqqqq/txs", b"[]", "application/json"),
            (f"address/bcrt1qqqqqq/txs/chain/{txid}", b"[]", "application/json"),
            ("address/bcrt1qqqqqq/utxo", b"[]", "application/json"),
            (f"tx/{txid}", b'{"txid":"' + txid.encode() + b'","vin":[],"vout":[]}', "application/json"),
            (f"tx/{txid}/hex", b"AABB\n", "text/plain"),
            (f"tx/{txid}/status", b'{"confirmed":false}', "application/json"),
            (f"tx/{txid}/outspends", b'[{"spent":false}]', "application/json"),
            (f"tx/{txid}/outspend/0", b'{ "spent" : false }', "application/json"),
            ("fee-estimates", b'{"1":1.25,"6":1}', "application/json"),
        ]
        for route, body, mime in cases:
            with self.subTest(route=route):
                self.chain_reply(body, extra=b"Set-Cookie: bad=value\r\nContent-Type: text/html\r\n")
                code, headers, response = await self.request(method="GET", path="/esplora/" + route)
                self.assertEqual((code, response, headers["Content-Type"]), (200, body, mime))
                self.assert_cors(headers)
                method, path, sent_headers, sent = self.chain_requests[-1]
                self.assertEqual((method, path, sent), ("GET", "/api/" + route, b""))
                self.assertEqual(sent_headers["Host"], self.esplora_url.removeprefix("http://").removesuffix("/api"))
                self.assertEqual(sent_headers["Accept-Encoding"], "identity")
                self.assertNotIn("Cookie", sent_headers)
                self.assertNotIn("Origin", sent_headers)
        self.assertEqual(self.received, [])

    async def test_history_and_utxos_are_not_normalized_or_silently_capped(self):
        body = json.dumps([{"txid": "ab" * 32, "vout": n, "value": 1,
                            "status": {"confirmed": False}} for n in range(65)]).encode()
        self.chain_reply(body)
        code, _headers, response = await self.request(method="GET", path="/esplora/address/bcrt1qqqqqq/utxo")
        self.assertEqual((code, response), (200, body))

    async def test_broadcast_is_raw_hex_and_once_only(self):
        path = "/esplora/tx"
        for headers in ({"Origin": None}, {"Origin": "https://other.invalid"},
                        {"Host": "other.invalid"}, {"Content-Type": "application/json"}):
            self.assertIn((await self.request(b"AAbb", path=path, headers=headers))[0], (403, 415))
        for malformed in (b'{"transaction_hex":"aa"}', b"zz", b"a", b"aabb\n", b"aa bb", b""):
            self.assertEqual((await self.request(malformed, path=path))[0], 400)
        self.assertEqual(self.chain_requests, [])
        txid = ("ab" * 32).encode()
        self.chain_reply(txid)
        code, headers, response = await self.request(b"AAbb", path=path,
                                                     headers={"Content-Type": "text/plain; charset=utf-8"})
        self.assertEqual((code, response, headers["Content-Type"]), (200, txid, "text/plain"))
        self.assert_cors(headers)
        self.assertEqual(len(self.chain_requests), 1)
        method, upstream, sent_headers, sent = self.chain_requests[0]
        self.assertEqual((method, upstream, sent), ("POST", "/api/tx", b"AAbb"))
        self.assertEqual(sent_headers["Content-Type"], "text/plain")
        self.assertEqual(self.received, [])

    async def test_arbitrary_chain_paths_never_reach_upstream(self):
        txid = "ab" * 32
        for path in ("/esplora/blocks/tip/height?url=http://other.invalid", "/esplora/../public-key",
                     "/esplora/%62locks", "/esplora//blocks", "/esplora/address/bcrt1qq/utxo",
                     "/esplora/address/tb1qqqqqq/utxo", f"/esplora/tx/{txid}/outspend/4294967296",
                     f"/esplora/tx/{txid}/outspend/01", "/esplora/http://other.invalid/tx",
                     "/esplora/blocks/4294967296", "/esplora/block-height/01",
                     f"/esplora/tx/{txid}/raw", "/esplora/mempool", "/esplora/blocks#x"):
            with self.subTest(path=path):
                self.assertIn((await self.request(method="GET", path=path))[0], (400, 404))
        self.assertEqual(self.chain_requests, [])

    async def test_chain_response_bounds_framing_and_redirects_never_retry(self):
        oversized = str(server.MAX_MESSAGE + 1).encode()
        responses = [
            b"HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1/escape\r\nContent-Length: 0\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nContent-Length: " + oversized + b"\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\n1",
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n100001\r\n",
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Length: 1\r\n\r\n1",
            b"HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: 1\r\n\r\n1",
            b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\ncontent-length: 1\r\n\r\n1",
            b"HTTP/1.1 200 OK\r\nX-Large: " + b"x" * server.MAX_HEADERS + b"\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n" + b"x" * (server.MAX_MESSAGE + 1),
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\nX-Trailer: no\r\n\r\n",
        ]
        for response in responses:
            self.chain_response = response
            code, headers, _body = await self.request(method="GET", path="/esplora/blocks/tip/height")
            self.assertEqual(code, 502)
            self.assert_cors(headers)
        self.assertEqual(len(self.chain_requests), len(responses))
        self.chain_response = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\n12\r\n0\r\n\r\n"
        code, _headers, body = await self.request(method="GET", path="/esplora/blocks/tip/height")
        self.assertEqual((code, body), (200, b"12"))

    async def test_exact_one_mib_body_boundary_is_accepted(self):
        body = b"aa" * (server.MAX_MESSAGE // 2)
        self.chain_reply(("ab" * 32).encode())
        self.assertEqual((await self.request(body, path="/esplora/tx"))[0], 200)
        self.assertEqual(self.chain_requests[0][3], body)
        self.chain_reply(body)
        code, _headers, received = await self.request(method="GET", path="/esplora/tx/" + "ab" * 32 + "/hex")
        self.assertEqual((code, received), (200, body))

    async def test_native_not_found_rejection_and_timeout_are_not_retried(self):
        for status, path, method, body in (
                (404, "/esplora/tx/" + "ab" * 32, "GET", b""),
                (400, "/esplora/tx", "POST", b"aabb"),
                (500, "/esplora/tx", "POST", b"aabb")):
            rejection = b"missing inputs " + b"x" * 1000
            self.chain_reply(rejection, status)
            code, headers, response = await self.request(body, method, path)
            self.assertEqual((code, response), (status, rejection))
            self.assert_cors(headers)
        self.chain_silent = True
        with patch.object(server, "TIMEOUT", 0.1):
            code, headers, _body = await self.request(b"aabb", path="/esplora/tx")
            self.assertEqual(code, 504)
            self.assert_cors(headers)
        self.assertEqual(len(self.chain_requests), 4)

    async def test_direct_tls_and_pre_handshake_admission(self):
        openssl = shutil.which("openssl")
        if openssl is None:
            self.skipTest("openssl is required only to generate a temporary TLS fixture")
        with tempfile.TemporaryDirectory() as directory:
            cert, key = Path(directory) / "cert.pem", Path(directory) / "key.pem"
            await asyncio.to_thread(subprocess.run, [openssl, "req", "-x509", "-newkey", "rsa:2048",
                "-nodes", "-days", "1", "-subj", "/CN=127.0.0.1",
                "-addext", "subjectAltName=IP:127.0.0.1", "-keyout", str(key), "-out", str(cert)],
                check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
            args = server.parser().parse_args([
                "--api-url", "https://127.0.0.1", "--origin", "https://owner.github.io",
                "--tls-cert", str(cert), "--tls-key", str(key),
                "--passkey-db", self.passkey_db,
                "--upstream-port", str(self.oracle.sockets[0].getsockname()[1])])
            relay, context = server.configure(args)
            self.acceptor.cancel()
            await asyncio.gather(self.acceptor, return_exceptions=True)
            self.relay.close()
            self.relay = relay
            self.listener = server.open_listener("127.0.0.1", 0)
            self.port = self.listener.getsockname()[1]
            self.acceptor = asyncio.create_task(server.accept_connections(self.listener, relay, context))
            self.client_tls = ssl.create_default_context(cafile=str(cert))
            code, headers, body = await self.request(headers={"Host": "127.0.0.1", "Origin": relay.origin})
            self.assertEqual((code, body), (200, self.response))
            self.assert_cors(headers)
            # The four stalled handshakes consume admission, not four extra
            # uncounted SSL transports waiting ahead of the HTTP limiter.
            clients = [await asyncio.open_connection("127.0.0.1", self.port)
                       for _ in range(server.MAX_CONNECTIONS)]
            try:
                reader, writer = await asyncio.open_connection("127.0.0.1", self.port)
                try:
                    self.assertEqual(await asyncio.wait_for(reader.read(), 2), b"")
                finally:
                    writer.close()
                    await writer.wait_closed()
                self.assertEqual(len(self.received), 1)
            finally:
                for _reader, writer in clients:
                    writer.close()
                    await writer.wait_closed()


class ConfigurationTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.passkey_db = str(Path(self.directory.name) / "passkeys.sqlite3")

    def arguments(self, *extra):
        return server.parser().parse_args([
            "--api-url", "https://api.example.test", "--origin", "https://owner.github.io",
            "--passkey-db", self.passkey_db, *extra])

    def test_production_has_no_implicit_plaintext_or_non_loopback_proxy(self):
        for extra in ((), ("--tls-cert", "/missing"), ("--tls-key", "/missing"),
                      ("--https-proxy", "--allow-local-dev"),
                      ("--https-proxy", "--listen", "0.0.0.0"),
                      ("--https-proxy", "--listen", "::"),
                      ("--https-proxy", "--upstream-host", "localhost"),
                      ("--https-proxy", "--upstream-port", "0"),
                      ("--https-proxy", "--port", "65536"),
                      ("--https-proxy", "--chain", "regtest", "--esplora-url", "http://127.0.0.1:3002")):
            with self.subTest(extra=extra), self.assertRaises(ValueError):
                server.configure(self.arguments(*extra))

    def test_api_and_frontend_are_exact_canonical_origins(self):
        for origin in ("https://wallet.example.test/", "https://wallet.example.test/path",
                       "https://wallet.example.test?", "https://wallet.example.test#",
                       "https://wallet.example.test:443", "https://wallet.example.test:0444",
                       "https://wallet.example.test:65536", "https://WALLET.example.test",
                       "https://user@wallet.example.test", "https://wallet.example.test\n",
                       "http://wallet.example.test", "null", "*"):
            for api, frontend in ((origin, "https://owner.github.io"), ("https://api.example.test", origin)):
                with self.subTest(api=api, frontend=frontend), self.assertRaises(ValueError):
                    server.Relay(api, frontend, mode="https-proxy", passkey_db=self.passkey_db)

    def test_ip_api_does_not_allow_ip_frontend(self):
        for origin in ("https://127.0.0.1", "https://[::1]"):
            with self.subTest(origin=origin), self.assertRaises(ValueError):
                server.Relay("https://127.0.0.1", origin, mode="https-proxy", passkey_db=self.passkey_db)

    def test_plaintext_requires_both_loopback_origins_and_explicit_opt_in(self):
        for extra in ((), ("--https-proxy",), ("--allow-local-dev", "--listen", "0.0.0.0")):
            args = self.arguments("--api-url", "http://localhost:8123", "--origin", "http://localhost:8000", *extra)
            with self.subTest(extra=extra), self.assertRaises(ValueError):
                server.configure(args)
        for api, origin in (("http://evil.invalid", "http://localhost:8000"),
                            ("http://localhost:8123", "http://evil.invalid"),
                            ("https://api.example.test", "http://localhost:8000")):
            with self.subTest(api=api, origin=origin), self.assertRaises(ValueError):
                server.Relay(api, origin, mode="local-dev", passkey_db=self.passkey_db)

    def test_esplora_destination_cannot_escape_pinned_chain(self):
        self.assertEqual(server.validate_esplora_url(None, "mutinynet", False).geturl(),
                         "https://mutinynet.com/api")
        for url in ("http://mutinynet.com/api", "https://mutinynet.com/api/",
                    "https://other.invalid/api", "https://mutinynet.com/api?x=1",
                    "https://mutinynet.com@other.invalid/api"):
            with self.subTest(url=url), self.assertRaises(ValueError):
                server.validate_esplora_url(url, "mutinynet", True)
        for url in (None, "https://mutinynet.com/api", "http://other.invalid",
                    "http://127.0.0.1:80/api/../escape", "http://127.0.0.1/%2e%2e",
                    "http://127.0.0.1?url=escape", "http://127.0.0.1#escape",
                    "http://user@127.0.0.1/api", "http://127.0.0.1:65536/api",
                    "http://127.0.0.1/api\n", "http://127.0.0.1/api%25n"):
            with self.subTest(url=url), self.assertRaises(ValueError):
                server.validate_esplora_url(url, "regtest", True)
        with self.assertRaises(ValueError):
            server.validate_esplora_url("http://127.0.0.1:8999/api", "regtest", False)
        for url in ("http://127.0.0.1:8999/api", "http://localhost:8999/api", "http://[::1]:8999"):
            self.assertEqual(server.validate_esplora_url(url, "regtest", True).geturl(), url)


if __name__ == "__main__":
    unittest.main()
