import asyncio
import json
import ssl
from datetime import UTC, datetime, timedelta

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from mcpshield.mtls_verifier import MTLSConfig
from mcpshield.policy import Policy, PolicyReloader
from mcpshield.proxy import HTTPUpstream, Proxy

IDENTITY = "spiffe://example.org/mcp"
PING = {"jsonrpc": "2.0", "method": "ping", "id": 1}
LIST = PING | {"method": "tools/list"}


def issue_certificate(folder, name, *, issuer=None, uris=(), usage=True, expired=False):
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    ca = issuer is None
    now = datetime.now(UTC)
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject if ca else issuer[0].subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=2))
        .not_valid_after(now + timedelta(days=-1 if expired else 1))
        .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
    )
    if usage:
        builder = builder.add_extension(x509.KeyUsage(
            digital_signature=not ca, content_commitment=False, key_encipherment=False,
            data_encipherment=False, key_agreement=False, key_cert_sign=ca, crl_sign=ca,
            encipher_only=False, decipher_only=False,
        ), critical=True)
    if not ca:
        builder = builder.add_extension(x509.ExtendedKeyUsage([
            ExtendedKeyUsageOID.SERVER_AUTH, ExtendedKeyUsageOID.CLIENT_AUTH,
        ]), critical=False)
        builder = builder.add_extension(x509.SubjectAlternativeName(
            [x509.DNSName("localhost"), *(x509.UniformResourceIdentifier(uri) for uri in uris)],
        ), critical=False)
    cert = builder.sign(key if ca else issuer[1], algorithm=hashes.SHA256())
    (folder / f"{name}.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    (folder / f"{name}.key").write_bytes(key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ))
    return cert, key


@pytest.mark.parametrize(("uris", "failure"), [
    ((IDENTITY,), None),
    (("spiffe://example.org/other",), "identity"),
    ((), "identity"),
    ((IDENTITY, "https://example.org"), "identity"),
    ((IDENTITY,), "untrusted"),
    ((IDENTITY,), "expired"),
    ((IDENTITY,), "usage"),
    ((IDENTITY,), "client-rejected"),
    ((IDENTITY,), "redirect"),
    ((IDENTITY,), "same-origin"),
    ((IDENTITY,), "downgrade"),
])
def test_real_mtls_upstream(tmp_path, uris, failure):
    ca = issue_certificate(tmp_path, "root")
    other = issue_certificate(tmp_path, "other-root")
    issue_certificate(tmp_path, "client", issuer=other if failure == "client-rejected" else ca)
    issue_certificate(tmp_path, "server", issuer=other if failure == "untrusted" else ca,
                      uris=uris, usage=failure != "usage", expired=failure == "expired")
    server_tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_tls.load_cert_chain(tmp_path / "server.pem", tmp_path / "server.key")
    server_tls.load_verify_locations(tmp_path / "root.pem")
    server_tls.verify_mode = ssl.CERT_REQUIRED
    config = MTLSConfig(tmp_path / "root.pem", tmp_path / "client.pem",
                        tmp_path / "client.key", (IDENTITY,))

    async def run():
        received = []

        async def serve(reader, writer):
            try:
                headers = await reader.readuntil(b"\r\n\r\n")
                length = next(line for line in headers.lower().splitlines()
                              if line.startswith(b"content-length:")).split(b":")[1]
                received.append(json.loads(await reader.readexactly(int(length))))
                assert writer.get_extra_info("ssl_object").getpeercert(binary_form=True)
                if failure in {"redirect", "downgrade", "same-origin"} and len(received) == 1:
                    port = writer.get_extra_info("sockname")[1]
                    target = {
                        "redirect": f"https://localhost:{port}/mcp",
                        "downgrade": f"http://127.0.0.1:{port}/mcp",
                        "same-origin": "/next",
                    }[failure]
                    writer.write(b"HTTP/1.1 307 Temporary Redirect\r\nLocation: " + target.encode()
                                 + b"\r\nContent-Length: 0\r\n\r\n")
                else:
                    reply = b'{"jsonrpc":"2.0","id":1,"result":{}}'
                    writer.write(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
                                 + f"Content-Length: {len(reply)}\r\n\r\n".encode() + reply)
                await writer.drain()
            except asyncio.IncompleteReadError:
                pass
            finally:
                writer.close()
                await writer.wait_closed()

        async with await asyncio.start_server(serve, "127.0.0.1", 0, ssl=server_tls) as server:
            port = server.sockets[0].getsockname()[1]
            upstream = HTTPUpstream(f"https://127.0.0.1:{port}/mcp", mtls=config)
            result = await asyncio.wait_for(Proxy(Policy(tools={}), upstream).handle(PING), 5)
        if failure in {None, "same-origin"}:
            assert result["result"] == {}
            assert received == [PING | {"params": {}}] * (2 if failure else 1)
        else:
            assert result["error"]["code"] == -32002
            # Redirects can receive the first request at the already authenticated origin.
            assert len(received) == int(failure in {"redirect", "downgrade"})

    asyncio.run(run())


@pytest.mark.parametrize("identity", [
    "", "https://example.org/mcp", "spiffe://example.org", "spiffe://example.org/",
    "spiffe://example.org/a/../b", "spiffe://example.org/a//b",
    "spiffe://example.org/mcp?query", "spiffe://example.org/mcp#fragment",
    "spiffe://example.org:443/mcp", "spiffe://example.org/%6dcp",
])
def test_invalid_allowlist(identity):
    config = MTLSConfig("", "", "", (identity,))
    with pytest.raises(ValueError, match="allowlist"):
        HTTPUpstream("https://localhost", mtls=config)


@pytest.mark.parametrize("url", ["http://localhost", "https://user:password@localhost"])
def test_mtls_requires_secure_url(url):
    config = MTLSConfig("", "", "", (IDENTITY,))
    with pytest.raises(ValueError, match="HTTPS upstream"):
        HTTPUpstream(url, mtls=config)


@pytest.mark.parametrize("invalid", [
    "tools: [", "tools: []", "tools: {read: {tier: invalid}}",
    "tools: {read: {arguments: {type: bogus}}}",
    'tools: {read: {arguments: {"$ref": "https://example.org/schema"}}}',
    "tools: {read: {arguments: &loop {properties: {read: *loop}}}}",
    None,
])
def test_invalid_reload_rolls_back_and_recovers(tmp_path, caplog, invalid):
    path = tmp_path / "policy.yml"
    path.write_text("tools: {read: {}}")
    policies = PolicyReloader(path)

    async def run():
        original = policies.current
        if invalid is None:
            path.unlink()
        else:
            path.write_text(invalid)
        assert not await policies.reload()
        assert policies.current is original
        assert path.name in caplog.text
        assert "Policy reload" in caplog.text
        warning_count = len(caplog.records)
        assert not await policies.reload()
        assert len(caplog.records) == warning_count
        path.write_text('{"tools": {"write": {"tier": "write"}}}')
        assert await policies.reload()
        assert set(policies.current.tools) == {"write"}
        assert not await policies.reload()

    asyncio.run(run())


def test_watcher_publishes_while_request_is_active(tmp_path):
    path = tmp_path / "policy.yml"
    path.write_text("tools: {before: {}}")
    policies = PolicyReloader(path)

    async def run():
        started = asyncio.Event()
        resume = asyncio.Event()

        async def upstream(message, scopes):
            started.set()
            await resume.wait()
            return {"jsonrpc": "2.0", "id": 1, "result": {
                "tools": [{"name": "before"}, {"name": "after"}],
            }}

        proxy = Proxy(policies, upstream)
        async with policies.watch(0.005):
            request = asyncio.create_task(proxy.handle(LIST))
            try:
                await asyncio.wait_for(started.wait(), 1)
                replacement = tmp_path / "replacement"
                replacement.write_text('{"tools": {"after": {}}}')
                replacement.replace(path)
                async with asyncio.timeout(2):
                    while "after" not in policies.current.tools:
                        await asyncio.sleep(0.005)
                assert not request.done()
            finally:
                resume.set()
                previous = await request
        assert previous["result"]["tools"] == [{"name": "before"}]
        assert (await proxy.handle(LIST))["result"]["tools"] == [{"name": "after"}]

    asyncio.run(run())
