"""Tests for the TLS certificate check.

The fixture makes a throwaway CA and server certificate with the openssl
command, then runs a TLS server on 127.0.0.1. The checker talks to a real
handshake, and nothing leaves this machine.
"""

import shutil
import socket
import ssl
import subprocess
import threading
from datetime import UTC, datetime

import pytest

from secops_cli import ssl_check
from secops_cli.output import FINDINGS, OK

pytestmark = pytest.mark.skipif(shutil.which("openssl") is None, reason="needs the openssl command")

LOCAL = staticmethod(lambda host: ["127.0.0.1"])


def openssl(*args, cwd):
    subprocess.run(["openssl", *args], cwd=cwd, check=True, capture_output=True)  # noqa: S603, S607


def make_pki(tmp, days):
    (tmp / "ca.ext").write_text(
        "basicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\n"
        "subjectKeyIdentifier=hash\n"
    )
    (tmp / "leaf.ext").write_text(
        "basicConstraints=CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\n"
        "extendedKeyUsage=serverAuth\nsubjectAltName=DNS:localhost\n"
        "subjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid\n"
    )
    openssl("genrsa", "-out", "ca.key", "2048", cwd=tmp)
    openssl("req", "-new", "-key", "ca.key", "-subj", "/CN=Test Lab CA", "-out", "ca.csr", cwd=tmp)
    openssl(
        "x509",
        "-req",
        "-in",
        "ca.csr",
        "-signkey",
        "ca.key",
        "-days",
        "30",
        "-extfile",
        "ca.ext",
        "-out",
        "ca.pem",
        cwd=tmp,
    )
    openssl("genrsa", "-out", "leaf.key", "2048", cwd=tmp)
    openssl(
        "req", "-new", "-key", "leaf.key", "-subj", "/CN=localhost", "-out", "leaf.csr", cwd=tmp
    )
    openssl(
        "x509",
        "-req",
        "-in",
        "leaf.csr",
        "-CA",
        "ca.pem",
        "-CAkey",
        "ca.key",
        "-set_serial",
        "7",
        "-days",
        str(days),
        "-extfile",
        "leaf.ext",
        "-out",
        "leaf.pem",
        cwd=tmp,
    )
    return tmp / "ca.pem", tmp / "leaf.pem", tmp / "leaf.key"


@pytest.fixture
def tls_server(tmp_path, request):
    days = getattr(request, "param", 90)
    ca, cert, key = make_pki(tmp_path, days)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert, key)
    server = socket.socket()
    server.bind(("127.0.0.1", 0))
    server.listen()
    stop = threading.Event()

    def serve():
        while not stop.is_set():
            try:
                conn, _ = server.accept()
            except OSError:
                return
            try:
                with context.wrap_socket(conn, server_side=True):
                    pass
            except (ssl.SSLError, OSError):
                pass  # the client may refuse our certificate; that is the test

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    yield server.getsockname()[1], ca
    stop.set()
    server.close()
    thread.join(timeout=2)


def test_trusted_with_lab_ca(tls_server):
    port, ca = tls_server
    report = ssl_check.check("localhost", port, cafile=str(ca), resolver=LOCAL)
    assert report.exit_code == OK
    assert report.data["verified"] is True
    assert report.data["san"] == ["localhost"]
    assert report.data["issuer"]["commonName"] == "Test Lab CA"
    assert 88 <= report.data["days_left"] <= 90


def test_untrusted_without_lab_ca(tls_server):
    port, _ = tls_server
    report = ssl_check.check("localhost", port, resolver=LOCAL)
    assert report.exit_code == FINDINGS
    assert report.data["verified"] is False
    assert "certificate" in report.data["error"]


@pytest.mark.parametrize("tls_server", [10], indirect=True)
def test_warns_when_expiry_is_near(tls_server):
    port, ca = tls_server
    report = ssl_check.check("localhost", port, cafile=str(ca), resolver=LOCAL)
    assert report.exit_code == FINDINGS
    assert "expires in" in report.data["problems"][0]


def test_reports_expired_relative_to_now(tls_server):
    port, ca = tls_server
    later = datetime(2100, 1, 1, tzinfo=UTC)
    report = ssl_check.check("localhost", port, cafile=str(ca), resolver=LOCAL, now=later)
    assert report.exit_code == FINDINGS
    assert report.data["problems"][0].startswith("expired")


def test_out_of_scope_target_is_refused_before_connecting():
    from secops_cli.scope import ScopeError

    with pytest.raises(ScopeError):
        ssl_check.check("example.com", resolver=lambda h: ["93.184.215.14"], fetch=pytest.fail)
