"""Run one-shot tools in a Linux Bubblewrap sandbox with no direct network access."""

import math
import os
import re
import selectors
import signal
import subprocess
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from pathlib import PurePosixPath
from time import monotonic
from urllib.parse import urlsplit

from .policy import Denied

_HOST = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", re.ASCII)


def _host_key(host: str) -> str:
    key = host.lower().removesuffix(".")
    if len(key) > 253 or not all(_HOST.fullmatch(label) for label in key.split(".")):
        raise Denied("invalid outbound host")
    return key


def validate_outbound_url(url: str, allowed_hosts: Iterable[str]) -> None:
    """Authorize an HTTP(S) destination by exact host for a trusted caller."""
    if any(ord(char) <= 32 or ord(char) == 127 or char == "\\" for char in url):
        raise Denied("invalid outbound URL")
    try:
        parsed = urlsplit(url)
        port = parsed.port
    except ValueError as exc:
        raise Denied("invalid outbound URL") from exc
    if (parsed.scheme not in {"http", "https"} or not parsed.hostname
            or parsed.username is not None or parsed.netloc.endswith(":")
            or "[" in parsed.netloc or "]" in parsed.netloc
            or port == 0):
        raise Denied("invalid outbound URL")
    if _host_key(parsed.hostname) not in {_host_key(host) for host in allowed_hosts}:
        raise Denied("outbound host is not permitted")


@dataclass(frozen=True)
class SandboxResult:
    returncode: int
    stdout: bytes
    stderr: bytes
    timed_out: bool
    stdout_truncated: bool
    stderr_truncated: bool


class SandboxRunner:
    """Expose read-only system binaries and libraries and a fresh writable /work."""

    def __init__(
        self, *, timeout: float = 5.0, max_output_bytes: int = 64 * 1024,
        allowed_hosts: Iterable[str] = (),
    ):
        if not math.isfinite(timeout) or timeout <= 0:
            raise ValueError("timeout must be finite and positive")
        if type(max_output_bytes) is not int or max_output_bytes < 0:
            raise ValueError("max_output_bytes must be a non-negative integer")
        self.timeout = timeout
        self.max_output_bytes = max_output_bytes
        self.allowed_hosts = frozenset(_host_key(host) for host in allowed_hosts)

    def run(
        self, argv: Sequence[str], *, outbound_urls: Iterable[str] = (),
    ) -> SandboxResult:
        """Run argv without a shell. Declared URLs are checked before launch."""
        if isinstance(argv, str) or not argv:
            raise ValueError("argv must contain an executable and optional arguments")
        executable = PurePosixPath(argv[0])
        if executable.parent != PurePosixPath("/usr/bin"):
            raise ValueError("use an absolute executable path under /usr/bin")
        for url in outbound_urls:
            validate_outbound_url(url, self.allowed_hosts)

        env = {"PATH": "/usr/bin:/bin", "HOME": "/work", "TMPDIR": "/work", "LANG": "C.UTF-8"}
        command = [
            "/usr/bin/bwrap", "--unshare-all", "--unshare-user", "--disable-userns",
            "--die-with-parent", "--new-session", "--cap-drop", "ALL",
            "--ro-bind", "/usr/bin", "/usr/bin", "--ro-bind", "/usr/lib", "/usr/lib",
            "--ro-bind-try", "/usr/lib64", "/usr/lib64",
            "--symlink", "usr/bin", "/bin", "--symlink", "usr/lib", "/lib",
            "--symlink", "usr/lib64", "/lib64",
            "--dev", "/dev", "--size", str(16 * 1024 * 1024), "--tmpfs", "/work",
            "--symlink", "work", "/tmp", "--remount-ro", "/", "--chdir", "/work",
            "--", *argv,
        ]
        deadline = monotonic() + self.timeout
        with subprocess.Popen(
            command, env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, start_new_session=True,
        ) as process:
            buffers = [bytearray(), bytearray()]
            truncated = [False, False]
            timed_out = False
            try:
                with selectors.DefaultSelector() as selector:
                    selector.register(process.stdout, selectors.EVENT_READ, 0)
                    selector.register(process.stderr, selectors.EVENT_READ, 1)
                    while selector.get_map():
                        remaining = deadline - monotonic()
                        if remaining <= 0:
                            raise subprocess.TimeoutExpired(command[0], self.timeout)
                        for key, _ in selector.select(remaining):
                            chunk = os.read(key.fd, 65536)
                            if not chunk:
                                selector.unregister(key.fileobj)
                                continue
                            index = key.data
                            capacity = self.max_output_bytes - len(buffers[index])
                            buffers[index].extend(chunk[:capacity])
                            truncated[index] |= len(chunk) > capacity
                process.wait(timeout=max(0, deadline - monotonic()))
            except subprocess.TimeoutExpired:
                timed_out = True
            finally:
                if process.returncode is None:
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    process.wait()
        return SandboxResult(
            process.returncode, bytes(buffers[0]), bytes(buffers[1]), timed_out,
            truncated[0], truncated[1],
        )
