"""Map target URLs between the two planes a tester's target lives on.

A target container (e.g. Juice Shop) is reachable two different ways, and the
system must NEVER collapse them into one value:

  * External (browser plane) — the Windows host + Chrome + the FastAPI backend
    (which runs on the host via uvicorn, NOT in Docker) reach the target through
    the published port on localhost, e.g. ``http://localhost:8082``.

  * Internal (Docker plane) — the engine's tool containers (nmap, http-probe,
    browser-recon, pentest-tools) run with ``--network pentest-net`` and reach
    the target by its compose service name + container port, e.g.
    ``http://juice-shop:3000``.

docker-compose.yml is the single source of truth linking the two:

    juice-shop:
      ports:
        - "8082:3000"     # <host_port>:<container_port>

From that one line this module can answer both directions:

    (service="juice-shop", host_port=8082)  --internal-->  juice-shop:3000
    (service="juice-shop", host_port=8082)  --external-->  localhost:8082

A tester enters the *service name* as hostname (``http://juice-shop:8082``) so
the engine plane is already correct; the external plane then needs the hostname
rewritten to ``localhost`` for the browser. This module keeps both planes
explicit and derivable; callers pick the plane for their consumer rather than
string-replacing one URL into the other.
"""
import pathlib
import re
from typing import Optional
from urllib.parse import urlsplit, urlunsplit

_REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
# Every compose file that defines a lab target on pentest-net. VulnShop
# (web: "8084:5000") lives outside microservices/target, so it is listed too.
_COMPOSE_PATHS = [
    _REPO_ROOT / "microservices" / "target" / "docker-compose.yml",
    _REPO_ROOT / "vulnshop" / "docker-compose.yml",
]

# Hostnames that already denote "this host" in the browser plane — no service
# lookup needed, they resolve for Chrome / the host-side backend as-is.
_LOCAL_HOSTS = {"localhost", "127.0.0.1", "0.0.0.0", "::1", "host.docker.internal"}


def _parse_compose_port_map() -> dict[tuple[str, int], int]:
    """Return {(service_name, host_port): container_port} from all target compose files."""
    mapping: dict[tuple[str, int], int] = {}
    for path in _COMPOSE_PATHS:
        if path.exists():
            mapping.update(_parse_one_compose(path.read_text(encoding="utf-8")))
    return mapping


def _parse_one_compose(text: str) -> dict[tuple[str, int], int]:
    mapping: dict[tuple[str, int], int] = {}
    current_service: Optional[str] = None
    in_ports = False

    for raw_line in text.splitlines():
        if not raw_line.strip() or raw_line.lstrip().startswith("#"):
            continue

        indent = len(raw_line) - len(raw_line.lstrip())
        stripped = raw_line.strip()

        if indent == 2 and stripped.endswith(":"):
            current_service = stripped[:-1].strip()
            in_ports = False
            continue

        if not current_service:
            continue

        if stripped == "ports:":
            in_ports = True
            continue

        if in_ports and stripped.startswith("-"):
            m = re.search(r'"?(\d+)\s*:\s*(\d+)"?', stripped)
            if m:
                host_port = int(m.group(1))
                container_port = int(m.group(2))
                mapping[(current_service, host_port)] = container_port
        elif in_ports and indent <= 4:
            in_ports = False

    return mapping


_CACHE: Optional[dict[tuple[str, int], int]] = None


def _port_map() -> dict[tuple[str, int], int]:
    global _CACHE
    if _CACHE is None:
        _CACHE = _parse_compose_port_map()
    return _CACHE


def host_to_internal_port(hostname: str, host_port: int) -> Optional[int]:
    """Return container port for (service_name, host_port), or None if unmapped."""
    return _port_map().get((hostname, host_port))


def service_for_host_port(host_port: int) -> Optional[str]:
    """Return the compose service name that publishes `host_port`, if unique.

    Lets the external plane recover the service name when the tester entered a
    bare localhost target. Returns None if no service — or more than one —
    publishes that host port (ambiguous, so we don't guess).
    """
    matches = {svc for (svc, hp) in _port_map() if hp == host_port}
    return next(iter(matches)) if len(matches) == 1 else None


def resolve_internal_url(hostname: str, host_port: int, scheme: str = "http") -> str:
    """Build the Docker-plane URL a tool container should fetch.

    Keeps the compose *service name* as hostname (reachable on pentest-net) and
    translates the published host port to the container port when compose knows
    the mapping. If `hostname` is a local alias the tester typed instead of the
    service name, recover the service from the port so the container gets a
    name it can resolve on the network.
    """
    service = hostname
    if hostname in _LOCAL_HOSTS:
        service = service_for_host_port(host_port) or hostname
    internal_port = host_to_internal_port(service, host_port) or host_port
    return f"{scheme}://{service}:{internal_port}"


def resolve_external_url(hostname: str, host_port: int, scheme: str = "http") -> str:
    """Build the browser-plane URL (Chrome / host-side backend/proxy should fetch).

    A compose *service name* (``juice-shop``) does not resolve in Chrome or on
    the Windows host, so it is rewritten to ``localhost`` while the published
    host port is kept unchanged. Hostnames that already denote this host, and
    unknown hostnames (a real external target the tester is authorized to test),
    are returned untouched — we only rewrite names we know are compose services.
    """
    host = hostname
    if hostname not in _LOCAL_HOSTS and (hostname, host_port) in _port_map():
        host = "localhost"
    return f"{scheme}://{host}:{host_port}"


def to_internal_url(browser_url: str) -> str:
    """Translate a full browser-plane URL into the Docker-plane URL to fetch.

    The frontend hands the backend the URL shown in the in-app browser address
    bar (localhost:8082/...). A tool container on pentest-net cannot reach
    localhost, so the host:port is rewritten to the compose service name +
    container port while the path, query and fragment are preserved (the tester
    may have navigated to a deep link). If the URL can't be mapped (unknown
    port/host, no scheme) it is returned unchanged.
    """
    parts = urlsplit(browser_url)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        return browser_url
    host_port = parts.port
    if host_port is None:
        return browser_url
    internal_origin = resolve_internal_url(parts.hostname, host_port, parts.scheme)
    io = urlsplit(internal_origin)
    return urlunsplit((io.scheme, io.netloc, parts.path, parts.query, parts.fragment))


def to_external_url(internal_url: str) -> str:
    """Translate a Docker-plane URL into the browser-plane URL shown to the tester.

    Inverse of `to_internal_url`: ``http://web:5000/login`` becomes
    ``http://localhost:8084/login`` because compose publishes ``web`` as
    ``"8084:5000"``. Use it at every DISPLAY/REPORT boundary (logs, live frames,
    findings) — never on the URL a tool container actually fetches, which must
    stay internal. Accepts the service with either its container port or its
    published host port. Unknown hosts (a real external target) and ambiguous
    mappings are returned unchanged.
    """
    parts = urlsplit(internal_url)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        return internal_url
    host, port = parts.hostname, parts.port
    if host in _LOCAL_HOSTS or port is None:
        return internal_url

    host_ports = {hp for (svc, hp), cp in _port_map().items() if svc == host and cp == port}
    if not host_ports and (host, port) in _port_map():
        host_ports = {port}  # service name + published port (e.g. web:8084)
    if len(host_ports) != 1:
        return internal_url

    netloc = f"localhost:{next(iter(host_ports))}"
    return urlunsplit((parts.scheme, netloc, parts.path, parts.query, parts.fragment))


# ─── Sandbox command translation (browser plane → Docker plane) ──────────────
#
# Sandbox commands run in pentest-container on pentest-net. There, localhost is
# the container itself and published host ports (8084) do not exist: the target
# is <service>:<container port> (web:5000). Testers and the assistant naturally
# write the browser-plane address, so commands are translated before running.

_ALIASES = r"localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\]|host\.docker\.internal"

# Tools that take a bare host (no host:port) — a port glued to the host is
# stripped (nmap gets it back as -p).
_HOST_ONLY_TOOLS = {"traceroute", "tracepath", "mtr", "ping", "dig", "host",
                    "nslookup", "whois", "nmap"}
# Tools whose port is given by a flag next to a bare host.
_PORT_FLAGS = {"nmap": r"-p\s*", "nikto": r"-p(?:ort)?\s+"}

_SEGMENT_SPLIT_RE = re.compile(r"(\s*(?:&&|\|\||;|\|)\s*)")


def _services() -> set[str]:
    return {svc for (svc, _hp) in _port_map()}


def _host_re(names: set[str]) -> str:
    svc = "|".join(re.escape(s) for s in sorted(names, key=len, reverse=True))
    return f"{_ALIASES}|{svc}" if svc else _ALIASES


def _is_alias(host: str) -> bool:
    return host.lower().strip("[]") in {h.strip("[]") for h in _LOCAL_HOSTS}


def _translate_host_port(host: str, port: int) -> Optional[tuple[str, int]]:
    """(host, port) as written → (service, container_port), or None if unknown.

    localhost:8084 → web:5000 ; web:8084 → web:5000 ; web:5000 → unchanged.
    """
    if _is_alias(host):
        service = service_for_host_port(port)
        if not service:
            return None
        return service, host_to_internal_port(service, port) or port
    if (host, port) in _port_map():
        return host, _port_map()[(host, port)]
    return None


def _translate_segment(seg: str, default_service: Optional[str]) -> str:
    """Host-only tools and port flags, inside one `cmd args` segment."""
    m = re.match(r"\s*(?:sudo\s+)?([\w.-]+)", seg)
    tool = m.group(1).lower() if m else ""
    services = _services()
    host_tok = re.compile(rf"(?<![\w./:@=-])({_host_re(services)})(?::(\d{{1,5}}))?(?![\w.-])",
                          re.IGNORECASE)

    target_service: Optional[str] = None
    glued_port: Optional[int] = None

    if tool in _HOST_ONLY_TOOLS:
        def repl(mm: "re.Match[str]") -> str:
            nonlocal target_service, glued_port
            host, port = mm.group(1), mm.group(2)
            if port:
                tr = _translate_host_port(host, int(port))
                service, cport = tr if tr else (host, int(port))
                glued_port = cport
            elif _is_alias(host):
                if not default_service:
                    return mm.group(0)
                service = default_service
            else:
                service = host
            if service in services:
                target_service = service
            return service
        seg = host_tok.sub(repl, seg)
        if tool == "nmap" and glued_port and not re.search(r"\s-p", seg):
            seg = re.sub(r"\bnmap\b", f"nmap -p {glued_port}", seg, count=1)

    flag = _PORT_FLAGS.get(tool)
    if flag:
        if target_service is None:
            hm = host_tok.search(seg)
            if hm and hm.group(1) in services:
                target_service = hm.group(1)

        def port_repl(pm: "re.Match[str]") -> str:
            ports = []
            for p in pm.group(2).split(","):
                if p.isdigit():
                    svc = target_service or service_for_host_port(int(p))
                    tr = _translate_host_port(svc, int(p)) if svc else None
                    p = str(tr[1]) if tr else p
                ports.append(p)
            return pm.group(1) + ",".join(ports)
        seg = re.sub(rf"({flag})([\d,]+)\b", port_repl, seg)

    return seg


def to_internal_command(command: str, default_url: str = "") -> str:
    """Rewrite browser-plane addresses in a shell command to the Docker plane.

    - ``http://localhost:8084``, ``127.0.0.1:8084`` or ``web:8084`` (service +
      published port) → ``web:5000`` anywhere in the command.
    - Host-only tools (nmap, traceroute, ping, dig…): a glued ``:port`` is
      removed (nmap gets it back as ``-p``) and a bare ``localhost`` becomes the
      session's service (from `default_url`, the session's browser URL).
    - ``nmap -p 8084 web`` / ``nikto -h web -p 8084`` → port 5000.

    Bare hosts in other tools (e.g. an SSRF/XFF payload ``127.0.0.1``) and
    unmapped ports are left untouched on purpose.
    """
    services = _services()

    def repl(m: "re.Match[str]") -> str:
        tr = _translate_host_port(m.group("host"), int(m.group("port")))
        if not tr:
            return m.group(0)
        return f"{m.group('scheme') or ''}{tr[0]}:{tr[1]}"

    hostport_re = re.compile(
        rf"(?P<scheme>https?://)?(?<![\w.-])(?P<host>{_host_re(services)}):(?P<port>\d{{1,5}})\b",
        re.IGNORECASE,
    )
    command = hostport_re.sub(repl, command)

    default_service: Optional[str] = None
    if default_url:
        host = urlsplit(to_internal_url(default_url)).hostname
        if host in services:
            default_service = host

    parts = _SEGMENT_SPLIT_RE.split(command)
    return "".join(
        p if i % 2 else _translate_segment(p, default_service)
        for i, p in enumerate(parts)
    )
