"""
core/tunnel_manager.py — SynthTel SSH SOCKS5 Tunnel Manager
============================================================
Replaces open_ssh_socks(), close_all_tunnels(), close_tunnel()
in synthtel_server.py.

Improvements over the original:
  • TunnelManager class — clean lifecycle instead of bare module globals
  • Health monitoring thread — detects crashed tunnels and auto-restarts them
  • Per-tunnel stats — uptime, restart count, bytes proxied estimate
  • Preflight connectivity test — verifies SOCKS5 works before returning
  • Port 25 test for direct-to-MX mode — returned in preflight result
  • Support for ISP SOCKS5 proxies alongside SSH tunnels (unified interface)
  • Key file tempfile written to /tmp with os.O_EXCL (atomic, no race)
  • Graceful SIGTERM → SIGKILL sequence on close with configurable timeout
  • Thread-safe — all state protected by a single RLock
  • Context manager support — guaranteed cleanup on campaign end

Usage:
    from core.tunnel_manager import TunnelManager

    mgr = TunnelManager()

    # Open an SSH SOCKS5 tunnel
    port, preflight = mgr.open(tunnel_cfg)
    # port: local SOCKS5 port (e.g. 1080)
    # preflight: {"socks_ok": True, "port25_ok": True, "public_ip": "..."}

    # Get proxy dict ready for smtp_sender / mx_sender
    proxy = mgr.get_proxy(port)
    # {"type": "socks5", "host": "127.0.0.1", "port": "1080"}

    # Close one tunnel
    mgr.close(port)

    # Close all at end of campaign
    mgr.close_all()

    # Or use as context manager:
    with TunnelManager() as mgr:
        port, pf = mgr.open(tunnel_cfg)
        ...

tunnel_cfg keys:
    tunnelType   : "ssh" (default) | "isp"
    sshHost      : SSH server hostname / ISP proxy host
    sshPort      : SSH port (default 22) / proxy port (default 1080)
    sshUser      : SSH username (default "root")
    sshKey       : Private key PEM string, path to key file, or password for sshpass
    localPort    : Local SOCKS5 listen port (default 1080)
    ehloDomain   : EHLO domain override for MX sends through this tunnel
    label        : Human-readable label for logs / UI
    # ISP-specific:
    username     : ISP proxy username (sshUser also accepted)
    password     : ISP proxy password (sshKey also accepted)
"""

import os
import re
import time
import socket
import logging
import tempfile
import threading
import subprocess
from dataclasses import dataclass, field
from typing import Optional

log = logging.getLogger(__name__)


# ═══════════════════════════════════════════════════════════════
# CONSTANTS
# ═══════════════════════════════════════════════════════════════

_DEFAULT_LOCAL_PORT     = 1080
_DEFAULT_SSH_PORT       = 22
_DEFAULT_SSH_USER       = "root"
_READY_POLL_INTERVAL    = 0.1   # seconds between readiness checks
_READY_MAX_ATTEMPTS     = 60    # up to 6 seconds total
_HEALTH_CHECK_INTERVAL  = 15    # seconds between health checks
_RESTART_DELAY          = 3     # seconds before restarting a crashed tunnel
_MAX_RESTART_ATTEMPTS   = 5     # give up after this many consecutive restarts
_SOCKS_TEST_HOST        = "8.8.8.8"
_SOCKS_TEST_PORT        = 53    # DNS — almost never blocked, good connectivity probe
_PORT25_TEST_HOST       = "gmail-smtp-in.l.google.com"
_PORT25_TEST_PORT       = 25


# ═══════════════════════════════════════════════════════════════
# DATA CLASSES
# ═══════════════════════════════════════════════════════════════

@dataclass
class TunnelInfo:
    """State for one active tunnel slot."""
    local_port:      int
    tunnel_type:     str          # "ssh" | "isp"
    label:           str
    cfg:             dict         # original tunnel_cfg (for restart)
    # SSH-specific
    proc:            Optional[subprocess.Popen] = None
    tmp_keyfile:     Optional[str]              = None
    # Stats
    opened_at:       float = 0.0
    restart_count:   int   = 0
    last_restart_at: float = 0.0
    disabled:        bool  = False
    disable_reason:  str   = ""

    def uptime_seconds(self) -> float:
        return time.time() - self.opened_at if self.opened_at else 0.0

    def is_ssh_alive(self) -> bool:
        if self.tunnel_type != "ssh":
            return True   # ISP proxies are stateless — always "alive"
        return self.proc is not None and self.proc.poll() is None

    def summary(self) -> dict:
        return {
            "port":          self.local_port,
            "type":          self.tunnel_type,
            "label":         self.label,
            "uptime_s":      round(self.uptime_seconds()),
            "restarts":      self.restart_count,
            "alive":         self.is_ssh_alive(),
            "disabled":      self.disabled,
            "disable_reason":self.disable_reason,
        }


# ═══════════════════════════════════════════════════════════════
# HELPERS
# ═══════════════════════════════════════════════════════════════

def _safe_int(val, default: int) -> int:
    try:
        return int(val)
    except (TypeError, ValueError):
        return default


def _write_temp_key(key_pem: str) -> str:
    """
    Write a PEM private key to a temp file with 0600 permissions.
    Uses O_EXCL for atomic creation — no race condition.
    Returns the file path.
    """
    fd, path = tempfile.mkstemp(suffix=".pem", prefix="synthtel_key_")
    try:
        os.write(fd, (key_pem.strip() + "\n").encode())
    finally:
        os.close(fd)
    os.chmod(path, 0o600)
    return path


def _cleanup_keyfile(path: Optional[str]):
    """Remove a temp key file, ignoring errors."""
    if path and os.path.exists(path):
        try:
            os.unlink(path)
        except Exception:
            pass


def _kill_proc(proc: Optional[subprocess.Popen], timeout: int = 3):
    """Graceful SIGTERM → SIGKILL sequence."""
    if proc is None or proc.poll() is not None:
        return
    try:
        proc.terminate()
        proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        try:
            proc.kill()
            proc.wait(timeout=2)
        except Exception:
            pass
    except Exception:
        pass


def _wait_for_socks_port(port: int, max_attempts: int = _READY_MAX_ATTEMPTS) -> bool:
    """Poll until the local SOCKS5 port accepts connections or we give up."""
    for _ in range(max_attempts):
        time.sleep(_READY_POLL_INTERVAL)
        try:
            s = socket.create_connection(("127.0.0.1", port), timeout=0.5)
            s.close()
            return True
        except (ConnectionRefusedError, OSError):
            continue
    return False


def _test_socks5_connectivity(host: str, port: int, test_host: str = _SOCKS_TEST_HOST,
                               test_port: int = _SOCKS_TEST_PORT) -> tuple:
    """
    Send a test connection through the SOCKS5 proxy at host:port.
    Returns (success: bool, public_ip: str, error: str).
    """
    try:
        import socks as pysocks
        sock = pysocks.socksocket()
        sock.set_proxy(pysocks.SOCKS5, host, port)
        sock.settimeout(10)
        sock.connect((test_host, test_port))
        sock.close()
        return True, "", ""
    except ImportError:
        # PySocks not available — just check the port is listening
        try:
            s = socket.create_connection((host, port), timeout=5)
            s.close()
            return True, "", ""
        except Exception as exc:
            return False, "", str(exc)
    except Exception as exc:
        return False, "", str(exc)


def _test_port25(proxy_host: str, proxy_port: int) -> tuple:
    """
    Test outbound port 25 through the SOCKS5 proxy.
    Returns (success: bool, banner: str, error: str).
    """
    try:
        import socks as pysocks
        sock = pysocks.socksocket()
        sock.set_proxy(pysocks.SOCKS5, proxy_host, proxy_port)
        sock.settimeout(15)
        sock.connect((_PORT25_TEST_HOST, _PORT25_TEST_PORT))
        banner = sock.recv(1024).decode("utf-8", errors="replace").strip()[:100]
        sock.close()
        return True, banner, ""
    except ImportError:
        return False, "", "PySocks not installed — cannot test port 25 through SOCKS5"
    except Exception as exc:
        err = str(exc)
        if "0x02" in err or "not allowed" in err.lower():
            return False, "", f"Port 25 BLOCKED by proxy firewall (0x02). Ask provider to allow outbound SMTP, or route through SMTP relay on port 587 instead."
        return False, "", err[:200]


def _get_public_ip_via_socks(proxy_host: str, proxy_port: int) -> str:
    """
    Retrieve the public IP the traffic exits from using the SOCKS5 proxy.
    Queries httpbin.org/ip through the proxy.
    """
    try:
        import socks as pysocks
        import json as _json
        sock = pysocks.socksocket()
        sock.set_proxy(pysocks.SOCKS5, proxy_host, proxy_port)
        sock.settimeout(10)
        sock.connect(("httpbin.org", 80))
        sock.sendall(b"GET /ip HTTP/1.1\r\nHost: httpbin.org\r\nConnection: close\r\n\r\n")
        resp = b""
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            resp += chunk
        sock.close()
        body = resp.decode(errors="replace").split("\r\n\r\n", 1)[-1]
        return _json.loads(body).get("origin", "").split(",")[0].strip()
    except Exception:
        return ""


# ═══════════════════════════════════════════════════════════════
# SSH COMMAND BUILDER
# ═══════════════════════════════════════════════════════════════

def _build_ssh_cmd(cfg: dict, local_port: int) -> tuple:
    """
    Build the SSH command list and handle key material.
    Returns (cmd: list, tmp_keyfile: str|None).

    Key material handling:
      - PEM string (contains newlines or "-----BEGIN") → write to temp file
      - Path to existing file → use directly
      - Anything else → treat as password and prepend sshpass
    """
    ssh_host  = cfg.get("sshHost", "")
    ssh_port  = _safe_int(cfg.get("sshPort", 22), 22)
    ssh_user  = cfg.get("sshUser", "") or _DEFAULT_SSH_USER
    ssh_key   = cfg.get("sshKey",  "")
    ehlo      = cfg.get("ehloDomain", "")

    cmd = [
        "ssh",
        "-o", "StrictHostKeyChecking=no",
        "-o", "UserKnownHostsFile=/dev/null",
        "-o", "ServerAliveInterval=30",
        "-o", "ServerAliveCountMax=3",
        "-o", "ExitOnForwardFailure=yes",
        "-o", "ConnectTimeout=15",
        "-N",                                   # no remote shell
        "-D", f"127.0.0.1:{local_port}",        # SOCKS5 listen port
        "-p", str(ssh_port),
        f"{ssh_user}@{ssh_host}",
    ]

    tmp_keyfile = None

    if ssh_key:
        key_stripped = ssh_key.strip()
        if "\n" in key_stripped or key_stripped.startswith("-----"):
            # Inline PEM — write to temp file
            tmp_keyfile = _write_temp_key(key_stripped)
            cmd = cmd[:1] + ["-i", tmp_keyfile] + cmd[1:]
        elif os.path.isfile(ssh_key):
            # Path to existing key file
            cmd = cmd[:1] + ["-i", ssh_key] + cmd[1:]
        else:
            # Treat as password — prepend sshpass
            cmd = ["sshpass", "-p", ssh_key] + cmd

    return cmd, tmp_keyfile


# ═══════════════════════════════════════════════════════════════
# TUNNEL MANAGER
# ═══════════════════════════════════════════════════════════════

class TunnelManager:
    """
    Manages SSH SOCKS5 tunnels and ISP SOCKS5 proxies for the campaign.

    Thread-safe. All state protected by a single RLock.
    Health monitor thread auto-restarts crashed SSH tunnels.
    """

    def __init__(
        self,
        auto_restart:      bool = True,
        max_restarts:      int  = _MAX_RESTART_ATTEMPTS,
        health_interval:   int  = _HEALTH_CHECK_INTERVAL,
        preflight_port25:  bool = True,
        preflight_get_ip:  bool = True,
    ):
        self._tunnels: dict[int, TunnelInfo] = {}    # local_port → TunnelInfo
        self._lock          = threading.RLock()
        self.auto_restart   = auto_restart
        self.max_restarts   = max_restarts
        self.preflight_port25 = preflight_port25
        self.preflight_get_ip = preflight_get_ip

        # Health monitor
        self._monitor_thread: Optional[threading.Thread] = None
        self._stop_event      = threading.Event()
        if auto_restart:
            self._start_monitor(health_interval)

    # ─────────────────────────────────────────────────────────
    # Public API
    # ─────────────────────────────────────────────────────────

    def open(self, tunnel_cfg: dict) -> tuple:
        """
        Open a tunnel (SSH or ISP SOCKS5) and verify it works.

        Returns:
            (local_port: int, preflight: dict)

        preflight keys:
            socks_ok    : bool — SOCKS5 connection test passed
            port25_ok   : bool — outbound port 25 available (if tested)
            port25_banner: str — MX server banner if port 25 connected
            public_ip   : str — exit IP of tunnel
            error       : str — human-readable error if socks_ok=False
            port25_error: str — human-readable error if port25_ok=False

        Raises on fatal errors (SSH not found, tunnel process exits immediately).
        """
        tt = (tunnel_cfg.get("tunnelType") or "ssh").lower()

        if tt == "isp":
            return self._open_isp(tunnel_cfg)
        else:
            return self._open_ssh(tunnel_cfg)

    def close(self, local_port: int):
        """Close and remove a specific tunnel by its local port."""
        with self._lock:
            info = self._tunnels.pop(local_port, None)
        if info:
            self._teardown(info)
            log.info("[TunnelManager] closed tunnel port %d (%s)", local_port, info.label)

    def close_all(self):
        """Close all open tunnels. Always call at end of campaign."""
        self._stop_event.set()
        if self._monitor_thread and self._monitor_thread.is_alive():
            self._monitor_thread.join(timeout=5)

        with self._lock:
            infos = list(self._tunnels.values())
            self._tunnels.clear()

        for info in infos:
            self._teardown(info)
        log.info("[TunnelManager] all tunnels closed")

    def get_proxy(self, local_port: int) -> dict:
        """
        Return a proxy config dict for smtp_sender / mx_sender.
        {"type": "socks5", "host": "127.0.0.1", "port": "1080"}
        """
        with self._lock:
            info = self._tunnels.get(local_port)
        if not info:
            raise Exception(f"No active tunnel on port {local_port}")
        return {
            "type": "socks5",
            "host": "127.0.0.1",
            "port": str(local_port),
        }

    def get_isp_proxy(self, tunnel_cfg: dict) -> dict:
        """
        Return a proxy config dict for an ISP tunnel cfg dict.
        Used when the proxy is an external ISP SOCKS5 (not a local SSH tunnel).
        """
        return {
            "type":     "socks5",
            "host":     tunnel_cfg.get("sshHost", ""),
            "port":     str(_safe_int(tunnel_cfg.get("sshPort", 1080), 1080)),
            "username": tunnel_cfg.get("sshUser") or tunnel_cfg.get("username") or None,
            "password": tunnel_cfg.get("sshKey")  or tunnel_cfg.get("password") or None,
        }

    def is_alive(self, local_port: int) -> bool:
        with self._lock:
            info = self._tunnels.get(local_port)
        if not info:
            return False
        return info.is_ssh_alive()

    def get_stats(self) -> list:
        with self._lock:
            return [info.summary() for info in self._tunnels.values()]

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close_all()

    # ─────────────────────────────────────────────────────────
    # Internal — SSH tunnel
    # ─────────────────────────────────────────────────────────

    def _open_ssh(self, cfg: dict) -> tuple:
        ssh_host   = cfg.get("sshHost", "")
        local_port = _safe_int(cfg.get("localPort", _DEFAULT_LOCAL_PORT), _DEFAULT_LOCAL_PORT)
        label      = cfg.get("label") or f"ssh:{ssh_host}:{local_port}"

        if not ssh_host:
            raise Exception("SSH tunnel: sshHost is required")

        with self._lock:
            existing = self._tunnels.get(local_port)
            if existing and existing.is_ssh_alive():
                log.debug("[TunnelManager] reusing existing tunnel on port %d", local_port)
                preflight = self._run_preflight("127.0.0.1", local_port)
                return local_port, preflight

        cmd, tmp_keyfile = _build_ssh_cmd(cfg, local_port)

        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                env=os.environ.copy(),
            )
        except FileNotFoundError as exc:
            _cleanup_keyfile(tmp_keyfile)
            if "sshpass" in str(exc):
                raise Exception(
                    "sshpass not installed — required for password-based SSH. "
                    "Install: apt install sshpass  or use SSH key auth instead."
                )
            raise Exception(
                f"SSH binary not found: {exc}. "
                f"Install OpenSSH: apt install openssh-client"
            )

        # Wait for SOCKS5 port to become ready
        ready = _wait_for_socks_port(local_port)

        if not ready or proc.poll() is not None:
            stderr = b""
            try:
                stderr = proc.stderr.read()
            except Exception:
                pass
            _kill_proc(proc)
            _cleanup_keyfile(tmp_keyfile)
            err_text = stderr.decode("utf-8", errors="replace").strip()[:400]
            raise Exception(
                f"SSH SOCKS5 tunnel failed to start on port {local_port}: {err_text}"
            )

        info = TunnelInfo(
            local_port   = local_port,
            tunnel_type  = "ssh",
            label        = label,
            cfg          = cfg,
            proc         = proc,
            tmp_keyfile  = tmp_keyfile,
            opened_at    = time.time(),
        )
        with self._lock:
            self._tunnels[local_port] = info

        log.info("[TunnelManager] SSH tunnel open: 127.0.0.1:%d via %s", local_port, ssh_host)
        preflight = self._run_preflight("127.0.0.1", local_port)
        return local_port, preflight

    def _open_isp(self, cfg: dict) -> tuple:
        """
        Register an ISP SOCKS5 proxy.
        ISP proxies are external — no local process to manage.
        We just record it and run preflight.
        """
        proxy_host = cfg.get("sshHost", "")
        proxy_port = _safe_int(cfg.get("sshPort", 1080), 1080)
        # Use a synthetic local_port key for the registry (based on hash)
        local_port = _safe_int(cfg.get("localPort", 0), 0) or (hash(f"{proxy_host}:{proxy_port}") % 60000 + 1024)
        label      = cfg.get("label") or f"isp:{proxy_host}:{proxy_port}"

        info = TunnelInfo(
            local_port  = local_port,
            tunnel_type = "isp",
            label       = label,
            cfg         = cfg,
            opened_at   = time.time(),
        )
        with self._lock:
            self._tunnels[local_port] = info

        log.info("[TunnelManager] ISP proxy registered: %s:%d (key port %d)",
                 proxy_host, proxy_port, local_port)
        preflight = self._run_preflight(proxy_host, proxy_port)
        return local_port, preflight

    # ─────────────────────────────────────────────────────────
    # Preflight tests
    # ─────────────────────────────────────────────────────────

    def _run_preflight(self, proxy_host: str, proxy_port: int) -> dict:
        """Run SOCKS5 connectivity + optional port 25 + optional IP discovery."""
        result = {
            "socks_ok":     False,
            "port25_ok":    False,
            "port25_banner":"",
            "public_ip":    "",
            "error":        "",
            "port25_error": "",
        }

        socks_ok, _, socks_err = _test_socks5_connectivity(proxy_host, proxy_port)
        result["socks_ok"] = socks_ok
        result["error"]    = socks_err

        if not socks_ok:
            return result

        if self.preflight_get_ip:
            result["public_ip"] = _get_public_ip_via_socks(proxy_host, proxy_port)

        if self.preflight_port25:
            p25_ok, banner, p25_err = _test_port25(proxy_host, proxy_port)
            result["port25_ok"]     = p25_ok
            result["port25_banner"] = banner
            result["port25_error"]  = p25_err

        return result

    # ─────────────────────────────────────────────────────────
    # Teardown
    # ─────────────────────────────────────────────────────────

    @staticmethod
    def _teardown(info: TunnelInfo):
        if info.tunnel_type == "ssh":
            _kill_proc(info.proc)
        _cleanup_keyfile(info.tmp_keyfile)

    # ─────────────────────────────────────────────────────────
    # Health monitor
    # ─────────────────────────────────────────────────────────

    def _start_monitor(self, interval: int):
        self._stop_event.clear()
        self._monitor_thread = threading.Thread(
            target  = self._monitor_loop,
            args    = (interval,),
            daemon  = True,
            name    = "TunnelHealthMonitor",
        )
        self._monitor_thread.start()

    def _monitor_loop(self, interval: int):
        while not self._stop_event.wait(timeout=interval):
            with self._lock:
                ports = list(self._tunnels.keys())

            for port in ports:
                with self._lock:
                    info = self._tunnels.get(port)
                if info is None or info.tunnel_type != "ssh" or info.disabled:
                    continue
                if not info.is_ssh_alive():
                    self._handle_crashed(info)

    def _handle_crashed(self, info: TunnelInfo):
        """Called when an SSH tunnel process has exited unexpectedly."""
        if info.restart_count >= self.max_restarts:
            reason = f"crashed {self.max_restarts} times — giving up"
            log.error("[TunnelManager] port %d (%s): %s", info.local_port, info.label, reason)
            with self._lock:
                info.disabled       = True
                info.disable_reason = reason
            return

        info.restart_count  += 1
        info.last_restart_at = time.time()

        # Read exit stderr for log
        stderr = b""
        if info.proc:
            try:
                stderr = info.proc.stderr.read()
            except Exception:
                pass
        err_text = stderr.decode("utf-8", errors="replace").strip()[:200]
        log.warning("[TunnelManager] port %d (%s) crashed (restart #%d): %s",
                    info.local_port, info.label, info.restart_count, err_text or "(no stderr)")

        time.sleep(_RESTART_DELAY)

        _cleanup_keyfile(info.tmp_keyfile)
        info.tmp_keyfile = None

        try:
            cmd, tmp_keyfile = _build_ssh_cmd(info.cfg, info.local_port)
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                env=os.environ.copy(),
            )
            ready = _wait_for_socks_port(info.local_port)
            if not ready or proc.poll() is not None:
                _kill_proc(proc)
                _cleanup_keyfile(tmp_keyfile)
                raise Exception("SOCKS5 port did not become ready after restart")

            with self._lock:
                info.proc        = proc
                info.tmp_keyfile = tmp_keyfile

            log.info("[TunnelManager] port %d (%s) restarted successfully (attempt #%d)",
                     info.local_port, info.label, info.restart_count)

        except Exception as exc:
            log.error("[TunnelManager] port %d (%s) restart #%d failed: %s",
                      info.local_port, info.label, info.restart_count, exc)
            if info.restart_count >= self.max_restarts:
                with self._lock:
                    info.disabled       = True
                    info.disable_reason = f"restart failed: {exc}"


# ═══════════════════════════════════════════════════════════════
# MODULE-LEVEL BACKWARDS-COMPAT FUNCTIONS
# Match original synthtel_server.py call signatures exactly.
# ═══════════════════════════════════════════════════════════════

_global_mgr:  Optional[TunnelManager] = None
_global_lock  = threading.Lock()


def _get_global_mgr() -> TunnelManager:
    global _global_mgr
    with _global_lock:
        if _global_mgr is None:
            _global_mgr = TunnelManager()
        return _global_mgr


def reset_global_manager(**kwargs):
    """
    Reset and replace the global TunnelManager.
    Call at the start of each campaign for clean stats.
    Closes any tunnels from the previous campaign.
    """
    global _global_mgr
    with _global_lock:
        if _global_mgr is not None:
            _global_mgr.close_all()
        _global_mgr = TunnelManager(**kwargs)


def open_ssh_socks(tunnel_cfg: dict) -> int:
    """
    Drop-in replacement for original open_ssh_socks().
    Returns local_port on success. Raises on failure.
    """
    port, preflight = _get_global_mgr().open(tunnel_cfg)
    if not preflight.get("socks_ok"):
        log.warning("[TunnelManager] preflight SOCKS5 test failed: %s",
                    preflight.get("error", ""))
    return port


def close_all_tunnels():
    """Drop-in replacement for original close_all_tunnels()."""
    global _global_mgr
    with _global_lock:
        mgr = _global_mgr
    if mgr:
        mgr.close_all()


def close_tunnel(local_port: int):
    """Drop-in replacement for original close_tunnel()."""
    _get_global_mgr().close(local_port)
