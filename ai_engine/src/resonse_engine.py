from __future__ import annotations

import asyncio
import hashlib
import json
import os
import platform
import shutil
import socket
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

import requests
import urllib3
from urllib3.exceptions import InsecureRequestWarning

try:
    import psutil
except Exception:  # pragma: no cover - optional in some environments
    psutil = None  # type: ignore


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _normalize_confidence(value: float | int | None) -> float:
    """Normalize confidence to 0..100 (accepts 0..1 or 0..100 inputs)."""
    if value is None:
        return 0.0
    v = float(value)
    if v <= 1.0:
        return max(0.0, min(v * 100.0, 100.0))
    return max(0.0, min(v, 100.0))

def _extract_hosts_from_url(raw: str) -> Set[str]:
    """Pull hostname tokens out of a URL or `host:port` string."""
    candidates: Set[str] = set()
    s = raw.strip()
    if not s:
        return candidates
    try:
        from urllib.parse import urlparse  # local import keeps top tidy

        if "://" not in s:
            s = "http://" + s
        parsed = urlparse(s)
        host = (parsed.hostname or "").strip()
        if host:
            candidates.add(host)
    except Exception:
        pass
    return candidates

def _resolve_to_ips(host: str) -> Set[str]:
    """Resolve a hostname to its IPv4/IPv6 literals plus echo the host itself.

    DNS failure is non-fatal — we simply return the literal so downstream
    string-comparison whitelisting still works for IPs given as IPs.
    """
    out: Set[str] = {host}
    try:
        infos = socket.getaddrinfo(host, None)
        for info in infos:
            ip = info[4][0]
            if ip:
                out.add(ip)

    except Exception:
        pass
    return out


@dataclass
class ActionRecord:
    timestamp: str
    event_id: str
    action: str
    status: str
    details: Dict[str, Any] = field(default_factory=dict)
    rollback_action: Optional[str] = None
    rollback_payload: Optional[Dict[str, Any]] = None


@dataclass
class EngineConfig:
    auto_response: bool = True
    manual_approval: bool = False
    dry_run: bool = False
    action_log_path: str = "logs/auto_response_actions.jsonl"
    history_path: str = "logs/auto_response_history.jsonl"
    quarantine_dir: str = "quarantine"
    blocked_hashes_path: str = "logs/blocked_hashes.txt"
    blockchain_api_url: Optional[str] = None
    blockchain_verify_tls: bool = False
    suspend_in_medium_band: bool = True
    request_timeout_sec: int = 5
    trusted_processes: Set[str] = field(default_factory=set)
    trusted_ips: Set[str] = field(default_factory=set)
    trusted_hashes: Set[str] = field(default_factory=set)
    @classmethod
    def from_env(cls) -> "EngineConfig":
        auto = str(os.getenv("AUTO_RESPONSE", "true")).strip().lower() in {"1", "true", "yes", "on"}
        manual = str(os.getenv("MANUAL_APPROVAL_MODE", "false")).strip().lower() in {"1", "true", "yes", "on"}
        dry_run = str(os.getenv("AUTO_RESPONSE_DRY_RUN", "false")).strip().lower() in {"1", "true", "yes", "on"}
        chain = os.getenv("BLOCKCHAIN_HASH_API_URL")
        if not chain:
            base = os.getenv("FABRIC_GATEWAY_URL", "https://127.0.0.1:8081").rstrip("/")
            chain = f"{base}/audit/hash" if base else None
        verify_tls = str(os.getenv("BLOCKCHAIN_HASH_API_VERIFY_TLS", "false")).strip().lower() in {"1", "true", "yes", "on"}

        trusted_ips = {p.strip() for p in str(os.getenv("RESPONSE_TRUSTED_IPS", "")).split(",") if p.strip()}
        trusted_processes = {
            p.strip().lower() for p in str(os.getenv("RESPONSE_TRUSTED_PROCESSES", "")).split(",") if p.strip()
        }

        # Auto-trust the agent's gateway endpoints. Without this, every agent
        # heartbeat / event POST appears as a "suspicious outbound connection",
        # the engine fires `block_ip` / `terminate_connection`, and the agent
        # is told to sever its own control channel. Operators can extend this
        # list via RESPONSE_GATEWAY_HOSTS=<comma-separated host or ip list>.
        gateway_candidates: Set[str] = set()

        for env_var in ("ASTRA_GATEWAY", "ASTRA_SERVER", "GATEWAY_URL"):
            raw = os.getenv(env_var, "").strip()
            if raw:
                gateway_candidates.update(_extract_hosts_from_url(raw))
        for raw in str(os.getenv("RESPONSE_GATEWAY_HOSTS", "")).split(","):
            host = raw.strip()
            if host:
                gateway_candidates.add(host)
        for host in gateway_candidates:
            trusted_ips.update(_resolve_to_ips(host))


        # Same logic for the EDR agent's own process name/path — the engine
        # must not order the agent to kill itself even if its beacon thread
        # crosses a behavioural threshold.
        for env_var in ("RESPONSE_PROTECTED_AGENT_PROCESSES", "EDR_AGENT_PROCESS_NAMES"):
            for proc in str(os.getenv(env_var, "")).split(","):
                p = proc.strip().lower()
                if p:
                    trusted_processes.add(p)


                    # Sensible defaults: the standard ASTRA agent entry-points AND the
        # second-order signatures of response actions the agent itself
        # executes. Without these patterns the engine will see the cmd.exe
        # subprocess the agent ran for `lock_user` / `block_ip` / `isolate_host`
        # and flag it as malicious, dispatching another wave of responses.
        trusted_processes.update({
            "win_agent.py", "linux_agent.py", "mac_agent.py", "win_agent_v2.py",
            # Response-action command signatures (substring-matched against
            # process command_line in _should_skip_due_to_whitelist).
            "net user ", "net.exe user ",                # lock_user (windows)
            "logoff ",                                    # force_logout (windows)
            "shutdown /l", "shutdown -l",                 # force_logout alternates
            "netsh advfirewall firewall add rule name=\"astra_block_",  # block_ip
            "netsh advfirewall firewall delete rule name=\"astra_block_",
            "netsh advfirewall set allprofiles state on", # isolate_host (windows)
            "iptables -a input -s",                       # block_ip (linux)
            "iptables -d input -s",
            "echo 'block drop from",                      # block_ip (macos pfctl)
            "pfctl -ef -",                                # isolate_host (macos)
        })

        return cls(
            auto_response=auto,
            manual_approval=manual,
            dry_run=dry_run,
            action_log_path=os.getenv("AUTO_RESPONSE_LOG_PATH", "logs/auto_response_actions.jsonl"),
            history_path=os.getenv("AUTO_RESPONSE_HISTORY_PATH", "logs/auto_response_history.jsonl"),
            quarantine_dir=os.getenv("QUARANTINE_DIR", "quarantine"),
            blocked_hashes_path=os.getenv("BLOCKED_HASHES_PATH", "logs/blocked_hashes.txt"),
            blockchain_api_url=chain,
            blockchain_verify_tls=verify_tls,
            suspend_in_medium_band=str(os.getenv("SUSPEND_IN_MEDIUM_BAND", "true")).lower() in {"1", "true", "yes", "on"},
            request_timeout_sec=int(os.getenv("AUTO_RESPONSE_HTTP_TIMEOUT", "5")),
            trusted_processes=trusted_processes,
            trusted_ips=trusted_ips,
            trusted_hashes={
                p.strip().lower() for p in str(os.getenv("RESPONSE_TRUSTED_HASHES", "")).split(",") if p.strip()
            },
        )
    
class DecisionEngine:
    """Pure decision logic. No side-effects here."""

    def decide(self, event: Dict[str, Any]) -> Tuple[List[Tuple[str, Dict[str, Any]]], str]:
        confidence = _normalize_confidence(event.get("confidence"))
        playbook = (event.get("playbook") or "").strip().lower()
        severity = str(event.get("severity") or "").strip().lower()
        event_source = str(event.get("event_source") or event.get("source") or "").strip().lower()
        telemetry_incomplete = bool(
            event.get("telemetry_incomplete")
            or event.get("incomplete_telemetry")
            or event.get("missing_telemetry")
        )
        if playbook in {"ransomware", "reverse_shell"}:
            return self._playbook_actions(playbook, event), f"playbook:{playbook}"

        payload: Dict[str, Any] = {
            "pid": event.get("pid"),
            "file_path": event.get("file_path"),
            "ip_address": event.get("ip_address"),
            "user": event.get("user"),
            "file_hash": event.get("file_hash"),
            "event": event,
        }

        # Registry monitor with missing telemetry should be less aggressive.
        if event_source == "registry_monitor" and telemetry_incomplete:
            confidence = max(0.0, confidence - 20.0)

        if confidence < 60:
            return [("log_only", payload)], "confidence<60"
        
        if confidence <= 80:
            actions: List[Tuple[str, Dict[str, Any]]] = [("alert_monitor", payload)]
            if event.get("pid") is not None:
                actions.append(("suspend_process", payload))
            return actions, "60<=confidence<=80"
        if confidence <= 95:
            return [
                ("kill_process", payload),
                ("quarantine_file", payload),
                ("block_ip", payload),
                ("terminate_connection", payload),
                ("collect_forensics", payload),
            ], "80<confidence<=95"
        
        if severity == "critical":
            return self._full_response_actions(payload), "severity==critical"
        return self._full_response_actions(payload), "confidence>95"

        @staticmethod
    def _full_response_actions(payload: Dict[str, Any]) -> List[Tuple[str, Dict[str, Any]]]:
        return [
            ("isolate_host", payload),
            ("kill_process", payload),
            ("quarantine_file", payload),
            ("block_ip", payload),
            ("terminate_connection", payload),
            ("block_file_hash", payload),
            ("lock_user", payload),
            ("force_logout", payload),
            ("collect_forensics", payload),
        ]