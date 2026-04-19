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
