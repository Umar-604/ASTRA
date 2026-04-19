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
    @staticmethod
    def _playbook_actions(playbook: str, event: Dict[str, Any]) -> List[Tuple[str, Dict[str, Any]]]:
        payload = {
            "pid": event.get("pid"),
            "file_path": event.get("file_path"),
            "ip_address": event.get("ip_address"),
            "user": event.get("user"),
            "file_hash": event.get("file_hash"),
            "event": event,
        }

        if playbook == "ransomware":
            return [
                ("kill_process", payload),
                ("quarantine_file", payload),
                ("block_file_hash", payload),
                ("isolate_host", payload),
                ("collect_forensics", payload),
            ]
        return [
            ("block_ip", payload),
            ("terminate_connection", payload),
            ("kill_process", payload),
            ("lock_user", payload),
            ("force_logout", payload),
            ("collect_forensics", payload),
        ]

class ResponseEngine:
    """
    Automated response orchestrator.
    - Action execution and rollback hooks are separated from decision logic.
    - AUTO_RESPONSE=False logs recommendations without executing side effects.
    """

    def __init__(self, config: Optional[EngineConfig] = None):
        self.config = config or EngineConfig.from_env()
        # Local dev often uses self-signed certs for gateway HTTPS.
        if not self.config.blockchain_verify_tls:
            urllib3.disable_warnings(InsecureRequestWarning)
        self.decision_engine = DecisionEngine()
        self._rollback_handlers: Dict[str, Callable[[Dict[str, Any]], Dict[str, Any]]] = {
            "unblock_ip": self.unblock_ip,
            "restore_file": self.restore_file,
            "resume_process": self.resume_process,
            "unisolate_host": self.unisolate_host,
        }

        self._action_handlers: Dict[str, Callable[[Dict[str, Any]], Dict[str, Any]]] = {
            "log_only": self.log_only,
            "alert_monitor": self.alert_monitor,
            "kill_process": self.kill_process,
            "suspend_process": self.suspend_process,
            "quarantine_file": self.quarantine_file,
            "delete_file": self.delete_file,
            "block_ip": self.block_ip,
            "terminate_connection": self.terminate_connection,
            "isolate_host": self.isolate_host,
            "unisolate_host": self.unisolate_host,
            "lock_user": self.lock_user,
            "force_logout": self.force_logout,
            "block_file_hash": self.block_file_hash,
            "collect_forensics": self.collect_forensics,
        }

        Path(self.config.quarantine_dir).mkdir(parents=True, exist_ok=True)
        Path(self.config.action_log_path).parent.mkdir(parents=True, exist_ok=True)
        Path(self.config.history_path).parent.mkdir(parents=True, exist_ok=True)
        Path(self.config.blocked_hashes_path).parent.mkdir(parents=True, exist_ok=True)
    
    # ---------- Remote-target dispatch helpers (Option A) ----------
    _HOST_PLATFORM_NORMALIZED = {
        "linux": "linux",
        "darwin": "darwin",
        "windows": "windows",
        "windows_nt": "windows",
    }

    def _is_remote_target(self, payload: Dict[str, Any]) -> bool:
        """Return True when the originating event is from a different platform than this engine host.

        Example: engine on macOS, event from Windows agent -> remote target.
        When True, endpoint-bound actions must be dispatched to the agent via NATS
        rather than executed server-side (where the PID/file_path/firewall rules do not exist).
        """

        ev = payload.get("event") or {}
        target = str(ev.get("platform") or "").strip().lower()
        if not target:
            return False
        host = platform.system().strip().lower()
        host_norm = self._HOST_PLATFORM_NORMALIZED.get(host, host)
        target_norm = self._HOST_PLATFORM_NORMALIZED.get(target, target)
        return target_norm != host_norm

    def _dispatch_to_endpoint(
        self,
        action: str,
        payload: Dict[str, Any],
        required: Dict[str, str],
        rollback_action: Optional[str] = None,
        extra: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        
        """Build a `dispatched` result for endpoint-bound actions.

        required: {friendly_name: payload_key} used for missing-field validation.
                 Error messages preserve the existing strings so the
                 `skipped_not_applicable` post-filter in process_event keeps working
                 (e.g. "pid is required", "file_path is required", "invalid ip",
                 "user required", "file_hash required").
        """
        err_msg_map = {
            "pid": "pid is required",
            "file_path": "file_path is required",
            "ip_address": "invalid ip",
            "user": "user required",
            "file_hash": "file_hash required",
        }

        for _, key in required.items():
            value = payload.get(key)
            if value in (None, "") or (isinstance(value, str) and not value.strip()):
                return {"status": "error", "error": err_msg_map.get(key, f"{key} required")}

        command_payload = {k: payload.get(k) for k in required.values()}
        result: Dict[str, Any] = {
            "status": "dispatched",
            "target": "endpoint_agent",
            "action": action,
            "payload": command_payload,
            "message": f"{action} dispatched to endpoint agent via NATS",
        }

        if rollback_action:
            result["rollback_action"] = rollback_action
            result["rollback_payload"] = command_payload
        if extra:
            result.update(extra)
        return result
    
    def process_event(self, event: Dict[str, Any]) -> Dict[str, Any]:
        event_id = str(event.get("event_id") or f"evt-{int(datetime.now().timestamp())}")
        event["event_id"] = event_id
        actions, rule = self.decision_engine.decide(event)
        outputs: List[Dict[str, Any]] = []
        triggered_by = str(event.get("triggered_by") or "AI")

        skip_reason = self._should_skip_due_to_whitelist(event)
        if skip_reason:
            rec = self._record(event_id, "log_only", "skipped", {"reason": skip_reason}, triggered_by=triggered_by)
            outputs.append(rec.__dict__)
            chain_status = self.log_to_blockchain(event, outputs, event_id)
            outputs.append(chain_status)
            return {
                "event_id": event_id,
                "decision_rule": f"whitelist:{skip_reason}",
                "confidence": _normalize_confidence(event.get("confidence")),
                "actions": outputs,
            }
        
        for action_name, payload in actions:
            payload = {**payload, "event_id": event_id}
            if action_name == "suspend_process" and not self.config.suspend_in_medium_band:
                continue
            if self.config.dry_run and action_name not in {"log_only", "alert_monitor"}:
                rec = self._record(
                    event_id,
                    action_name,
                    "simulated",
                    {"reason": "dry-run mode", "payload": payload},
                    triggered_by=triggered_by,
                )
                outputs.append(rec.__dict__)
                continue
            if self.config.manual_approval and not bool(event.get("manual_approved")) and action_name not in {"log_only", "alert_monitor"}:
                rec = self._record(
                    event_id,
                    action_name,
                    "pending_approval",
                    {"reason": "manual approval required"},
                    triggered_by=triggered_by,
                )

                outputs.append(rec.__dict__)
                continue
            if not self.config.auto_response and action_name not in {"log_only", "alert_monitor"}:
                rec = self._record(
                    event_id,
                    action_name,
                    "recommended",
                    {"reason": "AUTO_RESPONSE disabled"},
                    triggered_by=triggered_by,
                )

                outputs.append(rec.__dict__)
                continue
            handler = self._action_handlers.get(action_name)
            if not handler:
                rec = self._record(event_id, action_name, "error", {"error": "unknown action"}, triggered_by=triggered_by)
                outputs.append(rec.__dict__)
                continue

            try:
                result = handler(payload)
                # Missing/non-applicable input should be visible but not treated as hard execution failure.
                status = result.get("status", "ok")
                err = str(result.get("error") or "").strip().lower()
                if status == "error":

                    missing_map = {
                        "kill_process": (payload.get("pid") is None, {"pid is required"}),
                        "suspend_process": (payload.get("pid") is None, {"pid is required"}),
                        "quarantine_file": (not payload.get("file_path"), {"file_path is required"}),
                        "delete_file": (not payload.get("file_path"), {"file_path is required"}),
                        "block_ip": (not payload.get("ip_address"), {"invalid ip"}),
                        "terminate_connection": (not payload.get("ip_address"), {"invalid ip"}),
                        "block_file_hash": (not payload.get("file_hash"), {"file_hash required"}),
                        "lock_user": (not payload.get("user"), {"user required"}),
                        "force_logout": (not payload.get("user"), {"user required"}),
                    }

                    check = missing_map.get(action_name)
                    if check and check[0] and err in check[1]:
                        status = "skipped_not_applicable"
                rec = self._record(
                    event_id,
                    action_name,
                    status,
                    result,
                    rollback_action=result.get("rollback_action"),
                    rollback_payload=result.get("rollback_payload"),
                    triggered_by=triggered_by,
                )

                except Exception as exc:  # defensive catch
                rec = self._record(event_id, action_name, "error", {"error": str(exc)}, triggered_by=triggered_by)
            outputs.append(rec.__dict__)

            chain_status = self.log_to_blockchain(event, outputs, event_id)
        outputs.append(chain_status)
        return {
            "event_id": event_id,
            "decision_rule": rule,
            "confidence": _normalize_confidence(event.get("confidence")),
            "actions": outputs,
        }
    
    async def process_event_async(self, event: Dict[str, Any]) -> Dict[str, Any]:
        return await asyncio.to_thread(self.process_event, event)

    # ---------- Action implementations ----------
    def log_only(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        return {"status": "ok", "message": "logged only"}

    def alert_monitor(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        return {"status": "ok", "message": "alert generated and monitoring elevated"}

    def kill_process(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        if self._is_remote_target(payload):
            return self._dispatch_to_endpoint("kill_process", payload, {"pid": "pid"})
        pid = self._require_int(payload.get("pid"), "pid")
        if psutil is None:
            return {"status": "error", "error": "psutil not available"}
        try:
            proc = psutil.Process(pid)
            proc.kill()
            return {"status": "ok", "pid": pid}
        except psutil.NoSuchProcess:
            return {"status": "error", "error": "process not found", "pid": pid}
        except psutil.AccessDenied:
            return {"status": "error", "error": "permission denied", "pid": pid}

    def suspend_process(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        if self._is_remote_target(payload):
            return self._dispatch_to_endpoint(
                "suspend_process", payload, {"pid": "pid"}, rollback_action="resume_process"
            )
        pid = self._require_int(payload.get("pid"), "pid")
        if psutil is None:
            return {"status": "error", "error": "psutil not available"}
        try:
            proc = psutil.Process(pid)
            proc.suspend()
            return {"status": "ok", "pid": pid, "rollback_action": "resume_process", "rollback_payload": {"pid": pid}}
        except psutil.NoSuchProcess:
            return {"status": "error", "error": "process not found", "pid": pid}
        except psutil.AccessDenied:
            return {"status": "error", "error": "permission denied", "pid": pid}

    def resume_process(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        pid = self._require_int(payload.get("pid"), "pid")
        if psutil is None:
            return {"status": "error", "error": "psutil not available"}
        try:
            psutil.Process(pid).resume()
            return {"status": "ok", "pid": pid}
        except Exception as exc:
            return {"status": "error", "error": str(exc), "pid": pid}

    def quarantine_file(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        if self._is_remote_target(payload):
            return self._dispatch_to_endpoint(
                "quarantine_file",
                payload,
                {"file_path": "file_path"},
                rollback_action="restore_file",
            )
        file_path = self._require_path(payload.get("file_path"))
        src = Path(file_path)
        if not src.exists():
            return {"status": "error", "error": "file not found", "file_path": str(src)}
        qname = f"{datetime.now().strftime('%Y%m%d%H%M%S')}_{src.name}"
        dst = Path(self.config.quarantine_dir) / qname
        try:
            shutil.move(str(src), str(dst))
            return {
                "status": "ok",
                "file_path": str(src),
                "quarantine_path": str(dst),
                "rollback_action": "restore_file",
                "rollback_payload": {"from_path": str(dst), "to_path": str(src)},
            }
        except PermissionError:
            return {"status": "error", "error": "permission denied", "file_path": str(src)}

    def restore_file(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        src = Path(self._require_path(payload.get("from_path")))
        dst = Path(self._require_path(payload.get("to_path")))
        if not src.exists():
            return {"status": "error", "error": "quarantined file missing", "from_path": str(src)}
        try:
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.move(str(src), str(dst))
            return {"status": "ok", "from_path": str(src), "to_path": str(dst)}
        except Exception as exc:
            return {"status": "error", "error": str(exc)}

    def delete_file(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        if self._is_remote_target(payload):
            return self._dispatch_to_endpoint("delete_file", payload, {"file_path": "file_path"})
        file_path = self._require_path(payload.get("file_path"))
        p = Path(file_path)
        if not p.exists():
            eturn {"status": "error", "error": "file not found", "file_path": str(p)}
        try:
            p.unlink()
            return {"status": "ok", "file_path": str(p)}
        except PermissionError:
            return {"status": "error", "error": "permission denied", "file_path": str(p)}

    def block_file_hash(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        file_hash = str(payload.get("file_hash") or "").strip().lower()
        if not file_hash:
            return {"status": "error", "error": "file_hash required"}
        if file_hash in self.config.trusted_hashes:
            return {"status": "skipped", "reason": "trusted hash", "file_hash": file_hash}
        path = Path(self.config.blocked_hashes_path)
        existing = set()
        if path.exists():
            existing = {ln.strip().lower() for ln in path.read_text(encoding="utf-8").splitlines() if ln.strip()}
        if file_hash not in existing:
            with path.open("a", encoding="utf-8") as f:
                f.write(file_hash + "\n")
        return {"status": "ok", "file_hash": file_hash, "blocked_hashes_path": str(path)}

    def block_ip(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        if self._is_remote_target(payload):
            return self._dispatch_to_endpoint(
                "block_ip", payload, {"ip_address": "ip_address"}, rollback_action="unblock_ip"
            )
        ip_address = str(payload.get("ip_address") or "").strip()
        if not ip_address:
            return {"status": "error", "error": "invalid ip"}
        cmd = self._firewall_block_command(ip_address)
        return {
            "status": "ok" if cmd else "error",
            "ip_address": ip_address,
            "command": cmd,
            "rollback_action": "unblock_ip" if cmd else None,
            "rollback_payload": {"ip_address": ip_address} if cmd else None,
            "message": "command prepared/executed" if cmd else "unsupported OS for firewall block",
        }
    def terminate_connection(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        if self._is_remote_target(payload):
            return self._dispatch_to_endpoint("terminate_connection", payload, {"ip_address": "ip_address"})
        ip_address = str(payload.get("ip_address") or "").strip()
        if not ip_address:
            return {"status": "error", "error": "invalid ip"}
        system = platform.system().lower()
        if system in {"linux", "darwin"}:
            cmd = f"pkill -f {ip_address}"
        elif system == "windows":
            cmd = f'netstat -ano | findstr "{ip_address}"'
        else:
            cmd = None
        return {
            "status": "ok" if cmd else "error",
            "ip_address": ip_address,
            "command": cmd,
            "message": "connection termination command prepared" if cmd else "unsupported OS",
        }
    
    def unblock_ip(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        ip_address = str(payload.get("ip_address") or "").strip()
        if not ip_address:
            return {"status": "error", "error": "invalid ip"}
        cmd = self._firewall_unblock_command(ip_address)
        return {"status": "ok" if cmd else "error", "ip_address": ip_address, "command": cmd}

    def isolate_host(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        if self._is_remote_target(payload):
            return self._dispatch_to_endpoint(
                "isolate_host", payload, {}, rollback_action="unisolate_host"
            )
        # Production implementations usually integrate with EDR/MDM APIs.
        system = platform.system().lower()
        if system == "linux":
            cmd = "iptables -P OUTPUT DROP && iptables -P INPUT DROP"
        elif system == "darwin":
            cmd = "pfctl -e && pfctl -f /etc/pf.conf"
        elif system == "windows":
            cmd = "netsh advfirewall set allprofiles state on"
        else:
            cmd = None
        return {
            "status": "ok" if cmd else "error",
            "command": cmd,
            "rollback_action": "unisolate_host" if cmd else None,
            "rollback_payload": {},
            "message": "host isolation command prepared" if cmd else "unsupported OS",
        }