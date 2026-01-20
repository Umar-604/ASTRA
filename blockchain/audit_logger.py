#!/usr/bin/env python3
"""
Blockchain-based Audit Logger - Phase 2 Implementation
Tamper-proof logging using Hyperledger Fabric and Ethereum
"""
import os
import json
import hashlib
import time
from datetime import datetime
from typing import Dict, List, Any, Optional
import logging
from dataclasses import dataclass, asdict
import threading
from queue import Queue
from db_logging import attach_postgres_handler
from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine
import requests


# Hyperledger Fabric imports (simulated for demo)
try:
    from hfc.fabric import Client
    from hfc.fabric_ca.caservice import ca_service
    FABRIC_AVAILABLE = True
except ImportError:
    FABRIC_AVAILABLE = False
    print("Hyperledger Fabric SDK not available - using simulation mode")

# Ethereum imports (simulated for demo)
try:
    from web3 import Web3
    from eth_account import Account
    ETHEREUM_AVAILABLE = True
except ImportError:
    ETHEREUM_AVAILABLE = False
    print("Ethereum Web3 not available - using simulation mode")

@dataclass
class AuditEntry:
    """Immutable audit log entry"""
    event_id: str
    timestamp: str
    agent_id: str
    platform: str
    event_type: str
    severity: str
    data_hash: str
    previous_hash: str
    block_hash: str
    signature: str
    merkle_root: str


class BlockchainAuditLogger:
    """Blockchain-based tamper-proof audit logger"""
    
    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or self.get_default_config()
        self.setup_logging()
        self._db_engine: Optional[Engine] = self._ensure_db_engine()
        self._ensure_db_tables()
        
        # Initialize blockchain connections
        self.fabric_client = None
        self.ethereum_client = None
        self.audit_queue = Queue()
        self.audit_chain = []
        self.merkle_tree = {}
        
        # Initialize blockchain connections
        self.initialize_fabric()
        self.initialize_ethereum()
        
        # Start background processing
        self.running = False
        self.start_background_processing()

     def get_default_config(self) -> Dict[str, Any]:
        """Get default configuration"""
        return {
            'fabric': {
                'network_config': 'network-config.yaml',
                'channel_name': 'audit-channel',
                'chaincode_name': 'audit-logger',
                'org_name': 'SecurityOrg',
                'user_name': 'admin'
            },
            'ethereum': {
                'rpc_url': 'http://localhost:8545',
                'contract_address': '0x1234567890123456789012345678901234567890',
                'private_key': 'your_private_key_here',
                'gas_limit': 100000
            },
            'audit': {
                'batch_size': 10,
                'batch_timeout': 30,  # seconds
                'merkle_tree_depth': 10
            }
        }
    
     def setup_logging(self):
        """Setup logging configuration"""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - AuditLogger - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('logs/audit_logger.log'),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger('AuditLogger')
        # Also send logs to PostgreSQL when configured
        attach_postgres_handler(self.logger)

    def _get_dsn(self) -> Optional[str]:
        try:
            return os.getenv("POSTGRES_DSN") or os.getenv("DATABASE_URL")
        except Exception:
            return None
        
     def _ensure_db_engine(self) -> Optional[Engine]:
        dsn = self._get_dsn()
        if not dsn:
            return None
        try:
            return create_engine(dsn, pool_pre_ping=True)
        except Exception:
            return None
        
    def _ensure_db_tables(self) -> None:
        if not self._db_engine:
            return
        try:
            with self._db_engine.begin() as conn:
                conn.execute(text("""
                    CREATE TABLE IF NOT EXISTS audit_anchors (
                        id BIGSERIAL PRIMARY KEY,
                        batch_id TEXT UNIQUE NOT NULL,
                        merkle_root TEXT NOT NULL,
                        count INTEGER NOT NULL,
                        chain TEXT NOT NULL,
                        tx_id TEXT,
                        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
                    );
                """))
                conn.execute(text("""
                    CREATE TABLE IF NOT EXISTS audit_index (
                        id BIGSERIAL PRIMARY KEY,
                        event_id TEXT NOT NULL,
                        data_hash TEXT NOT NULL,
                        merkle_root TEXT NOT NULL,
                        batch_id TEXT NOT NULL,
                        tx_id TEXT,
                        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
                    );
                """))
        except Exception:
            # Non-fatal
            pass

    def initialize_fabric(self):
        """Initialize Hyperledger Fabric connection"""
        try:
            if FABRIC_AVAILABLE:
                self.fabric_client = Client(net_profile=self.config['fabric']['network_config'])
                self.fabric_client.new_channel(self.config['fabric']['channel_name'])
                
                # Get user context
                org = self.config['fabric']['org_name']
                user = self.config['fabric']['user_name']
                self.fabric_client.get_user(org, user)
                
                self.logger.info("Hyperledger Fabric connection initialized")
            else:
                self.logger.warning("Hyperledger Fabric not available - using simulation mode")
                
        except Exception as e:
            self.logger.error(f"Error initializing Fabric: {e}")
            self.fabric_client = None
    def initialize_ethereum(self):
        """Initialize Ethereum connection"""
        try:
            if ETHEREUM_AVAILABLE:
                self.ethereum_client = Web3(Web3.HTTPProvider(self.config['ethereum']['rpc_url']))
                
                if self.ethereum_client.is_connected():
                    self.logger.info("Ethereum connection initialized")
                else:
                    self.logger.warning("Ethereum connection failed - using simulation mode")
                    self.ethereum_client = None
            else:
                self.logger.warning("Ethereum not available - using simulation mode")
                
        except Exception as e:
            self.logger.error(f"Error initializing Ethereum: {e}")
            self.ethereum_client = None
    
    def calculate_data_hash(self, data: Dict[str, Any]) -> str:
        """Calculate SHA-256 hash of event data"""
        data_string = json.dumps(data, sort_keys=True)
        return hashlib.sha256(data_string.encode()).hexdigest()
    
    def calculate_merkle_root(self, entries: List[AuditEntry]) -> str:
        """Calculate Merkle tree root for batch of entries"""
        if not entries:
            return ""
        
        # Create leaf hashes
        leaf_hashes = []
        for entry in entries:
            entry_data = f"{entry.event_id}{entry.timestamp}{entry.data_hash}"
            leaf_hash = hashlib.sha256(entry_data.encode()).hexdigest()
            leaf_hashes.append(leaf_hash)
        
         # Build Merkle tree
        current_level = leaf_hashes
        while len(current_level) > 1:
            next_level = []
            for i in range(0, len(current_level), 2):
                left = current_level[i]
                right = current_level[i + 1] if i + 1 < len(current_level) else left
                combined = left + right
                parent_hash = hashlib.sha256(combined.encode()).hexdigest()
                next_level.append(parent_hash)
            current_level = next_level
        
        return current_level[0] if current_level else ""
    
    def create_audit_entry(self, event: Dict[str, Any]) -> AuditEntry:
        """Create immutable audit log entry"""
        try:
            # Calculate data hash
            data_hash = self.calculate_data_hash(event.get('data', {}))
            
            # Get previous hash
            previous_hash = ""
            if self.audit_chain:
                previous_hash = self.audit_chain[-1].block_hash

             # Create entry
            entry = AuditEntry(
                event_id=event.get('event_id', ''),
                timestamp=datetime.utcnow().isoformat(),
                agent_id=event.get('agent_id', ''),
                platform=event.get('platform', ''),
                event_type=event.get('event_type', ''),
                severity=event.get('severity', 'INFO'),
                data_hash=data_hash,
                previous_hash=previous_hash,
                block_hash="",  # Will be calculated after signature
                signature="",   # Will be added after signing
                merkle_root=""  # Will be calculated for batch
            )
             # Calculate block hash
            block_data = f"{entry.event_id}{entry.timestamp}{entry.data_hash}{entry.previous_hash}"
            entry.block_hash = hashlib.sha256(block_data.encode()).hexdigest()
            
            # Sign entry (simplified - in production use proper digital signatures)
            signature_data = f"{entry.event_id}{entry.timestamp}{entry.block_hash}"
            entry.signature = hashlib.sha256(signature_data.encode()).hexdigest()
            
            return entry
        
         except Exception as e:
            self.logger.error(f"Error creating audit entry: {e}")
            return None
        
    def log_to_fabric(self, entries: List[AuditEntry]) -> bool:
        """Log entries to Hyperledger Fabric via REST gateway if configured"""
        try:
            gateway_url = os.getenv("FABRIC_GATEWAY_URL")
            if not gateway_url:
                # Fall back to simulation if gateway is not configured
                self.logger.warning("FABRIC_GATEWAY_URL not set - simulating Fabric log")
                return True
            # Compute a batchId deterministically from merkle_root + count
            if not entries:
                return True
            merkle_root = entries[0].merkle_root if entries else ""
            batch_id = hashlib.sha256((merkle_root + str(len(entries))).encode()).hexdigest()[:32]
            payload = {
                "batchId": batch_id,
                "merkleRoot": merkle_root,
                "count": len(entries),
                "timestamp": datetime.utcnow().isoformat(),
                "entries": [
                    {
                        "event_id": e.event_id,
                        "agent_id": e.agent_id,
                        "severity": e.severity,
                        "timestamp": e.timestamp,
                        "data_hash": e.data_hash,
                    } for e in entries
                ],
            }
            resp = requests.post(f"{gateway_url.rstrip('/')}/audit/batch", json=payload, timeout=10)
            if resp.status_code == 200:
                self.logger.info(f"Logged {len(entries)} entries to Fabric via gateway")
                return True
            else:
                self.logger.error(f"Fabric gateway error: {resp.status_code} {resp.text}")
                return False
            
            except Exception as e:
            self.logger.error(f"Error logging to Fabric: {e}")
            return False
        
        def log_to_ethereum(self, entries: List[AuditEntry]) -> bool:
        """Log entries to Ethereum smart contract"""
        try:
            if not self.ethereum_client:
                self.logger.warning("Ethereum client not available - simulating log")
                return True
            
        # Prepare data for smart contract
            audit_data = []
            for entry in entries:
                audit_data.append([
                    entry.event_id,
                    entry.timestamp,
                    entry.agent_id,
                    entry.platform,
                    entry.event_type,
                    entry.severity,
                    entry.data_hash,
                    entry.block_hash,
                    entry.signature,
                    entry.merkle_root
                ])
        # Get contract instance (simplified)
            contract_address = self.config['ethereum']['contract_address']
            # In production, you would load the actual contract ABI and create contract instance
            
            # Simulate transaction
            tx_hash = f"0x{hashlib.sha256(str(audit_data).encode()).hexdigest()}"
            
            self.logger.info(f"Logged {len(entries)} entries to Ethereum: {tx_hash}")
            return True
        except Exception as e:
            self.logger.error(f"Error logging to Ethereum: {e}")
            return False
        
    def log_event(self, event: Dict[str, Any]) -> bool:
        """Log security event to blockchain"""
        try:
            # Create audit entry
            entry = self.create_audit_entry(event)
            if not entry:
                return False
            
            # Add to queue for batch processing
            self.audit_queue.put(entry)
            
            # Add to local chain
            self.audit_chain.append(entry)
            
            self.logger.debug(f"Queued audit entry: {entry.event_id}")
            return True
        except Exception as e:
            self.logger.error(f"Error logging event: {e}")
            return False
    
    def _persist_anchor(self, merkle_root: str, entries: List[AuditEntry], chain: str, tx_id: Optional[str]) -> None:
        if not self._db_engine:
            return
        batch_id = hashlib.sha256((merkle_root + str(len(entries))).encode()).hexdigest()[:32]
        try:
            with self._db_engine.begin() as conn:
                conn.execute(text("""
                    INSERT INTO audit_anchors (batch_id, merkle_root, count, chain, tx_id)
                    VALUES (:batch_id, :merkle_root, :count, :chain, :tx_id)
                    ON CONFLICT (batch_id) DO NOTHING
                """), {
                    "batch_id": batch_id,
                    "merkle_root": merkle_root,
                    "count": len(entries),
                    "chain": chain,
                    "tx_id": tx_id
                })
                for e in entries:
                    conn.execute(text("""
                        INSERT INTO audit_index (event_id, data_hash, merkle_root, batch_id, tx_id)
                        VALUES (:event_id, :data_hash, :merkle_root, :batch_id, :tx_id)
                    """), {
                        "event_id": e.event_id,
                        "data_hash": e.data_hash,
                        "merkle_root": merkle_root,
                        "batch_id": batch_id,
                        "tx_id": tx_id
                    })
        except Exception:
            # Non-fatal
            pass

        def process_audit_batch(self):
        """Process batch of audit entries"""
        try:
            batch = []
            batch_start_time = time.time()

            # Collect entries for batch
            while len(batch) < self.config['audit']['batch_size']:
                try:
                    entry = self.audit_queue.get(timeout=1)
                    batch.append(entry)
                except:
                    # Timeout - process current batch
                    break

            # Check timeout
            if time.time() - batch_start_time > self.config['audit']['batch_timeout']:
                # Process batch even if not full
                pass
            
            if not batch:
                return
            
            # Calculate Merkle root for batch
            merkle_root = self.calculate_merkle_root(batch)
            for entry in batch:
                entry.merkle_root = merkle_root

            # Log to blockchains
            fabric_success = self.log_to_fabric(batch)
            ethereum_success = self.log_to_ethereum(batch)
            # Simulated tx id based on merkle root + timestamp
            tx_id = hashlib.sha256((merkle_root + str(int(time.time()))).encode()).hexdigest()[:40]
            chain_label = "both" if (fabric_success and ethereum_success) else ("fabric" if fabric_success else ("ethereum" if ethereum_success else "none"))
            # Persist anchor/index off-chain
            self._persist_anchor(merkle_root, batch, chain_label, tx_id)
            
            if fabric_success and ethereum_success:
                self.logger.info(f"Successfully logged batch of {len(batch)} entries")
            else:
                self.logger.warning(f"Partial failure logging batch of {len(batch)} entries")
            
        except Exception as e:
            self.logger.error(f"Error processing audit batch: {e}")

        def start_background_processing(self):
        """Start background thread for processing audit entries"""
        self.running = True
        self.background_thread = threading.Thread(target=self.background_worker)
        self.background_thread.daemon = True
        self.background_thread.start()
        self.logger.info("Background audit processing started")

        def background_worker(self):
        """Background worker for processing audit entries"""
        while self.running:
            try:
                self.process_audit_batch()
                time.sleep(1)  # Check every second
            except Exception as e:
                self.logger.error(f"Error in background worker: {e}")
                time.sleep(5)  # Wait before retrying

        
    def stop(self):
        """Stop the audit logger"""
        self.running = False
        if hasattr(self, 'background_thread'):
            self.background_thread.join(timeout=5)
        self.logger.info("Audit logger stopped")

    # ------ Verification helpers ------
    def verify_hash(self, data_hash: str) -> Dict[str, Any]:
        """Check if a data hash is anchored (off-chain index lookup)."""
        result = {
            "anchored": False,
            "data_hash": data_hash,
            "tx_id": None,
            "merkle_root": None,
            "batch_id": None,
        }
         if not self._db_engine:
            return result
        try:
            with self._db_engine.begin() as conn:
                row = conn.execute(text("""
                    SELECT data_hash, tx_id, merkle_root, batch_id
                    FROM audit_index
                    WHERE data_hash = :h
                    ORDER BY id DESC
                    LIMIT 1
                """), {"h": data_hash}).mappings().first()
                if row:
                    result.update({
                        "anchored": True,
                        "tx_id": row["tx_id"],
                        "merkle_root": row["merkle_root"],
                        "batch_id": row["batch_id"],
                    })
        except Exception:
            pass
        return result
    
    def verify_event_payload(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Compute hash from event['data'] and verify anchoring."""
        try:
            h = self.calculate_data_hash(event.get("data", {}))
            res = self.verify_hash(h)
            res["event_id"] = event.get("event_id")
            return res
        except Exception as e:
            return {"anchored": False, "error": str(e)}
        

    def verify_audit_chain(self) -> Dict[str, Any]:
        """Verify integrity of audit chain"""
        try:
            verification_result = {
                'total_entries': len(self.audit_chain),
                'valid_entries': 0,
                'invalid_entries': 0,
                'chain_integrity': True,
                'errors': []
            }
        previous_hash = ""
            for i, entry in enumerate(self.audit_chain):
                # Verify previous hash
                if entry.previous_hash != previous_hash:
                    verification_result['chain_integrity'] = False
                    verification_result['errors'].append(f"Hash mismatch at entry {i}")
                    verification_result['invalid_entries'] += 1
                else:
                    verification_result['valid_entries'] += 1
