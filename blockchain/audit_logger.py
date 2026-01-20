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