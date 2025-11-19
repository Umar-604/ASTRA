# agents/network_agent.py - Network Monitoring Agent with Zeek and Suricata
import requests, os, time, json, subprocess, threading, logging
from jose import jwt
from datetime import datetime
from base_agent import BaseEDRAgent

class NetworkEDRAgent(BaseEDRAgent):
    """Network monitoring agent using Zeek and Suricata"""
    
    def __init__(self, agent_id="network_agent"):
        super().__init__(agent_id, "network")
        self.zeek_config_path = os.path.join(os.path.dirname(__file__), "configs", "zeek-config.zeek")
        self.suricata_config_path = os.path.join(os.path.dirname(__file__), "configs", "suricata.yaml")
        self.zeek_log_path = "/opt/zeek/logs"
        self.suricata_log_path = "/var/log/suricata"
        self.monitoring_threads = []
    
    def install_zeek(self):
        """Install and configure Zeek with ASTRA configuration"""
        try:
            # Check if Zeek is installed
            result = subprocess.run(['which', 'zeek'], capture_output=True, text=True)
            if result.returncode == 0:
                self.logger.info("Zeek is already installed")
            else:
                self.logger.info("Installing Zeek...")
                # Install Zeek (requires sudo)
                subprocess.run(['sudo', 'apt-get', 'update'], check=True)
                subprocess.run(['sudo', 'apt-get', 'install', '-y', 'zeek'], check=True)
                self.logger.info("Zeek installed successfully")
            
            # Apply ASTRA configuration
            if os.path.exists(self.zeek_config_path):
                subprocess.run(['sudo', 'cp', self.zeek_config_path, '/opt/zeek/share/zeek/site/astra-config.zeek'], check=True)
                self.logger.info("ASTRA Zeek configuration applied")
            else:
                self.logger.warning(f"Zeek config not found at {self.zeek_config_path}")
                
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Failed to install/configure Zeek: {e}")
        except Exception as e:
            self.logger.error(f"Error with Zeek setup: {e}")
    
    def install_suricata(self):
        """Install and configure Suricata with ASTRA configuration"""
        try:
            # Check if Suricata is installed
            result = subprocess.run(['which', 'suricata'], capture_output=True, text=True)
            if result.returncode == 0:
                self.logger.info("Suricata is already installed")
            else:
                self.logger.info("Installing Suricata...")
                # Install Suricata (requires sudo)
                subprocess.run(['sudo', 'apt-get', 'update'], check=True)
                subprocess.run(['sudo', 'apt-get', 'install', '-y', 'suricata'], check=True)
                self.logger.info("Suricata installed successfully")
            
            # Apply ASTRA configuration
            if os.path.exists(self.suricata_config_path):
                subprocess.run(['sudo', 'cp', self.suricata_config_path, '/etc/suricata/suricata.yaml'], check=True)
                subprocess.run(['sudo', 'systemctl', 'restart', 'suricata'], check=True)
                self.logger.info("ASTRA Suricata configuration applied")
            else:
                self.logger.warning(f"Suricata config not found at {self.suricata_config_path}")
                
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Failed to install/configure Suricata: {e}")
        except Exception as e:
            self.logger.error(f"Error with Suricata setup: {e}")
    
    def collect_zeek_events(self):
        """Collect network events from Zeek logs"""
        try:
            if not os.path.exists(self.zeek_log_path):
                self.logger.warning(f"Zeek log directory not found: {self.zeek_log_path}")
                return
            
            # Read Zeek connection logs
            conn_log = os.path.join(self.zeek_log_path, "current", "conn.log")
            if os.path.exists(conn_log):
                with open(conn_log, 'r') as f:
                    for line in f:
                        if line.startswith('#'):
                            continue
                        
                        # Parse Zeek log entry
                        fields = line.strip().split('\t')
                        if len(fields) >= 10:
                            event = {
                                "timestamp": fields[0],
                                "connection_id": fields[1],
                                "src_ip": fields[2],
                                "src_port": fields[3],
                                "dst_ip": fields[4],
                                "dst_port": fields[5],
                                "protocol": fields[6],
                                "duration": fields[8],
                                "orig_bytes": fields[9],
                                "resp_bytes": fields[10] if len(fields) > 10 else 0,
                                "event_type": "network_connection",
                                "source": "zeek"
                            }
                            
                            # Map to MITRE ATT&CK tactics
                            tactic = self.map_network_to_tactic(event)
                            self.create_event("network_connection", event, "INFO", tactic)
                            
        except Exception as e:
            self.logger.error(f"Error collecting Zeek events: {e}")
    
    def collect_suricata_events(self):
        """Collect alerts from Suricata"""
        try:
            eve_log = os.path.join(self.suricata_log_path, "eve.json")
            if not os.path.exists(eve_log):
                self.logger.warning(f"Suricata eve.json not found: {eve_log}")
                return
            
            with open(eve_log, 'r') as f:
                for line in f:
                    try:
                        alert = json.loads(line.strip())
                        if alert.get('event_type') == 'alert':
                            event = {
                                "timestamp": alert.get('timestamp'),
                                "alert": alert.get('alert', {}),
                                "src_ip": alert.get('src_ip'),
                                "src_port": alert.get('src_port'),
                                "dst_ip": alert.get('dest_ip'),
                                "dst_port": alert.get('dest_port'),
                                "protocol": alert.get('proto'),
                                "signature": alert.get('alert', {}).get('signature'),
                                "category": alert.get('alert', {}).get('category'),
                                "severity": alert.get('alert', {}).get('severity'),
                                "event_type": "suricata_alert",
                                "source": "suricata"
                            }
                            
                            # Map to MITRE ATT&CK tactics
                            tactic = self.map_suricata_to_tactic(event)
                            severity = self.map_suricata_severity(event.get('severity', 3))
                            self.create_event("suricata_alert", event, severity, tactic)
                            
                    except json.JSONDecodeError:
                        continue
                        
        except Exception as e:
            self.logger.error(f"Error collecting Suricata events: {e}")
    
    def map_network_to_tactic(self, event):
        """Map network events to MITRE ATT&CK tactics"""
        protocol = event.get('protocol', '').lower()
        dst_port = int(event.get('dst_port', 0))
        
        # Command and Control
        if dst_port in [80, 443, 8080, 8443] and protocol == 'tcp':
            return "Command and Control"
        
        # Exfiltration
        if int(event.get('orig_bytes', 0)) > 10000000:  # 10MB
            return "Exfiltration"
        
        # Initial Access
        if dst_port in [22, 23, 3389, 5900]:  # SSH, Telnet, RDP, VNC
            return "Initial Access"
        
        return "Network"
    
    def map_suricata_to_tactic(self, event):
        """Map Suricata alerts to MITRE ATT&CK tactics"""
        signature = event.get('signature', '').lower()
        category = event.get('category', '').lower()
        
        if 'trojan' in signature or 'malware' in signature:
            return "Execution"
        elif 'scan' in signature or 'reconnaissance' in signature:
            return "Reconnaissance"
        elif 'ddos' in signature or 'flood' in signature:
            return "Impact"
        elif 'backdoor' in signature or 'c2' in signature:
            return "Command and Control"
        elif 'exfiltration' in signature or 'data' in signature:
            return "Exfiltration"
        
        return "Network"
    
    def map_suricata_severity(self, severity):
        """Map Suricata severity to ASTRA severity levels"""
        severity_map = {
            1: "CRITICAL",
            2: "HIGH", 
            3: "MEDIUM",
            4: "LOW"
        }
        return severity_map.get(severity, "MEDIUM")
    
    def start_monitoring(self):
        """Start network monitoring threads"""
        try:
            # Start Zeek monitoring
            zeek_thread = threading.Thread(target=self._monitor_zeek, daemon=True)
            zeek_thread.start()
            self.monitoring_threads.append(zeek_thread)
            
            # Start Suricata monitoring
            suricata_thread = threading.Thread(target=self._monitor_suricata, daemon=True)
            suricata_thread.start()
            self.monitoring_threads.append(suricata_thread)
            
            self.logger.info("Network monitoring started")
            
        except Exception as e:
            self.logger.error(f"Error starting network monitoring: {e}")
    
    def _monitor_zeek(self):
        """Monitor Zeek logs continuously"""
        while self.running:
            try:
                self.collect_zeek_events()
                time.sleep(5)  # Check every 5 seconds
            except Exception as e:
                self.logger.error(f"Error in Zeek monitoring: {e}")
                time.sleep(10)
    
    def _monitor_suricata(self):
        """Monitor Suricata alerts continuously"""
        while self.running:
            try:
                self.collect_suricata_events()
                time.sleep(5)  # Check every 5 seconds
            except Exception as e:
                self.logger.error(f"Error in Suricata monitoring: {e}")
                time.sleep(10)
    
    def collect_events(self):
        """Collect network events from Zeek and Suricata"""
        self.collect_zeek_events()
        self.collect_suricata_events()

if __name__ == "__main__":
    agent = NetworkEDRAgent()
    agent.install_zeek()
    agent.install_suricata()
    agent.start()
