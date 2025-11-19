# agents/win_agent.py - Enhanced Windows EDR Agent with Sysmon Integration
import requests, os, time, json, subprocess, threading, queue, logging
from jose import jwt
from datetime import datetime
import winreg
import psutil
import win32evtlog
import win32evtlogutil
import win32con
from base_agent import BaseEDRAgent

class WindowsEDRAgent(BaseEDRAgent):
    """Enhanced Windows EDR Agent with Sysmon integration"""
    
    def __init__(self, agent_id="win_agent_v2"):
        super().__init__(agent_id, "windows")
        self.sysmon_events = [
            "Microsoft-Windows-Sysmon/Operational"  # Sysmon event log
        ]
        self.sysmon_config_path = os.path.join(os.path.dirname(__file__), "configs", "sysmon-config.xml")
        self.security_events = [
            "Security"  # Windows Security event log
        ]
        self.monitoring_threads = []
    
    def install_sysmon(self):
        """Install and configure Sysmon with ASTRA configuration"""
        try:
            # Check if Sysmon is already installed
            result = subprocess.run(['sysmon', '-c'], capture_output=True, text=True)
            if result.returncode == 0:
                self.logger.info("Sysmon is already installed")
            else:
                self.logger.info("Installing Sysmon...")
                # Download and install Sysmon (requires admin privileges)
                subprocess.run(['powershell', '-Command', 
                    'Invoke-WebRequest -Uri "https://download.sysinternals.com/files/Sysmon.zip" -OutFile "sysmon.zip"'], 
                    check=True)
                subprocess.run(['powershell', '-Command', 'Expand-Archive -Path "sysmon.zip" -DestinationPath "C:\\Sysmon"'], 
                    check=True)
                subprocess.run(['C:\\Sysmon\\Sysmon64.exe', '-i'], check=True)
                self.logger.info("Sysmon installed successfully")
            
            # Apply ASTRA configuration
            if os.path.exists(self.sysmon_config_path):
                subprocess.run(['sysmon', '-c', self.sysmon_config_path], check=True)
                self.logger.info("ASTRA Sysmon configuration applied")
            else:
                self.logger.warning(f"Sysmon config not found at {self.sysmon_config_path}")
                
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Failed to install/configure Sysmon: {e}")
        except Exception as e:
            self.logger.error(f"Error with Sysmon setup: {e}")
        
    def collect_sysmon_events(self):
        """Collect Sysmon events from Windows Event Log"""
        try:
            # Query Sysmon events
            hand = win32evtlog.OpenEventLog(None, "Microsoft-Windows-Sysmon/Operational")
            flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
            
            events = win32evtlog.ReadEventLog(hand, flags, 0)
            
            for event in events:
                if event.EventID in [1, 3, 11, 12, 13]:  # Key Sysmon events
                    event_data = self.parse_sysmon_event(event)
                    if event_data:
                        edr_event = self.create_event("sysmon", event_data, "INFO")
                        self.event_queue.put(edr_event)
            
            win32evtlog.CloseEventLog(hand)
            
        except Exception as e:
            self.logger.error(f"Error collecting Sysmon events: {e}")
    
    def parse_sysmon_event(self, event):
        """Parse Sysmon event data"""
        try:
            inserts = list(event.StringInserts or [])

            def s(idx, default=""):
                try:
                    v = inserts[idx]
                    return v if v is not None else default
                except Exception:
                    return default

            # Process based on event ID using known Sysmon field orders
            if event.EventID == 1:  # Process creation
                # Expected order (v13+):
                # 0 RuleName, 1 UtcTime, 2 ProcessGuid, 3 ProcessId, 4 Image,
                # 5 FileVersion, 6 Description, 7 Product, 8 Company, 9 OriginalFileName,
                # 10 CommandLine, 11 CurrentDirectory, 12 User, 13 LogonGuid, 14 LogonId,
                # 15 TerminalSessionId, 16 IntegrityLevel, 17 Hashes,
                # 18 ParentProcessGuid, 19 ParentProcessId, 20 ParentImage, 21 ParentCommandLine
                process_name = s(4)
                command_line = s(10)
                user = s(12)
                parent_image = s(20)
                process_id = s(3)
                parent_pid = s(19)
                return {
                    "event_id": 1,
                    "process_name": process_name,
                    "command_line": command_line,
                    "user": user,
                    "parent_process": parent_image,
                    "process_id": process_id,
                    "parent_id": parent_pid,
                    "tactic": "TA0002",  # Execution
                }

            elif event.EventID == 3:  # Network connection
                # Expected order:
                # 0 RuleName, 1 UtcTime, 2 ProcessGuid, 3 ProcessId, 4 Image, 5 User,
                # 6 Protocol, 7 Initiated, 8 SourceIsIpv6, 9 SourceIp, 10 SourceHostname, 11 SourcePort,
                # 12 SourcePortName, 13 DestinationIsIpv6, 14 DestinationIp, 15 DestinationHostname, 16 DestinationPort,
                # 17 DestinationPortName
                return {
                    "event_id": 3,
                    "process_name": s(4),
                    "source_ip": s(9),
                    "destination_ip": s(14),
                    "destination_port": s(16),
                    "protocol": s(6),
                    "tactic": "TA0011",  # Command and Control
                }

            elif event.EventID == 11:  # File creation
                # Expected order:
                # 0 RuleName, 1 UtcTime, 2 ProcessGuid, 3 ProcessId, 4 Image, 5 TargetFilename,
                # 6 CreationUtcTime (optional depending on version)
                return {
                    "event_id": 11,
                    "process_name": s(4),
                    "target_filename": s(5),
                    # Hashes usually appear in EventID 15; include if present
                    "file_hash": s(6, ""),
                    "tactic": "TA0002",  # Execution (file dropper behavior)
                }

            elif event.EventID == 12:  # Registry object create/delete
                # Expected order:
                # 0 RuleName, 1 UtcTime, 2 EventType, 3 UtcTime?, 4 ProcessGuid, 5 ProcessId, 6 Image,
                # 7 TargetObject, 8 Details
                return {
                    "event_id": 12,
                    "process_name": s(6),
                    "target_object": s(7),
                    "details": s(8),
                    "tactic": "TA0004",  # Privilege Escalation / Persistence
                }

            elif event.EventID == 13:  # Registry value set
                # Expected order similar to 12 with value set details
                return {
                    "event_id": 13,
                    "process_name": s(6),
                    "target_object": s(7),
                    "details": s(8),
                    "tactic": "TA0004",  # Privilege Escalation / Persistence
                }
                
        except Exception as e:
            self.logger.error(f"Error parsing Sysmon event: {e}")
        
        return None
    
    def collect_security_events(self):
        """Collect Windows Security events"""
        try:
            hand = win32evtlog.OpenEventLog(None, "Security")
            flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
            
            events = win32evtlog.ReadEventLog(hand, flags, 0)
            
            for event in events:
                if event.EventID in [4624, 4625, 4648, 4768, 4769]:  # Key security events
                    event_data = self.parse_security_event(event)
                    if event_data:
                        edr_event = self.create_event("security", event_data, "WARNING")
                        self.event_queue.put(edr_event)
            
            win32evtlog.CloseEventLog(hand)
            
        except Exception as e:
            self.logger.error(f"Error collecting security events: {e}")
    
    def parse_security_event(self, event):
        """Parse Windows Security event"""
        try:
            event_data = {}
            
            # Extract event data
            for data in event.StringInserts:
                if data:
                    event_data[data] = data
            
            if event.EventID == 4624:  # Successful logon
                return {
                    "event_id": 4624,
                    "logon_type": event_data.get("LogonType", ""),
                    "account_name": event_data.get("AccountName", ""),
                    "source_ip": event_data.get("IpAddress", ""),
                    "tactic": "TA0008"  # Lateral Movement
                }
            
            elif event.EventID == 4625:  # Failed logon
                return {
                    "event_id": 4625,
                    "logon_type": event_data.get("LogonType", ""),
                    "account_name": event_data.get("AccountName", ""),
                    "source_ip": event_data.get("IpAddress", ""),
                    "tactic": "TA0008"  # Lateral Movement
                }
            
            elif event.EventID == 4648:  # Logon with explicit credentials
                return {
                    "event_id": 4648,
                    "account_name": event_data.get("AccountName", ""),
                    "target_server": event_data.get("TargetServerName", ""),
                    "tactic": "TA0008"  # Lateral Movement
                }
                
        except Exception as e:
            self.logger.error(f"Error parsing security event: {e}")
        
        return None
    
    def collect_process_events(self):
        """Collect real-time process events using psutil"""
        try:
            # Get current processes
            current_processes = {p.pid: p for p in psutil.process_iter(['pid', 'name', 'cmdline', 'create_time'])}
            
            while self.running:
                time.sleep(1)  # Check every second
                
                new_processes = {p.pid: p for p in psutil.process_iter(['pid', 'name', 'cmdline', 'create_time'])}
                
                # Find new processes
                for pid, process in new_processes.items():
                    if pid not in current_processes:
                        try:
                            process_data = {
                                "process_name": process.info['name'],
                                "command_line": ' '.join(process.info['cmdline']) if process.info['cmdline'] else '',
                                "process_id": pid,
                                "create_time": process.info['create_time'],
                                "tactic": "TA0002"  # Execution
                            }
                            
                            edr_event = self.create_event("process_creation", process_data, "INFO")
                            self.event_queue.put(edr_event)
                            
                        except (psutil.NoSuchProcess, psutil.AccessDenied):
                            continue
                
                current_processes = new_processes
                
        except Exception as e:
            self.logger.error(f"Error collecting process events: {e}")
    
    def collect_network_events(self):
        """Collect network connection events"""
        try:
            while self.running:
                time.sleep(5)  # Check every 5 seconds
                
                for conn in psutil.net_connections(kind='inet'):
                    if conn.status == 'ESTABLISHED' and conn.raddr:
                        network_data = {
                            "local_address": f"{conn.laddr.ip}:{conn.laddr.port}",
                            "remote_address": f"{conn.raddr.ip}:{conn.raddr.port}",
                            "status": conn.status,
                            "pid": conn.pid,
                            "tactic": "TA0011"  # Command and Control
                        }
                        
                        edr_event = self.create_event("network_connection", network_data, "INFO")
                        self.event_queue.put(edr_event)
                        
        except Exception as e:
            self.logger.error(f"Error collecting network events: {e}")
    
    def collect_registry_events(self):
        """Monitor critical registry keys for changes"""
        try:
            critical_keys = [
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
                r"SYSTEM\CurrentControlSet\Services"
            ]
            
            while self.running:
                time.sleep(10)  # Check every 10 seconds
                
                for key_path in critical_keys:
                    try:
                        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path)
                        registry_data = {
                            "key_path": key_path,
                            "values": [],
                            "tactic": "TA0004"  # Privilege Escalation
                        }
                        
                        # Get all values
                        i = 0
                        while True:
                            try:
                                name, value, _ = winreg.EnumValue(key, i)
                                registry_data["values"].append({"name": name, "value": str(value)})
                                i += 1
                            except OSError:
                                break
                        
                        winreg.CloseKey(key)
                        
                        edr_event = self.create_event("registry_monitor", registry_data, "INFO")
                        self.event_queue.put(edr_event)
                        
                    except Exception as e:
                        self.logger.error(f"Error monitoring registry key {key_path}: {e}")
                        
        except Exception as e:
            self.logger.error(f"Error collecting registry events: {e}")
    
    def collect_events(self):
        """Collect all Windows events"""
        self.collect_sysmon_events()
        self.collect_security_events()
    
    def start_monitoring(self):
        """Start all monitoring threads"""
        # Start process monitoring
        process_thread = threading.Thread(target=self.collect_process_events)
        process_thread.daemon = True
        process_thread.start()
        self.monitoring_threads.append(process_thread)
        
        # Start network monitoring
        network_thread = threading.Thread(target=self.collect_network_events)
        network_thread.daemon = True
        network_thread.start()
        self.monitoring_threads.append(network_thread)
        
        # Start registry monitoring
        registry_thread = threading.Thread(target=self.collect_registry_events)
        registry_thread.daemon = True
        registry_thread.start()
        self.monitoring_threads.append(registry_thread)
        
        # Periodic event log collection
        def periodic_collection():
            while self.running:
                self.collect_events()
                time.sleep(30)  # Collect every 30 seconds
        
        collection_thread = threading.Thread(target=periodic_collection)
        collection_thread.daemon = True
        collection_thread.start()
        self.monitoring_threads.append(collection_thread)

def main():
    """Main function to run the Windows EDR agent"""
    # Create logs directory if it doesn't exist
    os.makedirs("logs", exist_ok=True)
    
    # Create and start the agent
    agent = WindowsEDRAgent()
    
    try:
        agent.start()
        print(f"Windows EDR Agent started. Press Ctrl+C to stop.")
        
        # Keep the main thread alive
        while True:
            time.sleep(1)
            
    except KeyboardInterrupt:
        print("\nShutting down Windows EDR Agent...")
        agent.stop()
        print("Agent stopped.")

if __name__ == "__main__":
    main()
