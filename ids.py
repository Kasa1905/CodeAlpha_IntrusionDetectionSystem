"""
Task 4: Network Intrusion Detection System (NIDS)
A Python-based network intrusion detection system that monitors traffic
and detects suspicious or malicious activity using rule-based detection.
"""

import socket
import struct
import textwrap
import logging
from datetime import datetime
from collections import defaultdict
import json
import re
from enum import Enum


# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class AlertLevel(Enum):
    """Alert severity levels"""
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class Alert:
    """Intrusion alert class"""
    
    def __init__(self, alert_level, rule_name, description, source_ip, dest_ip, port=None):
        self.timestamp = datetime.now().isoformat()
        self.level = alert_level
        self.rule_name = rule_name
        self.description = description
        self.source_ip = source_ip
        self.dest_ip = dest_ip
        self.port = port
    
    def to_dict(self):
        """Convert alert to dictionary"""
        return {
            "timestamp": self.timestamp,
            "level": self.level.value,
            "rule": self.rule_name,
            "description": self.description,
            "source_ip": self.source_ip,
            "dest_ip": self.dest_ip,
            "port": self.port
        }
    
    def to_json(self):
        """Convert alert to JSON"""
        return json.dumps(self.to_dict(), indent=2)
    
    def __str__(self):
        return (f"[{self.level.value}] {self.rule_name} - {self.description} "
                f"({self.source_ip} -> {self.dest_ip}:{self.port})")


class IntrusionDetectionRules:
    """Define detection rules for intrusions"""
    
    def __init__(self):
        self.rules = {
            "port_scan": {
                "name": "Port Scan Detection",
                "description": "Detects potential port scanning activity",
                "level": AlertLevel.MEDIUM,
                "threshold": 10  # Number of ports accessed in 10 seconds
            },
            "syn_flood": {
                "name": "SYN Flood Attack",
                "description": "Detects SYN flood DDoS attack",
                "level": AlertLevel.CRITICAL,
                "threshold": 50  # SYN packets from same source in 10 seconds
            },
            "brute_force": {
                "name": "Brute Force Attack",
                "description": "Detects brute force login attempts",
                "level": AlertLevel.HIGH,
                "threshold": 20  # Failed attempts within time window
            },
            "sql_injection": {
                "name": "SQL Injection Attempt",
                "description": "Detects potential SQL injection payload",
                "level": AlertLevel.HIGH,
                "patterns": [
                    r"(\bUNION\b.*\bSELECT\b)",
                    r"(\bDROP\b.*\bTABLE\b)",
                    r"(\bINSERT\b.*\bINTO\b)",
                    r"(\bDELETE\b.*\bFROM\b)",
                    r"(\bEXEC\b.*\()",
                    r"(;.*--)",
                    r"('\s*OR\s*'1'='1)",
                ]
            },
            "xss": {
                "name": "XSS Attack Attempt",
                "description": "Detects potential Cross-Site Scripting payload",
                "level": AlertLevel.MEDIUM,
                "patterns": [
                    r"(<script[^>]*>)",
                    r"(javascript:)",
                    r"(onerror=)",
                    r"(onload=)",
                    r"(onclick=)",
                ]
            },
            "suspicious_ports": {
                "name": "Suspicious Port Access",
                "description": "Detects access to suspicious ports",
                "level": AlertLevel.MEDIUM,
                "ports": [
                    22,    # SSH
                    3306,  # MySQL
                    5432,  # PostgreSQL
                    27017, # MongoDB
                    6379,  # Redis
                    8080,  # HTTP Alternate
                    9200,  # Elasticsearch
                ]
            },
            "protocol_anomaly": {
                "name": "Protocol Anomaly",
                "description": "Detects unusual protocol behavior",
                "level": AlertLevel.MEDIUM,
            },
            "invalid_header": {
                "name": "Invalid Packet Header",
                "description": "Detects malformed packet headers",
                "level": AlertLevel.LOW,
            }
        }
    
    def get_rule(self, rule_name):
        """Get a specific rule"""
        return self.rules.get(rule_name)
    
    def check_sql_injection(self, data):
        """Check for SQL injection patterns"""
        patterns = self.rules["sql_injection"]["patterns"]
        for pattern in patterns:
            if re.search(pattern, data, re.IGNORECASE):
                return True
        return False
    
    def check_xss(self, data):
        """Check for XSS patterns"""
        patterns = self.rules["xss"]["patterns"]
        for pattern in patterns:
            if re.search(pattern, data, re.IGNORECASE):
                return True
        return False


class NetworkFlowTracker:
    """Track network flows for anomaly detection"""
    
    def __init__(self, time_window=10):
        self.time_window = time_window
        self.flows = defaultdict(lambda: {
            "packets": [],
            "ports": set(),
            "syn_count": 0,
            "failed_attempts": 0
        })
    
    def track_packet(self, source_ip, dest_ip, port, flags=None):
        """Track a packet flow"""
        flow_key = (source_ip, dest_ip)
        self.flows[flow_key]["packets"].append({
            "timestamp": datetime.now(),
            "dest_port": port,
            "flags": flags
        })
        
        if port:
            self.flows[flow_key]["ports"].add(port)
        
        if flags and flags & 0x02:  # SYN flag
            self.flows[flow_key]["syn_count"] += 1
    
    def get_port_count(self, source_ip, dest_ip):
        """Get number of unique ports accessed"""
        flow_key = (source_ip, dest_ip)
        return len(self.flows[flow_key]["ports"])
    
    def get_syn_count(self, source_ip, dest_ip):
        """Get number of SYN packets"""
        flow_key = (source_ip, dest_ip)
        return self.flows[flow_key]["syn_count"]
    
    def reset_syn_count(self, source_ip, dest_ip):
        """Reset SYN packet counter"""
        flow_key = (source_ip, dest_ip)
        self.flows[flow_key]["syn_count"] = 0


class IntrusionDetectionSystem:
    """Main Intrusion Detection System"""
    
    def __init__(self):
        self.rules = IntrusionDetectionRules()
        self.flow_tracker = NetworkFlowTracker()
        self.alerts = []
        self.packet_count = 0
        self.suspicious_ips = defaultdict(int)
    
    def run(self, packet_count=0):
        """Start the IDS"""
        try:
            if sys.platform == 'darwin':  # macOS
                conn = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
                conn.bind((self._get_local_ip(), 0))
                conn.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            else:
                conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
            
            logger.info("=" * 70)
            logger.info("Network Intrusion Detection System Started")
            logger.info("=" * 70)
            logger.info("Monitoring network traffic for suspicious activity...")
            logger.info("Press Ctrl+C to stop\n")
            
            while True:
                if packet_count != 0 and self.packet_count >= packet_count:
                    break
                
                raw_buffer, addr = conn.recvfrom(65535)
                self.packet_count += 1
                
                self._analyze_packet(raw_buffer)
                
                # Display status periodically
                if self.packet_count % 100 == 0:
                    logger.info(f"[*] Processed {self.packet_count} packets, "
                               f"Alerts: {len(self.alerts)}")
        
        except PermissionError:
            logger.error("Error: This script requires elevated privileges (run with sudo)")
        except KeyboardInterrupt:
            logger.info("\n[*] IDS stopped by user")
            self._print_summary()
        except Exception as e:
            logger.error(f"Error: {str(e)}")
    
    def _analyze_packet(self, raw_buffer):
        """Analyze a packet for intrusions"""
        try:
            ipv4_packet = self._parse_ipv4(raw_buffer)
            
            if ipv4_packet:
                source_ip = ipv4_packet["src"]
                dest_ip = ipv4_packet["dest"]
                proto = ipv4_packet["proto"]
                
                # TCP packets
                if proto == 6:
                    tcp_data = self._parse_tcp(ipv4_packet["data"])
                    if tcp_data:
                        self._check_tcp_intrusions(source_ip, dest_ip, tcp_data)
                
                # UDP packets
                elif proto == 17:
                    udp_data = self._parse_udp(ipv4_packet["data"])
                    if udp_data:
                        self._check_udp_intrusions(source_ip, dest_ip, udp_data)
                
                # ICMP packets
                elif proto == 1:
                    self._check_icmp_intrusions(source_ip, dest_ip)
        
        except Exception as e:
            logger.debug(f"Error analyzing packet: {str(e)}")
    
    def _parse_ipv4(self, buf):
        """Parse IPv4 packet"""
        if len(buf) < 20:
            return None
        
        try:
            version_header_length = buf[0]
            version = version_header_length >> 4
            header_length = (version_header_length & 15) * 4
            
            if version != 4:
                return None
            
            ttl = buf[8]
            proto = buf[9]
            src = self._format_ipv4(buf[12:16])
            dest = self._format_ipv4(buf[16:20])
            
            return {
                "version": version,
                "header_length": header_length,
                "ttl": ttl,
                "proto": proto,
                "src": src,
                "dest": dest,
                "data": buf[header_length:]
            }
        except:
            return None
    
    def _parse_tcp(self, buf):
        """Parse TCP packet"""
        if len(buf) < 20:
            return None
        
        try:
            (src_port, dest_port, sequence, acknowledgment,
             offset_reserved_flags) = struct.unpack(">HHIIH", buf[0:14])
            
            offset = (offset_reserved_flags >> 12) * 4
            flags = offset_reserved_flags & 0x3F
            
            return {
                "src_port": src_port,
                "dest_port": dest_port,
                "sequence": sequence,
                "acknowledgment": acknowledgment,
                "flags": flags,
                "data": buf[offset:]
            }
        except:
            return None
    
    def _parse_udp(self, buf):
        """Parse UDP packet"""
        if len(buf) < 8:
            return None
        
        try:
            (src_port, dest_port, length) = struct.unpack(">HHH", buf[0:6])
            return {
                "src_port": src_port,
                "dest_port": dest_port,
                "length": length,
                "data": buf[8:]
            }
        except:
            return None
    
    def _check_tcp_intrusions(self, source_ip, dest_ip, tcp_data):
        """Check TCP packets for intrusions"""
        src_port = tcp_data["src_port"]
        dest_port = tcp_data["dest_port"]
        flags = tcp_data["flags"]
        payload = tcp_data["data"]
        
        # Track flow
        self.flow_tracker.track_packet(source_ip, dest_ip, dest_port, flags)
        
        # Check for SYN flood
        if flags & 0x02:  # SYN flag
            syn_count = self.flow_tracker.get_syn_count(source_ip, dest_ip)
            if syn_count > 50:
                alert = Alert(
                    AlertLevel.CRITICAL,
                    "SYN_FLOOD",
                    "Possible SYN flood DDoS attack detected",
                    source_ip,
                    dest_ip,
                    dest_port
                )
                self._raise_alert(alert)
        
        # Check port scan
        unique_ports = self.flow_tracker.get_port_count(source_ip, dest_ip)
        if unique_ports > 10:
            alert = Alert(
                AlertLevel.MEDIUM,
                "PORT_SCAN",
                f"Port scanning detected - {unique_ports} ports accessed",
                source_ip,
                dest_ip
            )
            self._raise_alert(alert)
        
        # Check suspicious ports
        if dest_port in self.rules.get_rule("suspicious_ports")["ports"]:
            alert = Alert(
                AlertLevel.MEDIUM,
                "SUSPICIOUS_PORT",
                f"Access to suspicious port {dest_port}",
                source_ip,
                dest_ip,
                dest_port
            )
            self._raise_alert(alert)
        
        # Check payload for attacks
        if payload:
            try:
                payload_str = payload.decode("utf-8", errors="ignore")
                
                # SQL Injection check
                if self.rules.check_sql_injection(payload_str):
                    alert = Alert(
                        AlertLevel.HIGH,
                        "SQL_INJECTION",
                        "SQL injection attempt detected in payload",
                        source_ip,
                        dest_ip,
                        dest_port
                    )
                    self._raise_alert(alert)
                
                # XSS check
                if self.rules.check_xss(payload_str):
                    alert = Alert(
                        AlertLevel.MEDIUM,
                        "XSS_ATTEMPT",
                        "XSS attack attempt detected in payload",
                        source_ip,
                        dest_ip,
                        dest_port
                    )
                    self._raise_alert(alert)
            except:
                pass
    
    def _check_udp_intrusions(self, source_ip, dest_ip, udp_data):
        """Check UDP packets for intrusions"""
        dest_port = udp_data["dest_port"]
        
        # Check suspicious ports
        suspicious_udp_ports = [53, 123, 161, 162, 445, 5353]
        if dest_port in suspicious_udp_ports:
            # This is normal - only alert on unusual patterns
            pass
    
    def _check_icmp_intrusions(self, source_ip, dest_ip):
        """Check ICMP packets for intrusions"""
        # ICMP used for ping requests - normally harmless
        # But can be used for reconnaissance or DoS
        
        # Track for later analysis
        pass
    
    def _raise_alert(self, alert):
        """Raise and log an alert"""
        self.alerts.append(alert)
        self.suspicious_ips[alert.source_ip] += 1
        
        # Log alert
        logger.warning(str(alert))
        logger.warning(alert.to_json())
    
    def _format_ipv4(self, bytes_addr):
        """Format IPv4 address"""
        return ".".join(map(str, bytes_addr))
    
    def _get_local_ip(self):
        """Get local IP address"""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except:
            return "127.0.0.1"
    
    def _print_summary(self):
        """Print IDS summary"""
        logger.info("\n" + "=" * 70)
        logger.info("INTRUSION DETECTION SYSTEM SUMMARY")
        logger.info("=" * 70)
        logger.info(f"Total packets processed: {self.packet_count}")
        logger.info(f"Total alerts raised: {len(self.alerts)}")
        
        if self.alerts:
            # Count by level
            critical = sum(1 for a in self.alerts if a.level == AlertLevel.CRITICAL)
            high = sum(1 for a in self.alerts if a.level == AlertLevel.HIGH)
            medium = sum(1 for a in self.alerts if a.level == AlertLevel.MEDIUM)
            low = sum(1 for a in self.alerts if a.level == AlertLevel.LOW)
            
            logger.info(f"\nAlerts by severity:")
            logger.info(f"  CRITICAL: {critical}")
            logger.info(f"  HIGH:     {high}")
            logger.info(f"  MEDIUM:   {medium}")
            logger.info(f"  LOW:      {low}")
            
            logger.info(f"\nTop suspicious IP addresses:")
            for ip, count in sorted(self.suspicious_ips.items(),
                                  key=lambda x: x[1], reverse=True)[:10]:
                logger.info(f"  {ip}: {count} alerts")
        
        logger.info("=" * 70)
    
    def export_alerts(self, filename):
        """Export alerts to JSON file"""
        with open(filename, 'w') as f:
            json.dump([a.to_dict() for a in self.alerts], f, indent=2)
        logger.info(f"Alerts exported to {filename}")


import sys

def main():
    """Main function"""
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Network Intrusion Detection System"
    )
    parser.add_argument("-c", "--count", type=int, default=0,
                       help="Number of packets to analyze (default: 0 = unlimited)")
    parser.add_argument("-o", "--output", type=str, default=None,
                       help="Output file for alerts (JSON format)")
    args = parser.parse_args()
    
    ids = IntrusionDetectionSystem()
    
    try:
        ids.run(args.count)
    finally:
        if args.output:
            ids.export_alerts(args.output)


if __name__ == "__main__":
    main()
