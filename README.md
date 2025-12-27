# Task 4: Network Intrusion Detection System (NIDS)

## Overview
A comprehensive Python-based Network Intrusion Detection System that monitors network traffic in real-time and detects suspicious or malicious activities using rule-based detection mechanisms.

## Features

### 1. **Real-time Packet Capture and Analysis**
- Captures raw network packets at the system level
- Analyzes IPv4, TCP, UDP, and ICMP protocols
- Processes and logs suspicious activities immediately

### 2. **Detection Rules**
The system includes detection rules for:

| Rule Name | Severity | Description |
|-----------|----------|-------------|
| **SYN Flood** | CRITICAL | Detects DDoS attacks using SYN flood technique |
| **Port Scan** | MEDIUM | Identifies systematic port scanning activities |
| **Brute Force** | HIGH | Detects repeated failed login attempts |
| **SQL Injection** | HIGH | Identifies SQL injection payloads in traffic |
| **XSS Attack** | MEDIUM | Detects Cross-Site Scripting attempts |
| **Suspicious Ports** | MEDIUM | Monitors access to unusual ports (SSH, MySQL, etc.) |
| **Protocol Anomaly** | MEDIUM | Detects unusual protocol behavior |
| **Invalid Header** | LOW | Identifies malformed packet headers |

### 3. **Alert System**
- Multi-level alert severity (CRITICAL, HIGH, MEDIUM, LOW)
- Detailed alert information including:
  - Timestamp of detection
  - Source and destination IP addresses
  - Port numbers involved
  - Rule name and description
  - JSON export capability

### 4. **Network Flow Tracking**
- Tracks communication flows between IP pairs
- Counts unique ports accessed
- Monitors SYN packet counts
- Maintains temporal analysis of network activity

### 5. **Suspicious Activity Tracking**
- Maintains log of suspicious IP addresses
- Counts alerts per IP
- Generates summary reports
- Exports alerts to JSON format

## Requirements

```bash
pip install -r requirements.txt
```

### System Requirements
- Python 3.6+
- Elevated privileges (sudo) for raw socket access
- Linux or macOS operating system
- Sufficient network bandwidth for monitoring

## Usage

### Basic Usage (Monitor indefinitely)
```bash
sudo python3 ids.py
```

### Monitor Specific Number of Packets
```bash
sudo python3 ids.py -c 1000
```

### Export Alerts to File
```bash
sudo python3 ids.py -o alerts.json
```

### Combine Options
```bash
sudo python3 ids.py -c 5000 -o network_alerts.json
```

## Output Example

```
2024-12-24 15:30:45,123 - INFO - ======================================================================
2024-12-24 15:30:45,123 - INFO - Network Intrusion Detection System Started
2024-12-24 15:30:45,123 - INFO - ======================================================================
2024-12-24 15:30:45,123 - INFO - Monitoring network traffic for suspicious activity...
2024-12-24 15:30:45,123 - INFO - Press Ctrl+C to stop

2024-12-24 15:31:12,456 - WARNING - [CRITICAL] SYN_FLOOD - Possible SYN flood DDoS attack detected (192.168.1.100 -> 10.0.0.5:443)
2024-12-24 15:31:12,456 - WARNING - {
  "timestamp": "2024-12-24T15:31:12.456789",
  "level": "CRITICAL",
  "rule": "SYN_FLOOD",
  "description": "Possible SYN flood DDoS attack detected",
  "source_ip": "192.168.1.100",
  "dest_ip": "10.0.0.5",
  "port": 443
}

2024-12-24 15:31:45,789 - WARNING - [MEDIUM] PORT_SCAN - Port scanning detected - 25 ports accessed (192.168.1.101 -> 10.0.0.6)
2024-12-24 15:31:45,789 - WARNING - {
  "timestamp": "2024-12-24T15:31:45.789123",
  "level": "MEDIUM",
  "rule": "PORT_SCAN",
  "description": "Port scanning detected - 25 ports accessed",
  "source_ip": "192.168.1.101",
  "dest_ip": "10.0.0.6",
  "port": null
}

2024-12-24 15:32:00,100 - INFO - [*] Processed 1000 packets, Alerts: 3
```

## Alert JSON Format

```json
[
  {
    "timestamp": "2024-12-24T15:31:12.456789",
    "level": "CRITICAL",
    "rule": "SYN_FLOOD",
    "description": "Possible SYN flood DDoS attack detected",
    "source_ip": "192.168.1.100",
    "dest_ip": "10.0.0.5",
    "port": 443
  },
  {
    "timestamp": "2024-12-24T15:31:45.789123",
    "level": "HIGH",
    "rule": "SQL_INJECTION",
    "description": "SQL injection attempt detected in payload",
    "source_ip": "192.168.1.102",
    "dest_ip": "10.0.0.7",
    "port": 80
  }
]
```

## Detection Examples

### 1. SYN Flood Attack Detection
**What it detects**: Multiple SYN packets from same source exceeding threshold
**Threshold**: 50+ SYN packets in monitoring window
**Severity**: CRITICAL
**Response**: Immediate alert to administrator

### 2. Port Scanning Detection
**What it detects**: Single source accessing multiple unique ports
**Threshold**: 10+ different ports accessed
**Severity**: MEDIUM
**Response**: Alert with port count

### 3. SQL Injection Detection
**What it detects**: SQL keywords in payload (UNION, DROP, INSERT, EXEC, etc.)
**Patterns**: 
- `UNION SELECT`
- `DROP TABLE`
- `' OR '1'='1`
- `;--` (comment)

**Severity**: HIGH
**Response**: Alert with source/destination info

### 4. XSS Attack Detection
**What it detects**: JavaScript injection patterns in payload
**Patterns**:
- `<script>` tags
- `javascript:` protocol
- Event handlers (onerror, onload, onclick)

**Severity**: MEDIUM
**Response**: Alert with payload source

### 5. Suspicious Port Access
**What it detects**: Connection attempts to unusual ports
**Suspicious Ports**: 22 (SSH), 3306 (MySQL), 5432 (PostgreSQL), 27017 (MongoDB), 6379 (Redis), etc.
**Severity**: MEDIUM
**Response**: Alert with port information

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│         Network Interface (Raw Packets)                 │
└──────────────────────┬──────────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────┐
│   Intrusion Detection System (ids.py)                   │
├─────────────────────────────────────────────────────────┤
│ • IntrusionDetectionSystem (Main)                       │
│ • NetworkFlowTracker (Flow Analysis)                    │
│ • IntrusionDetectionRules (Rules Engine)                │
└──────────────────────┬──────────────────────────────────┘
                       │
        ┌──────────────┼──────────────┐
        │              │              │
        ▼              ▼              ▼
    TCP Parser   UDP Parser    ICMP Parser
        │              │              │
        └──────────────┼──────────────┘
                       │
                       ▼
        ┌──────────────────────────────┐
        │   Detection Rules Engine     │
        ├──────────────────────────────┤
        │ • Port Scan Detection        │
        │ • SYN Flood Detection        │
        │ • Payload Analysis           │
        │ • Pattern Matching           │
        └──────────────┬───────────────┘
                       │
        ┌──────────────┴──────────────┐
        │                             │
        ▼                             ▼
    Alert System              Flow Tracking
        │                             │
        ├────────────────┬────────────┘
        │                │
        ▼                ▼
    Logging          Summary Report
        │
        └──► JSON Export
```

## Alert Levels

### CRITICAL (🔴)
- SYN flood attacks
- Exploitation attempts
- Large-scale DoS attacks
- **Action**: Immediate blocking/notification

### HIGH (🟠)
- SQL injection attempts
- Suspicious authentication failures
- Known attack patterns
- **Action**: Investigate and block

### MEDIUM (🟡)
- Port scanning
- XSS attempts
- Suspicious port access
- **Action**: Monitor and log

### LOW (🟢)
- Invalid packet headers
- Protocol anomalies
- Unusual patterns (low confidence)
- **Action**: Log for analysis

## Response Mechanisms

### Current Implementation:
1. Real-time alert logging
2. Detailed JSON export
3. Summary statistics
4. Suspicious IP tracking

### Suggested Enhancements:
1. **Automated Response**:
   - Automatic firewall rule injection
   - IP blacklisting
   - Traffic rate limiting

2. **Integration**:
   - SIEM integration (Splunk, ELK)
   - Email/SMS alerts
   - Webhook notifications

3. **Advanced Monitoring**:
   - Machine learning for anomaly detection
   - Behavioral analysis
   - Threat intelligence integration

## Performance Considerations

- **Packet Processing**: ~1000 packets/second on typical hardware
- **Memory Usage**: ~100MB for tracking 10,000 flows
- **CPU Usage**: 5-15% depending on detection complexity
- **Storage**: ~1-5MB per 10,000 alerts (JSON format)

## Visualization

Generate visualization of detected attacks:

```bash
python3 visualize_alerts.py -i alerts.json -o attacks.html
```

(Requires matplotlib/plotly)

## Integration Examples

### 1. Send Alerts to Slack
```python
import requests

def send_to_slack(alert):
    webhook_url = "https://hooks.slack.com/..."
    requests.post(webhook_url, json={
        "text": str(alert)
    })
```

### 2. Database Logging
```python
import sqlite3

def log_to_db(alert):
    conn = sqlite3.connect('alerts.db')
    conn.execute('''
        INSERT INTO alerts VALUES (?, ?, ?, ?, ?, ?, ?)
    ''', alert.to_dict().values())
    conn.commit()
```

### 3. Automated Response
```python
def block_ip(ip_address):
    # Add firewall rule
    os.system(f"iptables -A DROP -s {ip_address}")
    logger.warning(f"Blocked IP: {ip_address}")
```

## Limitations

1. **Requires Root/Admin**: Raw socket access needed
2. **Single Interface**: Monitors default network interface only
3. **Pattern-based**: Signature-based detection (not behavioral)
4. **No Encryption**: Cannot analyze encrypted traffic (HTTPS/TLS)
5. **Resource Intensive**: Heavy CPU/memory on high-traffic networks

## Future Enhancements

1. **Machine Learning Detection**:
   - Anomaly detection algorithms
   - Traffic pattern analysis
   - Zero-day detection

2. **Advanced Features**:
   - Multi-interface monitoring
   - Geographical IP tracking
   - Threat intelligence feeds
   - Predictive alerting

3. **Scalability**:
   - Distributed monitoring
   - Cloud integration
   - Load balancing

4. **User Interface**:
   - Web dashboard
   - Real-time visualization
   - Alert management portal

## Security Notes

⚠️ **Important Considerations**:
- Only use on networks you own or have authorization to monitor
- Ensure compliance with local regulations
- Sensitive data may be visible in payloads
- Consider encryption for transmitted alerts
- Implement proper access controls for alert logs

## References

- [Tcpdump/Libpcap](https://www.tcpdump.org/)
- [Snort IDS](https://www.snort.org/)
- [Suricata IDS](https://suricata.io/)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [CWE Top 25](https://cwe.mitre.org/top25/)

## Troubleshooting

### "Permission Denied" Error
```bash
# Run with sudo
sudo python3 ids.py
```

### No Packets Captured
```bash
# Check network connectivity
ping google.com

# List network interfaces
ifconfig

# Generate some traffic
curl https://example.com
```

### High CPU Usage
```bash
# Reduce analysis scope
sudo python3 ids.py -c 1000
```

### Memory Issues
```bash
# Export and clear alerts
sudo python3 ids.py -o alerts.json
```

## Support and Contribution

For issues, improvements, or contributions:
1. Document the issue clearly
2. Provide network traffic samples (anonymized)
3. Include system information
4. Suggest improvements or fixes

---

**Task Status**: ✅ Complete
**Detection Rules**: 8+ types
**Alert Levels**: 4 levels
**Export Formats**: JSON, Logs
