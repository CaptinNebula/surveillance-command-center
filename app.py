#!/usr/bin/env python3
"""
Surveillance Command Center
Network intelligence + OSINT investigation platform.
"""

import os
import re
import sys
import json
import time
import socket
import sqlite3
import hashlib
import logging
import platform
import shutil
import threading
import subprocess
from datetime import datetime
from ipaddress import ip_address, ip_network
from functools import wraps
from concurrent.futures import ThreadPoolExecutor

import requests
from dotenv import load_dotenv
from flask import Flask, render_template, jsonify, request, Response, redirect, url_for
from werkzeug.middleware.proxy_fix import ProxyFix

load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    stream=sys.stderr,
)
logger = logging.getLogger("surveillance_command_center")

# ============================================================================
# CONFIGURATION
# ============================================================================
DASHBOARD_USER = os.getenv("DASHBOARD_USER")
DASHBOARD_PASS = os.getenv("DASHBOARD_PASS")
SECRET_KEY = os.getenv("SECRET_KEY")

_INSECURE_DEFAULTS = {"admin1", "Admin123@", "change-this-to-a-random-string"}

if not DASHBOARD_USER or not DASHBOARD_PASS or not SECRET_KEY:
    raise SystemExit(
        "FATAL: DASHBOARD_USER, DASHBOARD_PASS, and SECRET_KEY must all be set "
        "(e.g. via a .env file — see .env.example). Refusing to start with no credentials configured."
    )
if DASHBOARD_USER in _INSECURE_DEFAULTS or DASHBOARD_PASS in _INSECURE_DEFAULTS or SECRET_KEY in _INSECURE_DEFAULTS:
    raise SystemExit(
        "FATAL: DASHBOARD_USER/DASHBOARD_PASS/SECRET_KEY must not use the old insecure default values."
    )

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "command_center.db")
LAN_SCAN_TIMEOUT = float(os.getenv("SCAN_TIMEOUT", "0.3"))
SCAN_WORKERS = int(os.getenv("SCAN_WORKERS", "40"))
NMAP_TIMEOUT = int(os.getenv("NMAP_TIMEOUT", "120"))

CAMERA_PORTS = [554, 8554, 80, 8080, 8000, 8060]
COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 554, 587,
                993, 995, 1723, 3306, 3389, 5432, 6379, 8000, 8080, 8443, 8888, 9000]

STREAM_TEMPLATES = [
    "rtsp://{ip}:554/stream1",
    "rtsp://{ip}:554/live/0",
    "rtsp://{ip}:554/h264",
    "rtsp://{ip}:554/cam/realmonitor?channel=1&subtype=0",
    "rtsp://{ip}:554/Streaming/Channels/101",
    "rtsp://{ip}:554/axis-media/media.amp",
    "rtsp://{ip}:8554/stream1",
    "http://{ip}:{port}/video/mjpg.cgi",
    "http://{ip}:{port}/mjpg/video.mjpg",
    "http://{ip}:{port}/videostream.cgi",
    "http://{ip}:{port}/stream1",
    "http://{ip}:{port}/snapshot.jpg",
    "http://{ip}:{port}/image/jpeg.cgi",
]

ANSI_ESCAPE = re.compile(r"\x1b\[[0-9;]*[a-zA-Z]")

app = Flask(__name__)
app.config["SECRET_KEY"] = SECRET_KEY
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1)

_active_feeds = {}

_failed_logins = {}
_LOGIN_LOCKOUT_THRESHOLD = 5
_LOGIN_LOCKOUT_WINDOW = 300  # 5 minutes

_live_lan_state = {"scanning": False, "last_scan": None, "devices": [], "interval": 30, "enabled": False}
_live_lan_lock = threading.Lock()

_last_errors = {"lan_monitor": None, "traffic_monitor": None, "osint": None}


# ============================================================================
# WIFI TRAFFIC MONITOR
# ============================================================================
_traffic_state = {
    "snapshots": [],       # Ring buffer of traffic data points
    "max_snapshots": 1440,  # 24 hours at 1-min intervals
    "current": None,
    "connections": [],
    "wifi_networks": [],
    "scanning": False,
    "interval": 60,
    "enabled": True,
}

PORT_PROTOCOLS = {
    80: "HTTP", 443: "HTTPS", 22: "SSH", 21: "FTP", 25: "SMTP",
    53: "DNS", 110: "POP3", 143: "IMAP", 993: "IMAPS", 995: "POP3S",
    587: "SMTPS", 3306: "MySQL", 5432: "PostgreSQL", 6379: "Redis",
    27017: "MongoDB", 9092: "Kafka", 5672: "AMQP", 1883: "MQTT",
    8080: "HTTP-Alt", 8443: "HTTPS-Alt", 8000: "HTTP-Alt",
    67: "DHCP", 68: "DHCP", 123: "NTP", 161: "SNMP", 162: "SNMP-Trap",
    389: "LDAP", 636: "LDAPS", 137: "NetBIOS", 138: "NetBIOS", 139: "NetBIOS",
    445: "SMB", 1900: "SSDP", 5353: "mDNS", 3000: "Dev-Server",
}


def get_network_io():
    """Get network I/O counters using psutil (cross-platform)."""
    try:
        import psutil
        io = psutil.net_io_counters(pernic=True)
        stats = {}
        for nic, counters in io.items():
            if "lo" in nic.lower() or "loopback" in nic.lower():
                continue
            stats[nic] = {
                "bytes_sent": counters.bytes_sent,
                "bytes_recv": counters.bytes_recv,
                "packets_sent": counters.packets_sent,
                "packets_recv": counters.packets_recv,
                "errin": counters.errin,
                "errout": counters.errout,
                "dropin": counters.dropin,
                "dropout": counters.dropout,
            }
        return stats
    except ImportError:
        return {}
    except Exception:
        return {}


def get_active_connections():
    """Get active network connections (cross-platform)."""
    try:
        import psutil
        conns = psutil.net_connections(kind="inet")
        results = []
        for c in conns:
            if c.status == "NONE":
                continue
            laddr = ""
            if c.laddr:
                laddr = f"{c.laddr.ip}:{c.laddr.port}"
            raddr = ""
            if c.raddr:
                raddr = f"{c.raddr.ip}:{c.raddr.port}"
            proc_name = ""
            if c.pid:
                try:
                    proc_name = psutil.Process(c.pid).name()
                except Exception:
                    pass
            results.append({
                "family": "IPv4" if c.family.name == "AF_INET" else "IPv6",
                "laddr": laddr,
                "raddr": raddr,
                "status": c.status,
                "pid": c.pid or 0,
                "process": proc_name,
            })
        return results
    except ImportError:
        return []
    except Exception:
        return []


def infer_protocols(connections):
    """Infer protocol distribution from remote ports."""
    protocols = {}
    for conn in connections:
        raddr = conn.get("raddr", "")
        if ":" in raddr:
            try:
                port = int(raddr.rsplit(":", 1)[1])
                proto = PORT_PROTOCOLS.get(port, f"Other ({port})")
            except (ValueError, IndexError):
                proto = "Other"
        else:
            proto = "Local"
        protocols[proto] = protocols.get(proto, 0) + 1
    return dict(sorted(protocols.items(), key=lambda x: x[1], reverse=True))


def get_top_talkers(connections):
    """Find IPs with most active connections."""
    talkers = {}
    for conn in connections:
        raddr = conn.get("raddr", "")
        if ":" in raddr:
            ip = raddr.rsplit(":", 1)[0]
            talkers[ip] = talkers.get(ip, 0) + 1
    return dict(sorted(talkers.items(), key=lambda x: x[1], reverse=True)[:10])


def get_wifi_survey():
    """Scan nearby WiFi networks (Linux only)."""
    networks = []
    # Try nmcli first (most Linux distros)
    try:
        result = subprocess.run(
            ["nmcli", "-t", "-f", "SSID,BSSID,SIGNAL,FREQ,SECURITY,CHANNEL", "device", "wifi", "list", "--rescan", "yes"],
            capture_output=True, text=True, timeout=30
        )
        if result.returncode == 0 and result.stdout.strip():
            for line in result.stdout.strip().splitlines():
                parts = line.split(":")
                if len(parts) >= 6:
                    ssid = parts[0] if parts[0] else "Hidden"
                    networks.append({
                        "ssid": ssid,
                        "bssid": parts[1],
                        "signal": int(parts[2]) if parts[2].isdigit() else 0,
                        "freq": parts[3],
                        "security": parts[4] if parts[4] else "Open",
                        "channel": parts[5],
                    })
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
    except Exception:
        pass

    # Try airport on macOS
    if not networks:
        try:
            result = subprocess.run(
                ["/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport", "-s"],
                capture_output=True, text=True, timeout=15
            )
            if result.returncode == 0 and result.stdout.strip():
                lines = result.stdout.strip().splitlines()[1:]  # Skip header
                for line in lines:
                    parts = line.split()
                    if len(parts) >= 7:
                        networks.append({
                            "ssid": parts[0] if parts[0] != "" else "Hidden",
                            "bssid": parts[1],
                            "signal": abs(int(parts[2])) if parts[2].lstrip("-").isdigit() else 0,
                            "freq": "",
                            "security": "",
                            "channel": parts[-1],
                        })
        except Exception:
            pass

    return networks


def traffic_monitor_loop():
    """Background thread — captures traffic stats every interval."""
    logger.info("Traffic monitor thread starting")
    prev_io = get_network_io()

    while True:
        time.sleep(_traffic_state["interval"])

        if not _traffic_state["enabled"]:
            continue

        _traffic_state["scanning"] = True
        try:
            current_io = get_network_io()
            connections = get_active_connections()
            protocols = infer_protocols(connections)
            top_talkers = get_top_talkers(connections)

            # Calculate throughput delta
            delta = {}
            total_sent = 0
            total_recv = 0
            for nic in current_io:
                if nic in prev_io:
                    sent_delta = current_io[nic]["bytes_sent"] - prev_io[nic]["bytes_sent"]
                    recv_delta = current_io[nic]["bytes_recv"] - prev_io[nic]["bytes_recv"]
                    if sent_delta < 0:
                        sent_delta = 0
                    if recv_delta < 0:
                        recv_delta = 0
                    delta[nic] = {
                        "bytes_sent": sent_delta,
                        "bytes_recv": recv_delta,
                        "packets_sent": current_io[nic]["packets_sent"] - prev_io[nic]["packets_sent"],
                        "packets_recv": current_io[nic]["packets_recv"] - prev_io[nic]["packets_recv"],
                    }
                    total_sent += sent_delta
                    total_recv += recv_delta

            # Count connection states
            conn_states = {}
            for c in connections:
                state = c["status"]
                conn_states[state] = conn_states.get(state, 0) + 1

            snapshot = {
                "timestamp": datetime.now().isoformat(),
                "total_bytes_sent": total_sent,
                "total_bytes_recv": total_recv,
                "total_sent_formatted": format_bytes(total_sent),
                "total_recv_formatted": format_bytes(total_recv),
                "packets_sent": sum(d.get("packets_sent", 0) for d in delta.values()),
                "packets_recv": sum(d.get("packets_recv", 0) for d in delta.values()),
                "connection_count": len(connections),
                "conn_states": conn_states,
                "protocols": protocols,
                "top_talkers": top_talkers,
                "per_nic": delta,
                "interfaces": list(delta.keys()),
            }

            # WiFi survey (may fail silently on macOS for some methods)
            wifi = get_wifi_survey()
            if wifi:
                snapshot["wifi_networks"] = wifi
                snapshot["wifi_count"] = len(wifi)
                _traffic_state["wifi_networks"] = wifi

            _traffic_state["current"] = snapshot
            _traffic_state["connections"] = connections

            # Append to ring buffer
            _traffic_state["snapshots"].append(snapshot)
            if len(_traffic_state["snapshots"]) > _traffic_state["max_snapshots"]:
                _traffic_state["snapshots"].pop(0)

            prev_io = current_io

            log_activity("Traffic Monitor", "snapshot",
                         f"↑{format_bytes(total_sent)} ↓{format_bytes(total_recv)} | {len(connections)} conns",
                         json.dumps({"protocols": protocols, "talkers": top_talkers}))

            trim_activity_log()

        except Exception as e:
            logger.exception("Traffic monitor cycle failed")
            _last_errors["traffic_monitor"] = f"{datetime.now().isoformat()}: {e}"
            log_activity("Traffic Monitor", "error", str(e), "")
        finally:
            _traffic_state["scanning"] = False


def format_bytes(num):
    """Format bytes into human-readable string."""
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if abs(num) < 1024.0:
            return f"{num:.1f} {unit}"
        num /= 1024.0
    return f"{num:.1f} PB"


# Start traffic monitor thread
_traffic_thread = threading.Thread(target=traffic_monitor_loop, daemon=True)
_traffic_thread.start()


# ============================================================================
# AUTOMATED OSINT ENGINE
# ============================================================================
_osint_state = {
    "queue": [],            # Pending investigations
    "results": [],          # Completed investigations
    "max_results": 500,     # Ring buffer
    "processing": False,
    "current_target": None,
    "enabled": True,
    "stats": {
        "total_processed": 0,
        "ips_investigated": 0,
        "domains_investigated": 0,
        "threats_found": 0,
        "errors": 0,
    },
}


def enqueue_osint(target, source="lan_scan", target_type=None):
    """Add an IP or domain to the OSINT investigation queue."""
    target = target.strip()
    if not target:
        return

    # Auto-detect type if not specified
    if target_type is None:
        try:
            ip_address(target)
            target_type = "ip"
        except ValueError:
            target_type = "domain"

    # Deduplicate — don't re-queue if already processed or already queued
    existing_queued = any(q["target"] == target for q in _osint_state["queue"])
    existing_done = any(r["target"] == target for r in _osint_state["results"])
    if existing_queued or existing_done:
        return

    _osint_state["queue"].append({
        "target": target,
        "type": target_type,
        "source": source,
        "queued_at": datetime.now().isoformat(),
    })


def parse_nmap_for_hosts(nmap_output):
    """Extract IPs and hostnames from nmap output."""
    hosts = []
    for line in nmap_output.splitlines():
        line = line.strip()
        # Match: "Nmap scan report for hostname (192.168.1.50)"
        if line.startswith("Nmap scan report for"):
            parts = line.replace("Nmap scan report for", "").strip()
            if "(" in parts and ")" in parts:
                # hostname (ip) format
                hostname = parts.split("(")[0].strip()
                ip = parts.split("(")[1].replace(")", "").strip()
                if hostname and hostname != ip:
                    hosts.append({"target": hostname, "type": "domain"})
                hosts.append({"target": ip, "type": "ip"})
            else:
                # Just IP or just hostname
                try:
                    ip_address(parts)
                    hosts.append({"target": parts, "type": "ip"})
                except ValueError:
                    if parts:
                        hosts.append({"target": parts, "type": "domain"})

        # Match rDNS lines: "rDNS record for 192.168.1.50: hostname.local"
        if "rDNS record for" in line:
            try:
                ip_part = line.split("rDNS record for")[1].split(":")[0].strip()
                hostname_part = line.split(":", 2)[2].strip() if line.count(":") >= 2 else ""
                if hostname_part:
                    hosts.append({"target": hostname_part, "type": "domain"})
                if ip_part:
                    hosts.append({"target": ip_part, "type": "ip"})
            except Exception:
                pass

        # Match: "|_hostname: example.com" from host scripts
        if "|_hostname:" in line or "| hostname:" in line:
            hostname = line.split("hostname:")[1].strip()
            if hostname:
                hosts.append({"target": hostname, "type": "domain"})

    # Deduplicate
    seen = set()
    unique = []
    for h in hosts:
        if h["target"] not in seen:
            seen.add(h["target"])
            unique.append(h)
    return unique


def run_osint_investigation(target, target_type):
    """Run full OSINT investigation on an IP or domain. Returns structured results."""
    result = {
        "target": target,
        "type": target_type,
        "timestamp": datetime.now().isoformat(),
        "geo": None,
        "asn": None,
        "reverse_dns": None,
        "threat_score": None,
        "dns_records": None,
        "whois": None,
        "subdomains": None,
        "open_ports": None,
        "classification": "unknown",
        "notes": [],
    }

    # Resolve domain to IP if needed
    resolved_ip = target
    if target_type == "domain":
        try:
            resolved_ip = socket.gethostbyname(target)
            result["resolved_ip"] = resolved_ip
        except Exception:
            result["notes"].append("Could not resolve domain to IP")
            resolved_ip = None

    # IP Intelligence (geolocation + ASN)
    if resolved_ip:
        ip_data = ip_lookup(resolved_ip)
        if "error" not in ip_data:
            result["geo"] = {
                "country": ip_data.get("country", ""),
                "region": ip_data.get("region", ""),
                "city": ip_data.get("city", ""),
                "lat": ip_data.get("lat", 0),
                "lon": ip_data.get("lon", 0),
                "isp": ip_data.get("isp", ""),
                "org": ip_data.get("org", ""),
            }
            result["asn"] = ip_data.get("as", "")
            result["reverse_dns"] = ip_data.get("reverse_dns", "")

            # Threat check if API key is available
            if os.getenv("ABUSEIPDB_KEY"):
                threat = threat_check(resolved_ip)
                if "error" not in threat:
                    result["threat_score"] = threat.get("abuse_score", 0)
                    if result["threat_score"] > 50:
                        result["classification"] = "malicious"
                        _osint_state["stats"]["threats_found"] += 1
                    elif result["threat_score"] > 20:
                        result["classification"] = "suspicious"
                    else:
                        result["classification"] = "clean"
        else:
            result["notes"].append("IP lookup failed")
            _osint_state["stats"]["errors"] += 1

    # Domain-specific OSINT
    if target_type == "domain":
        # DNS records
        try:
            dns_data = dns_lookup(target)
            if dns_data:
                result["dns_records"] = dns_data
                # Check for suspicious DNS configs
                a_records = dns_data.get("A", [])
                if a_records and resolved_ip and resolved_ip not in a_records:
                    result["notes"].append(f"DNS A record mismatch: expected {resolved_ip}")
        except Exception as e:
            result["notes"].append(f"DNS lookup failed: {e}")

        # Subdomain enumeration
        try:
            subs = subdomain_enum(target)
            if subs:
                result["subdomains"] = subs
                # Queue subdomains for investigation too
                for sub in subs[:10]:  # Limit to first 10 to avoid flooding
                    enqueue_osint(sub, source=f"subdomain:{target}", target_type="domain")
        except Exception:
            pass

        # WHOIS
        try:
            whois_data = whois_lookup(target)
            if whois_data and "error" not in whois_data:
                result["whois"] = whois_data.get("raw", "")[:2000]
        except Exception:
            pass

    # Classify if not already classified
    if result["classification"] == "unknown":
        if result["reverse_dns"] and "No PTR" not in result["reverse_dns"]:
            result["classification"] = "identified"
        elif result["geo"]:
            result["classification"] = "located"
        else:
            result["classification"] = "unknown"

    return result


def osint_worker_loop():
    """Background thread — processes the OSINT queue."""
    logger.info("OSINT worker thread starting")
    while True:
        if not _osint_state["enabled"] or not _osint_state["queue"]:
            time.sleep(5)
            continue

        item = _osint_state["queue"].pop(0)
        target = item["target"]
        target_type = item["type"]

        _osint_state["processing"] = True
        _osint_state["current_target"] = target

        try:
            result = run_osint_investigation(target, target_type)
            _osint_state["results"].append(result)

            # Trim ring buffer
            if len(_osint_state["results"]) > _osint_state["max_results"]:
                _osint_state["results"].pop(0)

            # Update stats
            _osint_state["stats"]["total_processed"] += 1
            if target_type == "ip":
                _osint_state["stats"]["ips_investigated"] += 1
            else:
                _osint_state["stats"]["domains_investigated"] += 1

            # Log to activity
            classification = result["classification"]
            threat = result.get("threat_score", 0)
            country = result.get("geo", {}).get("country", "") if result.get("geo") else ""
            summary = f"{classification} | threat={threat} | {country}"
            log_activity("Auto-OSINT", target, summary, json.dumps(result)[:500])

            # Store in database
            db = get_db()
            db.execute(
                "INSERT OR REPLACE INTO ip_reports (ip, timestamp, threat_score, country, asn, raw_data, classification) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (target, result["timestamp"], threat or 0, country, result.get("asn", ""), json.dumps(result)[:5000], classification)
            )
            db.commit()
            db.close()

        except Exception as e:
            logger.exception("OSINT investigation of %s failed", target)
            _last_errors["osint"] = f"{datetime.now().isoformat()}: {e}"
            _osint_state["stats"]["errors"] += 1
            log_activity("Auto-OSINT", target, f"Error: {e}", "")
        finally:
            _osint_state["processing"] = False
            _osint_state["current_target"] = None

        # Small delay between investigations to avoid rate limiting
        time.sleep(3)


# Start OSINT worker thread
_osint_thread = threading.Thread(target=osint_worker_loop, daemon=True)
_osint_thread.start()


# ============================================================================
# DATABASE
# ============================================================================
def get_db():
    db = sqlite3.connect(DB_PATH)
    db.row_factory = sqlite3.Row
    return db


def init_db():
    db = get_db()
    db.executescript("""
        CREATE TABLE IF NOT EXISTS activity_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            action TEXT NOT NULL,
            target TEXT,
            result TEXT,
            details TEXT
        );

        CREATE TABLE IF NOT EXISTS known_devices (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT NOT NULL,
            mac TEXT,
            hostname TEXT,
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL,
            notes TEXT,
            UNIQUE(ip, mac)
        );

        CREATE TABLE IF NOT EXISTS ip_reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            threat_score INTEGER DEFAULT 0,
            country TEXT,
            asn TEXT,
            raw_data TEXT
        );

        CREATE TABLE IF NOT EXISTS cases (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            status TEXT DEFAULT 'open',
            created TEXT NOT NULL,
            updated TEXT NOT NULL,
            summary TEXT
        );

        CREATE TABLE IF NOT EXISTS case_entries (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            case_id INTEGER NOT NULL,
            timestamp TEXT NOT NULL,
            entry_type TEXT NOT NULL,
            content TEXT NOT NULL,
            FOREIGN KEY (case_id) REFERENCES cases(id)
        );
    """)
    db.commit()
    try:
        db.execute("ALTER TABLE ip_reports ADD COLUMN classification TEXT")
        db.commit()
    except sqlite3.OperationalError:
        pass  # column already exists
    db.close()


init_db()


def log_activity(action, target="", result="", details=""):
    db = get_db()
    db.execute(
        "INSERT INTO activity_log (timestamp, action, target, result, details) VALUES (?, ?, ?, ?, ?)",
        (datetime.now().isoformat(), action, target, result, details),
    )
    db.commit()
    db.close()


def trim_activity_log(max_rows=5000):
    db = get_db()
    db.execute(
        "DELETE FROM activity_log WHERE id NOT IN (SELECT id FROM activity_log ORDER BY id DESC LIMIT ?)",
        (max_rows,),
    )
    db.commit()
    db.close()


# ============================================================================
# AUTHENTICATION
# ============================================================================
def requires_auth(f):
    import base64
    @wraps(f)
    def decorated(*args, **kwargs):
        ip = request.remote_addr
        now = time.time()
        attempts = [t for t in _failed_logins.get(ip, []) if now - t < _LOGIN_LOCKOUT_WINDOW]
        if len(attempts) >= _LOGIN_LOCKOUT_THRESHOLD:
            return Response("Too many failed login attempts. Try again later.", 429)

        auth = request.authorization
        if not auth:
            return Response(
                "Authentication required", 401,
                {"WWW-Authenticate": "Basic realm='Command Center'"}
            )
        if auth.username != DASHBOARD_USER or auth.password != DASHBOARD_PASS:
            attempts.append(now)
            _failed_logins[ip] = attempts
            return Response(
                "Authentication required", 401,
                {"WWW-Authenticate": "Basic realm='Command Center'"}
            )
        _failed_logins.pop(ip, None)
        return f(*args, **kwargs)
    return decorated


# ============================================================================
# NETWORK UTILITIES
# ============================================================================
def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except Exception:
        return "127.0.0.1"
    finally:
        s.close()


def get_subnet():
    override = os.getenv("LAN_SUBNET_OVERRIDE")
    if override:
        return str(ip_network(override, strict=False))
    local_ip = get_local_ip()
    return str(ip_network(f"{local_ip}/24", strict=False))


def get_gateway():
    try:
        result = subprocess.run(
            ["ip", "route", "show", "default"],
            capture_output=True, text=True, timeout=5
        )
        for line in result.stdout.splitlines():
            if "default" in line:
                return line.split("via")[1].split()[0]
    except Exception:
        pass
    return None


def get_hostname(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return None


_MAC_RE = re.compile(r"\b([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})\b")


def get_mac_via_arp(ip):
    """Look up a device's MAC address from the local neighbor/ARP cache.

    Tries Linux's `ip neighbor show` first, then falls back to `arp -n`
    (works on both macOS/BSD and Linux systems with net-tools installed).
    Both commands scope their output to the single queried IP, so any
    MAC-shaped substring found is unambiguously the answer.
    """
    for cmd in (["ip", "neighbor", "show", ip], ["arp", "-n", ip]):
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=3)
            match = _MAC_RE.search(result.stdout)
            if match:
                return match.group(1)
        except Exception:
            continue
    return None


def get_known_devices_map():
    """Build an ip -> {mac, hostname} lookup from the known_devices table."""
    db = get_db()
    rows = db.execute("SELECT ip, mac, hostname FROM known_devices").fetchall()
    db.close()
    return {r["ip"]: {"mac": r["mac"] or "", "hostname": r["hostname"] or ""} for r in rows}


def get_latest_ip_reports_map():
    """Latest ip_reports row per IP, as {ip: {classification, threat_score, country, asn, timestamp}}."""
    db = get_db()
    rows = db.execute("""
        SELECT ip, threat_score, classification, country, asn, timestamp
        FROM ip_reports
        WHERE id IN (SELECT MAX(id) FROM ip_reports GROUP BY ip)
    """).fetchall()
    db.close()
    return {r["ip"]: dict(r) for r in rows}


def default_iface():
    try:
        result = subprocess.run(
            ["ip", "route", "get", "1.1.1.1"],
            capture_output=True, text=True, timeout=5, check=True,
        )
        return result.stdout.split("dev")[1].split()[0]
    except Exception:
        return None


def scan_port(ip, port, timeout=None):
    if timeout is None:
        timeout = LAN_SCAN_TIMEOUT
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            return sock.connect_ex((ip, port)) == 0
    except Exception:
        return False


def probe_host(ip, ports=None):
    if ports is None:
        ports = COMMON_PORTS
    open_ports = []
    for port in ports:
        if scan_port(str(ip), port):
            open_ports.append(port)
    return {"ip": str(ip), "ports": open_ports}


def scan_lan():
    subnet = ip_network(get_subnet(), strict=False)
    hosts = list(subnet.hosts())
    with ThreadPoolExecutor(max_workers=SCAN_WORKERS) as pool:
        results = pool.map(lambda ip: probe_host(ip), hosts)
    found = [host for host in results if host["ports"]]
    log_activity("LAN Scan", str(subnet), f"Found {len(found)} devices", json.dumps(found))
    return found


def record_devices_seen(devices, source="lan_scan_new_device"):
    """Upsert LAN devices into known_devices and enqueue OSINT for newly-seen ones."""
    now = datetime.now().isoformat()
    db = get_db()
    for d in devices:
        hostname = get_hostname(d["ip"]) or ""
        mac = d.get("mac") or get_mac_via_arp(d["ip"]) or ""
        existing = db.execute(
            "SELECT id FROM known_devices WHERE ip = ?", (d["ip"],)
        ).fetchone()
        if not existing:
            log_activity("NEW DEVICE DETECTED", d["ip"], "Unknown device joined network", json.dumps(d))
            if _osint_state["enabled"]:
                enqueue_osint(d["ip"], source=source, target_type="ip")
            db.execute(
                "INSERT INTO known_devices (ip, mac, hostname, first_seen, last_seen, notes) VALUES (?, ?, ?, ?, ?, '')",
                (d["ip"], mac, hostname, now, now),
            )
        else:
            db.execute(
                "UPDATE known_devices SET mac = CASE WHEN ? != '' THEN ? ELSE mac END, hostname = ?, last_seen = ? WHERE id = ?",
                (mac, mac, hostname, now, existing["id"]),
            )
    db.commit()
    db.close()


def _update_live_lan_state(devices):
    now = datetime.now().isoformat()
    with _live_lan_lock:
        _live_lan_state["devices"] = devices
        _live_lan_state["last_scan"] = now
        _live_lan_state["scanning"] = False
    record_devices_seen(devices)


def _live_lan_worker():
    logger.info("LAN monitor thread starting")
    while True:
        if not _live_lan_state["enabled"]:
            time.sleep(5)
            continue
        with _live_lan_lock:
            _live_lan_state["scanning"] = True
        try:
            devices = scan_lan()
            _update_live_lan_state(devices)
        except Exception as e:
            logger.exception("LAN scan cycle failed")
            _last_errors["lan_monitor"] = f"{datetime.now().isoformat()}: {e}"
            log_activity("LAN Monitor", "error", str(e), "")
            with _live_lan_lock:
                _live_lan_state["scanning"] = False
        with _live_lan_lock:
            interval = _live_lan_state["interval"]
        time.sleep(interval)


_live_lan_thread = threading.Thread(target=_live_lan_worker, daemon=True)
_live_lan_thread.start()


def arp_scan():
    """Use arp-scan if available, fall back to socket probing."""
    try:
        result = subprocess.run(
            ["sudo", "-n", "arp-scan", "--localnet", "--quiet"],
            capture_output=True, text=True, timeout=30
        )
        if result.returncode == 0:
            devices = []
            for line in result.stdout.strip().splitlines():
                parts = line.split()
                if len(parts) >= 2:
                    try:
                        ip_address(parts[0])
                        devices.append({
                            "ip": parts[0],
                            "mac": parts[1] if len(parts) > 1 else "",
                            "vendor": " ".join(parts[2:]) if len(parts) > 2 else ""
                        })
                    except ValueError:
                        continue
            log_activity("ARP Scan", "localnet", f"Found {len(devices)} devices", json.dumps(devices))
            return devices
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
    except Exception:
        pass

    # Fallback to socket probing
    subnet = ip_network(get_subnet(), strict=False)
    hosts = list(subnet.hosts())
    devices = []
    for host in hosts:
        if scan_port(str(host), 80, timeout=0.1) or scan_port(str(host), 443, timeout=0.1):
            mac = get_mac_via_arp(str(host)) or ""
            devices.append({"ip": str(host), "mac": mac, "vendor": ""})
    log_activity("Socket Scan", str(subnet), f"Found {len(devices)} devices", json.dumps(devices))
    return devices


# ============================================================================
# IP INTELLIGENCE
# ============================================================================
def ip_lookup(ip):
    """Geolocation + ASN via free ip-api.com"""
    try:
        resp = requests.get(f"http://ip-api.com/json/{ip}", timeout=10)
        data = resp.json()
        if data.get("status") == "success":
            result = {
                "ip": ip,
                "country": data.get("country", ""),
                "region": data.get("regionName", ""),
                "city": data.get("city", ""),
                "lat": data.get("lat", 0),
                "lon": data.get("lon", 0),
                "timezone": data.get("timezone", ""),
                "isp": data.get("isp", ""),
                "org": data.get("org", ""),
                "as": data.get("as", ""),
                "reverse_dns": reverse_dns(ip),
                "query_time": datetime.now().isoformat(),
            }
            log_activity("IP Lookup", ip, "Success", json.dumps(result))
            return result
    except Exception as e:
        log_activity("IP Lookup", ip, f"Error: {e}", "")
    return {"error": f"Could not look up {ip}"}


def reverse_dns(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return "No PTR record"


def whois_lookup(domain):
    """Basic WHOIS via whois CLI or RDAP fallback."""
    try:
        result = subprocess.run(
            ["whois", domain],
            capture_output=True, text=True, timeout=15
        )
        if result.returncode == 0 and result.stdout.strip():
            output = result.stdout[:5000]  # Truncate large output
            log_activity("WHOIS", domain, "Success", output[:500])
            return {"domain": domain, "raw": output}
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
    except Exception:
        pass

    # Fallback to RDAP
    try:
        resp = requests.get(f"https://rdap.org/domain/{domain}", timeout=10, headers={"Accept": "application/json"})
        if resp.status_code == 200:
            data = resp.json()
            output = json.dumps(data, indent=2)[:5000]
            log_activity("RDAP Lookup", domain, "Success", output[:500])
            return {"domain": domain, "raw": output, "source": "RDAP"}
    except Exception as e:
        log_activity("WHOIS", domain, f"Error: {e}", "")

    return {"error": f"Could not retrieve WHOIS for {domain}"}


def dns_lookup(domain):
    """DNS record enumeration using dnspython."""
    records = {}
    record_types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]
    try:
        import dns.resolver
        resolver = dns.resolver.Resolver()
        resolver.timeout = 5
        resolver.lifetime = 5
        for rtype in record_types:
            try:
                answers = resolver.resolve(domain, rtype)
                records[rtype] = [str(r) for r in answers]
            except Exception:
                records[rtype] = []
    except ImportError:
        # Fallback to dig
        for rtype in record_types:
            try:
                result = subprocess.run(
                    ["dig", "+short", domain, rtype],
                    capture_output=True, text=True, timeout=5
                )
                records[rtype] = [l for l in result.stdout.strip().splitlines() if l]
            except Exception:
                records[rtype] = []
    log_activity("DNS Lookup", domain, "Success", json.dumps(records))
    return records


def subdomain_enum(domain):
    """Enumerate subdomains via crt.sh certificate transparency logs."""
    subdomains = set()
    try:
        resp = requests.get(
            f"https://crt.sh/?q=%.{domain}&output=json",
            timeout=20,
            headers={"User-Agent": "Mozilla/5.0"}
        )
        if resp.status_code == 200:
            data = resp.json()
            for entry in data:
                name = entry.get("name_value", "")
                for sub in name.split("\n"):
                    sub = sub.strip().lower()
                    if sub and domain in sub:
                        subdomains.add(sub)
    except Exception:
        pass

    result = sorted(list(subdomains))
    log_activity("Subdomain Enum", domain, f"Found {len(result)} subdomains", json.dumps(result[:100]))
    return result


def threat_check(ip):
    """Check IP against AbuseIPDB (requires free API key)."""
    api_key = os.getenv("ABUSEIPDB_KEY", "")
    if not api_key:
        return {"error": "Set ABUSEIPDB_KEY environment variable for threat scoring"}
    try:
        resp = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            params={"ipAddress": ip, "maxAgeInDays": 90},
            headers={"Key": api_key, "Accept": "application/json"},
            timeout=10
        )
        if resp.status_code == 200:
            data = resp.json().get("data", {})
            result = {
                "ip": ip,
                "abuse_score": data.get("abuseConfidenceScore", 0),
                "country": data.get("countryCode", ""),
                "usage_type": data.get("usageType", ""),
                "isp": data.get("isp", ""),
                "domain": data.get("domain", ""),
                "total_reports": data.get("totalReports", 0),
                "last_reported": data.get("lastReportedAt", ""),
            }
            log_activity("Threat Check", ip, f"Score: {result['abuse_score']}", json.dumps(result))
            return result
    except Exception as e:
        log_activity("Threat Check", ip, f"Error: {e}", "")
    return {"error": f"Could not check threat score for {ip}"}


def shodan_lookup(ip):
    """Look up IP on Shodan (requires free API key)."""
    api_key = os.getenv("SHODAN_KEY", "")
    if not api_key:
        return {"error": "Set SHODAN_KEY environment variable for Shodan lookups"}
    try:
        resp = requests.get(
            f"https://api.shodan.io/shodan/host/{ip}",
            params={"key": api_key},
            timeout=10
        )
        if resp.status_code == 200:
            data = resp.json()
            result = {
                "ip": ip,
                "ports": data.get("ports", []),
                "hostnames": data.get("hostnames", []),
                "country": data.get("country_name", ""),
                "city": data.get("city", ""),
                "org": data.get("org", ""),
                "os": data.get("os", ""),
                "vulns": data.get("vulns", []),
                "tags": data.get("tags", []),
            }
            log_activity("Shodan Lookup", ip, "Success", json.dumps(result)[:500])
            return result
    except Exception as e:
        log_activity("Shodan Lookup", ip, f"Error: {e}", "")
    return {"error": f"No Shodan data for {ip}"}


# ============================================================================
# DIAGNOSTICS
# ============================================================================
def run_nmap(ip, ports=None):
    port_arg = ",".join(str(p) for p in ports) if ports else ""
    cmd = ["nmap", "-sV", "--version-intensity", "2", "-sC", "--script-timeout", "10s", "-T4", "-Pn", "--host-timeout", "90s"]
    if port_arg:
        cmd.extend(["-p", port_arg])
    cmd.append(ip)
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=NMAP_TIMEOUT)
        output = ANSI_ESCAPE.sub("", result.stdout.strip())
        log_activity("Nmap Scan", ip, "Completed", output[:500])

        # Parse nmap output for hosts and enqueue for OSINT
        hosts = parse_nmap_for_hosts(output)
        for host in hosts:
            if _osint_state["enabled"]:
                enqueue_osint(host["target"], source=f"nmap:{ip}", target_type=host["type"])

        return {"ok": True, "output": output}
    except subprocess.TimeoutExpired:
        return {"ok": False, "output": "nmap timed out"}
    except FileNotFoundError:
        return {"ok": False, "output": "nmap is not installed (apt install nmap)"}
    except Exception as e:
        return {"ok": False, "output": str(e)}


try:
    HAS_SUDO = os.geteuid() == 0 or subprocess.run(["sudo", "-n", "true"], capture_output=True, timeout=5).returncode == 0
except Exception:
    HAS_SUDO = False


def run_bettercap(ip, mode="recon"):
    if not HAS_SUDO:
        return {"ok": False, "output": "Passwordless sudo required for bettercap.\nRun: echo 'ALL=(ALL) NOPASSWD: /usr/bin/bettercap' | sudo tee /etc/sudoers.d/bettercap"}

    iface = os.getenv("BETTERCAP_IFACE") or default_iface()
    if not iface:
        return {"ok": False, "output": "Could not determine network interface"}

    if mode == "active":
        eval_cmd = (
            f"net.probe on; "
            f"set arp.spoof.targets {ip}; "
            f"set arp.spoof.internal false; "
            f"set arp.spoof.fullduplex true; "
            f"set net.sniff.verbose true; "
            f"set net.sniff.output /tmp/command_center_capture.pcap; "
            f"arp.spoof on; "
            f"net.sniff on; "
            f"sleep 10; "
            f"arp.spoof off; "
            f"net.sniff off; "
            f"net.show; "
            f"exit"
        )
        timeout = 30
    else:
        eval_cmd = "net.probe on; net.recon on; sleep 5; net.show; exit"
        timeout = 20

    try:
        result = subprocess.run(
            ["sudo", "-n", "bettercap", "-iface", iface, "-eval", eval_cmd],
            capture_output=True, text=True, timeout=timeout
        )
    except subprocess.TimeoutExpired:
        return {"ok": False, "output": "bettercap timed out"}
    except FileNotFoundError:
        return {"ok": False, "output": "bettercap is not installed (apt install bettercap)"}

    output = ANSI_ESCAPE.sub("", result.stdout + result.stderr)
    lines = [l for l in output.splitlines() if ip in l or "spoof" in l.lower() or "sniff" in l.lower()]

    if mode == "active":
        return {
            "ok": True,
            "output": "\n".join(lines) if lines else output.strip(),
            "warning": "ARP spoofing was active. Verify restoration: run 'arp -a'"
        }
    return {"ok": True, "output": "\n".join(lines) if lines else output.strip()}


# ============================================================================
# CAMERA STREAMING (Optional — requires opencv)
# ============================================================================
def try_open_stream(ip, port):
    try:
        import cv2
    except ImportError:
        return None, "opencv-python-headless not installed"

    for template in STREAM_TEMPLATES:
        url = template.format(ip=ip, port=port)
        cap = cv2.VideoCapture(url)
        if cap.isOpened():
            ok, _ = cap.read()
            if ok:
                cap.release()
                return cv2.VideoCapture(url), url
        cap.release()
    return None, None


def mjpeg_frames(capture, feed_id):
    try:
        while feed_id in _active_feeds and _active_feeds[feed_id]["running"]:
            ok, frame = capture.read()
            if not ok:
                break
            ok, jpeg = cv2.imencode(".jpg", frame, [cv2.IMWRITE_JPEG_QUALITY, 70])
            if not ok:
                break
            yield (b"--frame\r\nContent-Type: image/jpeg\r\n\r\n" + jpeg.tobytes() + b"\r\n")
    finally:
        capture.release()
        _active_feeds.pop(feed_id, None)


# ============================================================================
# CASE MANAGEMENT
# ============================================================================
def create_case(title, summary=""):
    db = get_db()
    now = datetime.now().isoformat()
    cur = db.execute(
        "INSERT INTO cases (title, status, created, updated, summary) VALUES (?, 'open', ?, ?, ?)",
        (title, now, now, summary)
    )
    db.commit()
    case_id = cur.lastrowid
    db.close()
    log_activity("Case Created", str(case_id), title, summary)
    return case_id


def add_case_entry(case_id, entry_type, content):
    db = get_db()
    now = datetime.now().isoformat()
    db.execute(
        "INSERT INTO case_entries (case_id, timestamp, entry_type, content) VALUES (?, ?, ?, ?)",
        (case_id, now, entry_type, content)
    )
    db.execute("UPDATE cases SET updated = ? WHERE id = ?", (now, case_id))
    db.commit()
    db.close()
    log_activity("Case Entry", str(case_id), entry_type, content[:200])


# ============================================================================
# FLASK ROUTES
# ============================================================================
@app.route("/")
@requires_auth
def index():
    return render_template("index.html")


@app.route("/api/status")
@requires_auth
def api_status():
    local_ip = get_local_ip()
    subnet = get_subnet()
    gateway = get_gateway()
    iface = default_iface()
    has_nmap = subprocess.run(["which", "nmap"], capture_output=True).returncode == 0
    has_bettercap = subprocess.run(["which", "bettercap"], capture_output=True).returncode == 0
    has_opencv = False
    try:
        import cv2
        has_opencv = True
    except ImportError:
        pass
    has_sudo = HAS_SUDO

    return jsonify({
        "local_ip": local_ip,
        "subnet": subnet,
        "gateway": gateway,
        "interface": iface,
        "capabilities": {
            "nmap": has_nmap,
            "bettercap": has_bettercap,
            "opencv": has_opencv,
            "sudo": has_sudo,
            "sudo_bettercap": has_sudo and has_bettercap,
        },
        "tools": {
            "abuseipdb": bool(os.getenv("ABUSEIPDB_KEY")),
            "shodan": bool(os.getenv("SHODAN_KEY")),
        },
        "timestamp": datetime.now().isoformat(),
    })


@app.route("/api/debug")
@requires_auth
def api_debug():
    try:
        import psutil
        interfaces = {
            name: [addr.address for addr in addrs if addr.family in (socket.AF_INET, socket.AF_INET6)]
            for name, addrs in psutil.net_if_addrs().items()
        }
    except Exception as e:
        interfaces = {"error": str(e)}

    tools = {}
    for tool in ("nmap", "bettercap", "arp-scan", "arp", "ip", "nmcli", "whois", "dig"):
        tools[tool] = shutil.which(tool) is not None

    return jsonify({
        "system": {
            "platform": platform.system(),
            "platform_release": platform.release(),
            "python_version": platform.python_version(),
        },
        "network": {
            "local_ip": get_local_ip(),
            "subnet": get_subnet(),
            "gateway": get_gateway(),
            "default_interface": default_iface(),
            "subnet_override_active": bool(os.getenv("LAN_SUBNET_OVERRIDE")),
            "bettercap_iface_override_active": bool(os.getenv("BETTERCAP_IFACE")),
            "all_interfaces": interfaces,
        },
        "tools": tools,
        "threads": {
            "lan_monitor": {
                "alive": _live_lan_thread.is_alive(),
                "state": _live_lan_state,
                "last_error": _last_errors["lan_monitor"],
            },
            "traffic_monitor": {
                "alive": _traffic_thread.is_alive(),
                "enabled": _traffic_state["enabled"],
                "scanning": _traffic_state["scanning"],
                "interval": _traffic_state["interval"],
                "snapshot_count": len(_traffic_state["snapshots"]),
                "last_error": _last_errors["traffic_monitor"],
            },
            "osint_engine": {
                "alive": _osint_thread.is_alive(),
                "enabled": _osint_state["enabled"],
                "processing": _osint_state["processing"],
                "current_target": _osint_state["current_target"],
                "queue_size": len(_osint_state["queue"]),
                "results_count": len(_osint_state["results"]),
                "stats": _osint_state["stats"],
                "last_error": _last_errors["osint"],
            },
        },
        "api_keys": {
            "abuseipdb_configured": bool(os.getenv("ABUSEIPDB_KEY")),
            "shodan_configured": bool(os.getenv("SHODAN_KEY")),
        },
        "timestamp": datetime.now().isoformat(),
    })


# --- LAN MONITOR ---
@app.route("/api/lan/scan")
@requires_auth
def api_lan_scan():
    devices = scan_lan()
    _update_live_lan_state(devices)
    return jsonify({"devices": devices, "count": len(devices)})


@app.route("/api/lan/live")
@requires_auth
def api_lan_live():
    with _live_lan_lock:
        return jsonify({
            "enabled": _live_lan_state["enabled"],
            "scanning": _live_lan_state["scanning"],
            "last_scan": _live_lan_state["last_scan"],
            "devices": _live_lan_state["devices"],
        })


@app.route("/api/lan/toggle", methods=["POST"])
@requires_auth
def api_lan_toggle():
    with _live_lan_lock:
        _live_lan_state["enabled"] = not _live_lan_state["enabled"]
        enabled = _live_lan_state["enabled"]
    state = "enabled" if enabled else "disabled"
    log_activity("Config", "lan_monitor", f"Toggled {state}", "")
    return jsonify({"ok": True, "enabled": enabled})


@app.route("/api/lan/known")
@requires_auth
def api_lan_known():
    db = get_db()
    rows = db.execute("SELECT * FROM known_devices ORDER BY last_seen DESC").fetchall()
    db.close()
    reports = get_latest_ip_reports_map()
    devices = []
    for r in rows:
        d = dict(r)
        report = reports.get(d["ip"])
        d["classification"] = report["classification"] if report else None
        d["threat_score"] = report["threat_score"] if report else None
        devices.append(d)
    return jsonify({"devices": devices})


@app.route("/api/lan/interval", methods=["POST"])
@requires_auth
def api_lan_interval():
    data = request.json or {}
    try:
        interval = max(10, int(data.get("interval", 30)))
    except (TypeError, ValueError):
        return jsonify({"error": "Invalid interval"}), 400
    with _live_lan_lock:
        _live_lan_state["interval"] = interval
    return jsonify({"ok": True, "interval": interval})


@app.route("/api/lan/arp")
@requires_auth
def api_lan_arp():
    devices = arp_scan()
    record_devices_seen(devices, source="arp_scan_new_device")
    return jsonify({"devices": devices, "count": len(devices)})


@app.route("/api/lan/ports/<ip>")
@requires_auth
def api_lan_ports(ip):
    try:
        ip_address(ip)
    except ValueError:
        return jsonify({"error": "Invalid IP"}), 400
    ports = []
    for port in COMMON_PORTS:
        if scan_port(ip, port, timeout=1.0):
            ports.append(port)
    result = {"ip": ip, "open_ports": ports}
    log_activity("Port Scan", ip, f"Open: {ports}", json.dumps(result))
    return jsonify(result)


# --- IP INTELLIGENCE ---
@app.route("/api/ip/lookup/<path:target>")
@requires_auth
def api_ip_lookup(target):
    try:
        ip_address(target)
        is_ip = True
    except ValueError:
        is_ip = False

    devices = get_known_devices_map()

    if is_ip:
        result = ip_lookup(target)
        result["known_device"] = devices.get(target)
        return jsonify(result)
    else:
        # Domain — resolve to IP first
        try:
            resolved = socket.gethostbyname(target)
            ip_result = ip_lookup(resolved)
            dns_result = dns_lookup(target)
            whois_result = whois_lookup(target)
            subs = subdomain_enum(target)
            return jsonify({
                "domain": target,
                "resolved_ip": resolved,
                "ip_info": ip_result,
                "dns": dns_result,
                "whois": whois_result,
                "subdomains": subs,
                "known_device": devices.get(resolved),
            })
        except Exception as e:
            return jsonify({"error": str(e)}), 500


@app.route("/api/ip/threat/<ip>")
@requires_auth
def api_ip_threat(ip):
    return jsonify(threat_check(ip))


@app.route("/api/ip/shodan/<ip>")
@requires_auth
def api_ip_shodan(ip):
    return jsonify(shodan_lookup(ip))


@app.route("/api/osint/subdomains/<domain>")
@requires_auth
def api_osint_subdomains(domain):
    subs = subdomain_enum(domain)
    return jsonify({"domain": domain, "subdomains": subs, "count": len(subs)})


@app.route("/api/osint/dns/<domain>")
@requires_auth
def api_osint_dns(domain):
    records = dns_lookup(domain)
    return jsonify({"domain": domain, "records": records})


@app.route("/api/osint/whois/<domain>")
@requires_auth
def api_osint_whois(domain):
    return jsonify(whois_lookup(domain))


# --- DIAGNOSTICS ---
@app.route("/api/diagnose/<ip>")
@requires_auth
def api_diagnose(ip):
    try:
        ip_address(ip)
    except ValueError:
        return jsonify({"error": "Invalid IP"}), 400

    mode = request.args.get("mode", "recon")
    confirm = request.args.get("confirm", "no")

    if request.remote_addr not in ("127.0.0.1", "::1"):
        return jsonify({
            "ip": ip,
            "nmap": {"ok": False, "output": "Diagnostics restricted to localhost"},
            "bettercap": {"ok": False, "output": "Diagnostics restricted to localhost"},
        })

    if mode == "active" and confirm != "yes":
        return jsonify({
            "error": "Active MITM mode requires &confirm=yes parameter",
            "warning": "ARP spoofing intercepts traffic. Unauthorized use is illegal.",
        })

    known_ports = None
    for d in _live_lan_state["devices"]:
        if d["ip"] == ip:
            known_ports = d["ports"]
            break
    scan_ports = known_ports if known_ports else COMMON_PORTS

    result = {
        "ip": ip,
        "nmap": run_nmap(ip, ports=scan_ports),
        "bettercap": run_bettercap(ip, mode=mode),
    }
    return jsonify(result)


# --- CAMERA FEEDS ---
@app.route("/api/stream/start/<ip>/<int:port>")
@requires_auth
def api_stream_start(ip, port):
    feed_id = hashlib.md5(f"{ip}:{port}".encode()).hexdigest()[:12]
    capture, stream_url = try_open_stream(ip, port)
    if capture is None:
        return jsonify({"error": f"Could not open stream for {ip}:{port}"}), 502
    _active_feeds[feed_id] = {"ip": ip, "port": port, "url": stream_url, "running": True, "capture": capture}
    log_activity("Camera Stream", f"{ip}:{port}", "Started", stream_url)
    return jsonify({"feed_id": feed_id, "url": stream_url})


@app.route("/api/stream/stop/<feed_id>")
@requires_auth
def api_stream_stop(feed_id):
    if feed_id in _active_feeds:
        _active_feeds[feed_id]["running"] = False
        log_activity("Camera Stream", feed_id, "Stopped", "")
        return jsonify({"ok": True})
    return jsonify({"error": "Feed not found"}), 404


@app.route("/stream/<feed_id>")
@requires_auth
def stream_feed(feed_id):
    if feed_id not in _active_feeds:
        return jsonify({"error": "Feed not found"}), 404
    capture = _active_feeds[feed_id]["capture"]
    return Response(mjpeg_frames(capture, feed_id), mimetype="multipart/x-mixed-replace; boundary=frame")


@app.route("/api/feeds")
@requires_auth
def api_feeds():
    return jsonify({
        "active_feeds": [
            {"feed_id": fid, "ip": f["ip"], "port": f["port"], "url": f["url"]}
            for fid, f in _active_feeds.items()
        ]
    })


# --- WIFI TRAFFIC MONITOR ---
@app.route("/api/traffic/live")
@requires_auth
def api_traffic_live():
    snap = _traffic_state.get("current")
    if not snap:
        return jsonify({"status": "waiting", "message": "First snapshot pending...", "interval": _traffic_state["interval"]})
    devices = get_known_devices_map()
    result = dict(snap)
    result["top_talkers"] = [
        {
            "ip": ip,
            "count": count,
            "mac": devices.get(ip, {}).get("mac", ""),
            "device_name": devices.get(ip, {}).get("hostname", ""),
        }
        for ip, count in snap.get("top_talkers", {}).items()
    ]
    return jsonify(result)


@app.route("/api/traffic/history")
@requires_auth
def api_traffic_history():
    limit = request.args.get("limit", 60, type=int)
    snaps = _traffic_state["snapshots"][-limit:]
    return jsonify({
        "history": [{
            "timestamp": s["timestamp"],
            "bytes_sent": s["total_bytes_sent"],
            "bytes_recv": s["total_bytes_recv"],
            "connections": s["connection_count"],
        } for s in snaps],
        "count": len(snaps),
    })


@app.route("/api/traffic/connections")
@requires_auth
def api_traffic_connections():
    limit = request.args.get("limit", 50, type=int)
    conns = _traffic_state.get("connections", [])[:limit]
    devices = get_known_devices_map()
    enriched = []
    for c in conns:
        ip = c["raddr"].rsplit(":", 1)[0] if ":" in c["raddr"] else ""
        info = devices.get(ip, {})
        enriched.append({**c, "mac": info.get("mac", ""), "device_name": info.get("hostname", "")})
    return jsonify({"connections": enriched, "count": len(enriched)})


@app.route("/api/traffic/wifi")
@requires_auth
def api_traffic_wifi():
    return jsonify({
        "networks": _traffic_state.get("wifi_networks", []),
        "count": len(_traffic_state.get("wifi_networks", [])),
    })


@app.route("/api/traffic/interval", methods=["POST"])
@requires_auth
def api_traffic_interval():
    data = request.json or {}
    new_interval = int(data.get("interval", 60))
    if new_interval < 10:
        new_interval = 10
    _traffic_state["interval"] = new_interval
    log_activity("Config", "traffic_interval", f"Set to {new_interval}s", "")
    return jsonify({"ok": True, "interval": new_interval})


@app.route("/api/traffic/toggle", methods=["POST"])
@requires_auth
def api_traffic_toggle():
    _traffic_state["enabled"] = not _traffic_state["enabled"]
    state = "enabled" if _traffic_state["enabled"] else "disabled"
    log_activity("Config", "traffic_monitor", f"Toggled {state}", "")
    return jsonify({"ok": True, "enabled": _traffic_state["enabled"]})


# --- AUTOMATED OSINT ENGINE ---
@app.route("/api/osint/auto/live")
@requires_auth
def api_osint_auto_live():
    return jsonify({
        "enabled": _osint_state["enabled"],
        "processing": _osint_state["processing"],
        "current_target": _osint_state["current_target"],
        "queue_size": len(_osint_state["queue"]),
        "queue": _osint_state["queue"][:20],
        "results_count": len(_osint_state["results"]),
        "stats": _osint_state["stats"],
    })


@app.route("/api/osint/auto/results")
@requires_auth
def api_osint_auto_results():
    limit = request.args.get("limit", 50, type=int)
    classification = request.args.get("classification", None)
    results = _osint_state["results"][-limit:]

    if classification and classification != "all":
        results = [r for r in results if r.get("classification") == classification]

    return jsonify({"results": results[::-1], "count": len(results)})


@app.route("/api/osint/auto/toggle", methods=["POST"])
@requires_auth
def api_osint_auto_toggle():
    _osint_state["enabled"] = not _osint_state["enabled"]
    state = "enabled" if _osint_state["enabled"] else "disabled"
    log_activity("Config", "auto_osint", f"Toggled {state}", "")
    return jsonify({"ok": True, "enabled": _osint_state["enabled"]})


@app.route("/api/osint/auto/queue")
@requires_auth
def api_osint_auto_queue():
    return jsonify({"queue": _osint_state["queue"], "count": len(_osint_state["queue"])})


@app.route("/api/osint/auto/clear", methods=["POST"])
@requires_auth
def api_osint_auto_clear():
    _osint_state["results"] = []
    log_activity("Config", "auto_osint", "Results cleared", "")
    return jsonify({"ok": True})


@app.route("/api/osint/auto/enqueue", methods=["POST"])
@requires_auth
def api_osint_auto_enqueue():
    data = request.json or {}
    target = data.get("target", "").strip()
    if not target:
        return jsonify({"error": "No target provided"}), 400
    enqueue_osint(target, source="manual", target_type=data.get("type"))
    return jsonify({"ok": True, "queue_size": len(_osint_state["queue"])})


# --- ACTIVITY LOG ---
@app.route("/api/activity")
@requires_auth
def api_activity():
    limit = request.args.get("limit", 100, type=int)
    db = get_db()
    rows = db.execute(
        "SELECT * FROM activity_log ORDER BY timestamp DESC LIMIT ?",
        (limit,)
    ).fetchall()
    db.close()
    return jsonify({"activity": [dict(r) for r in rows], "count": len(rows)})


@app.route("/api/activity/clear", methods=["POST"])
@requires_auth
def api_activity_clear():
    db = get_db()
    db.execute("DELETE FROM activity_log")
    db.commit()
    db.close()
    return jsonify({"ok": True})


# --- CASE MANAGEMENT ---
@app.route("/api/cases")
@requires_auth
def api_cases():
    db = get_db()
    rows = db.execute("SELECT * FROM cases ORDER BY updated DESC").fetchall()
    db.close()
    return jsonify({"cases": [dict(r) for r in rows]})


@app.route("/api/cases/create", methods=["POST"])
@requires_auth
def api_cases_create():
    data = request.json or {}
    title = data.get("title", "Untitled Case")
    summary = data.get("summary", "")
    case_id = create_case(title, summary)
    return jsonify({"ok": True, "case_id": case_id})


@app.route("/api/cases/<int:case_id>/delete", methods=["POST"])
@requires_auth
def api_cases_delete(case_id):
    db = get_db()
    db.execute("DELETE FROM case_entries WHERE case_id = ?", (case_id,))
    db.execute("DELETE FROM cases WHERE id = ?", (case_id,))
    db.commit()
    db.close()
    log_activity("Case Deleted", str(case_id), "", "")
    return jsonify({"ok": True})


@app.route("/api/cases/<int:case_id>/entries")
@requires_auth
def api_case_entries(case_id):
    db = get_db()
    rows = db.execute(
        "SELECT * FROM case_entries WHERE case_id = ? ORDER BY timestamp ASC",
        (case_id,)
    ).fetchall()
    db.close()
    return jsonify({"entries": [dict(r) for r in rows]})


@app.route("/api/cases/<int:case_id>/entries/add", methods=["POST"])
@requires_auth
def api_case_entries_add(case_id):
    data = request.json or {}
    entry_type = data.get("type", "note")
    content = data.get("content", "")
    add_case_entry(case_id, entry_type, content)
    return jsonify({"ok": True})


# ============================================================================
# MAIN
# ============================================================================
if __name__ == "__main__":
    print("=" * 60)
    print("  SURVEILLANCE COMMAND CENTER")
    print(f"  Login: {DASHBOARD_USER} / {DASHBOARD_PASS}")
    print("  Open: http://localhost:8000")
    print("=" * 60)
    print()
    print("  Capabilities detected at runtime:")
    print("  - nmap:", subprocess.run(["which", "nmap"], capture_output=True).returncode == 0)
    print("  - bettercap:", subprocess.run(["which", "bettercap"], capture_output=True).returncode == 0)
    try:
        import cv2
        print("  - opencv: True")
    except ImportError:
        print("  - opencv: False")
    print("  - sudo:", check_sudo())
    print()
    print("  ⚠️  LEGAL: ARP spoofing / MITM is for authorized networks only.")
    print("=" * 60)
    print()

    app.run(host="0.0.0.0", port=8000, debug=False)