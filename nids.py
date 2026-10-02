import argparse
import collections
import json
import logging
import os
import sys
import time
from scapy.all import sniff, ARP, IP, TCP, DNS, DNSRR

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)

DEFAULT_CONFIG = {
    "interface": None,
    "alert_log": os.path.join("logs", "nids_alerts.json"),
    "syn_flood_threshold": 20,
    "syn_flood_window_seconds": 2.0,
    "port_scan_threshold": 15,
    "port_scan_window_seconds": 3.0,
    "trusted_dns_servers": ["8.8.8.8", "8.8.4.4", "1.1.1.1", "192.168.1.1"]
}

class NetSentryEngine:
    def __init__(self, config=None):
        self.config = config or DEFAULT_CONFIG
        self.arp_table = {}
        self.syn_tracker = collections.defaultdict(list)
        self.port_scan_tracker = collections.defaultdict(list)
        self.alert_history = []
        os.makedirs(os.path.dirname(self.config["alert_log"]), exist_ok=True)

    def log_alert(self, alert_type, severity, details):
        alert_record = {
            "timestamp": time.time(),
            "readable_time": time.strftime("%Y-%m-%d %H:%M:%S"),
            "alert_type": alert_type,
            "severity": severity,
            "details": details
        }
        self.alert_history.append(alert_record)
        log_func = logging.critical if severity == "CRITICAL" else logging.warning
        log_func(f"[{alert_type}] {details}")
        try:
            with open(self.config["alert_log"], "a", encoding="utf-8") as f:
                f.write(json.dumps(alert_record) + "\n")
        except OSError:
            pass
        return alert_record

    def process_arp(self, packet):
        if not packet.haslayer(ARP):
            return None
        arp_layer = packet[ARP]
        if arp_layer.op != 2:
            return None
        src_ip = arp_layer.psrc
        src_mac = arp_layer.hwsrc.lower()
        if src_ip in self.arp_table:
            known_mac = self.arp_table[src_ip]
            if known_mac != src_mac:
                return self.log_alert(
                    "ARP_SPOOFING_DETECTED",
                    "CRITICAL",
                    {
                        "ip": src_ip,
                        "original_mac": known_mac,
                        "spoofed_mac": src_mac
                    }
                )
        else:
            self.arp_table[src_ip] = src_mac
        return None

    def process_dns(self, packet):
        if not (packet.haslayer(DNS) and packet.haslayer(DNSRR)):
            return None
        dns_layer = packet[DNS]
        if dns_layer.qr != 1:
            return None
        if packet.haslayer(IP):
            src_ip = packet[IP].src
            trusted = self.config.get("trusted_dns_servers", [])
            if trusted and src_ip not in trusted:
                query_name = ""
                if dns_layer.qd:
                    try:
                        query_target = dns_layer.qd[0]
                    except (TypeError, IndexError):
                        query_target = dns_layer.qd
                    raw_name = getattr(query_target, "qname", b"")
                    if isinstance(raw_name, bytes):
                        query_name = raw_name.decode(errors="ignore")
                    else:
                        query_name = str(raw_name)
                return self.log_alert(
                    "UNAUTHORIZED_DNS_RESPONDER",
                    "WARNING",
                    {"responder_ip": src_ip, "query": query_name}
                )
        return None

    def process_tcp(self, packet):
        if not (packet.haslayer(IP) and packet.haslayer(TCP)):
            return None
        ip_layer = packet[IP]
        tcp_layer = packet[TCP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        dst_port = tcp_layer.dport
        flags = tcp_layer.flags
        now = time.time()

        if flags == "S":
            window = self.config["syn_flood_window_seconds"]
            self.syn_tracker[src_ip] = [t for t in self.syn_tracker[src_ip] if now - t <= window]
            self.syn_tracker[src_ip].append(now)
            if len(self.syn_tracker[src_ip]) >= self.config["syn_flood_threshold"]:
                return self.log_alert(
                    "SYN_FLOOD_DETECTED",
                    "CRITICAL",
                    {"source_ip": src_ip, "rate_per_sec": len(self.syn_tracker[src_ip]) / window}
                )

            ps_window = self.config["port_scan_window_seconds"]
            active_scans = [entry for entry in self.port_scan_tracker[src_ip] if now - entry[1] <= ps_window]
            active_scans.append((dst_port, now))
            self.port_scan_tracker[src_ip] = active_scans
            unique_ports = {p for p, t in active_scans}
            if len(unique_ports) >= self.config["port_scan_threshold"]:
                return self.log_alert(
                    "PORT_SCAN_DETECTED",
                    "WARNING",
                    {"source_ip": src_ip, "scanned_ports_count": len(unique_ports)}
                )

        return None

    def packet_callback(self, packet):
        self.process_arp(packet)
        self.process_dns(packet)
        self.process_tcp(packet)

    def start_sniffing(self, count=0):
        logging.info("Starting NetSentry-NIDS packet sniffer...")
        sniff(
            iface=self.config.get("interface"),
            prn=self.packet_callback,
            store=False,
            count=count
        )

def load_config(path):
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    return DEFAULT_CONFIG

def main():
    parser = argparse.ArgumentParser(description="NetSentry-NIDS Engine")
    parser.add_argument("--config", default="config/config.json", help="Path to config file")
    parser.add_argument("--iface", default=None, help="Network interface")
    parser.add_argument("--count", type=int, default=0, help="Packet capture limit (0 = infinite)")
    args = parser.parse_args()

    cfg = load_config(args.config)
    if args.iface:
        cfg["interface"] = args.iface

    engine = NetSentryEngine(cfg)
    try:
        engine.start_sniffing(count=args.count)
    except KeyboardInterrupt:
        logging.info("Stopping NetSentry-NIDS...")
        sys.exit(0)

if __name__ == "__main__":
    main()