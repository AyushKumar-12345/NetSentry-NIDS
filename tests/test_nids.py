import os
import shutil
import tempfile
import unittest
from scapy.all import Ether, ARP, IP, TCP, DNS, DNSRR, DNSQR
from nids import NetSentryEngine

class TestNetSentryNIDS(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.alert_log = os.path.join(self.test_dir, "test_alerts.json")
        self.config = {
            "interface": None,
            "alert_log": self.alert_log,
            "syn_flood_threshold": 5,
            "syn_flood_window_seconds": 2.0,
            "port_scan_threshold": 4,
            "port_scan_window_seconds": 2.0,
            "trusted_dns_servers": ["8.8.8.8"]
        }
        self.engine = NetSentryEngine(self.config)

    def tearDown(self):
        shutil.rmtree(self.test_dir)

    def test_arp_baseline_population(self):
        pkt = ARP(op=2, psrc="192.168.1.50", hwsrc="aa:bb:cc:dd:ee:ff")
        self.engine.packet_callback(pkt)
        self.assertEqual(self.engine.arp_table.get("192.168.1.50"), "aa:bb:cc:dd:ee:ff")
        self.assertEqual(len(self.engine.alert_history), 0)

    def test_arp_spoofing_detection(self):
        valid = ARP(op=2, psrc="192.168.1.1", hwsrc="11:22:33:44:55:66")
        spoofed = ARP(op=2, psrc="192.168.1.1", hwsrc="ff:ee:dd:cc:bb:aa")
        self.engine.packet_callback(valid)
        alert = self.engine.process_arp(spoofed)
        self.assertIsNotNone(alert)
        self.assertEqual(alert["alert_type"], "ARP_SPOOFING_DETECTED")
        self.assertEqual(alert["severity"], "CRITICAL")
        self.assertEqual(alert["details"]["ip"], "192.168.1.1")

    def test_syn_flood_detection(self):
        src_ip = "10.0.0.99"
        for _ in range(4):
            pkt = IP(src=src_ip, dst="10.0.0.1") / TCP(dport=80, flags="S")
            self.engine.packet_callback(pkt)
        self.assertEqual(len(self.engine.alert_history), 0)

        trigger_pkt = IP(src=src_ip, dst="10.0.0.1") / TCP(dport=80, flags="S")
        alert = self.engine.process_tcp(trigger_pkt)
        self.assertIsNotNone(alert)
        self.assertEqual(alert["alert_type"], "SYN_FLOOD_DETECTED")

    def test_port_scan_detection(self):
        src_ip = "10.0.0.88"
        for port in [21, 22, 23]:
            pkt = IP(src=src_ip, dst="10.0.0.1") / TCP(dport=port, flags="S")
            self.engine.packet_callback(pkt)
        self.assertEqual(len(self.engine.alert_history), 0)

        scan_pkt = IP(src=src_ip, dst="10.0.0.1") / TCP(dport=80, flags="S")
        alert = self.engine.process_tcp(scan_pkt)
        self.assertIsNotNone(alert)
        self.assertEqual(alert["alert_type"], "PORT_SCAN_DETECTED")

    def test_unauthorized_dns_detection(self):
        legit_pkt = IP(src="8.8.8.8", dst="192.168.1.5") / DNS(qr=1, qd=DNSQR(qname="google.com"), an=DNSRR(rrname="google.com", rdata="142.250.190.46"))
        self.engine.packet_callback(legit_pkt)
        self.assertEqual(len(self.engine.alert_history), 0)

        rogue_pkt = IP(src="192.168.1.200", dst="192.168.1.5") / DNS(qr=1, qd=DNSQR(qname="bank.com"), an=DNSRR(rrname="bank.com", rdata="1.2.3.4"))
        alert = self.engine.process_dns(rogue_pkt)
        self.assertIsNotNone(alert)
        self.assertEqual(alert["alert_type"], "UNAUTHORIZED_DNS_RESPONDER")

if __name__ == "__main__":
    unittest.main(verbosity=2)