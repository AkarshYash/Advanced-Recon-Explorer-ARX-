import tkinter as tk
from tkinter import messagebox, scrolledtext, ttk, filedialog
import socket
import threading
import concurrent.futures
import webbrowser
from urllib.parse import urlparse
import pyttsx3
import requests
import re
import json
import csv
from datetime import datetime
import dns.resolver
import platform

# ====================== CONFIGURATION ======================
PORT_INFO = {
    21: ["FTP", "High", "Anonymous login", "Brute-force login", "Disable or secure FTP"],
    22: ["SSH", "Medium", "Weak keys", "Try Hydra", "Enforce key policies"],
    23: ["Telnet", "Critical", "Unencrypted login", "Exploit via Metasploit", "Disable Telnet"],
    25: ["SMTP", "Medium", "Open relay", "Test with telnet", "Configure properly"],
    53: ["DNS", "Medium", "Zone transfer", "dig AXFR", "Restrict transfers"],
    80: ["HTTP", "Medium", "Outdated CMS", "Use Nikto", "Update & enable WAF"],
    110: ["POP3", "Medium", "Clear-text auth", "Sniff traffic", "Use POP3S"],
    111: ["RPCbind", "High", "Info disclosure", "rpcinfo", "Restrict access"],
    135: ["MSRPC", "High", "DCE/RPC vulns", "rpcdump.py", "Block externally"],
    139: ["NetBIOS", "High", "SMB vulns", "nbtscan", "Disable SMBv1"],
    143: ["IMAP", "Medium", "Clear-text auth", "Sniff traffic", "Use IMAPS"],
    161: ["SNMP", "High", "Default strings", "snmpwalk", "Change community"],
    389: ["LDAP", "Medium", "Info disclosure", "ldapsearch", "Enable TLS"],
    443: ["HTTPS", "Low", "TLS misconfig", "Run SSLScan", "Patch OpenSSL"],
    445: ["SMB", "Critical", "EternalBlue", "MSF exploit", "Patch Windows"],
    465: ["SMTPS", "Medium", "Config issues", "Test auth", "Secure config"],
    512: ["rexec", "Critical", "No auth", "Try login", "Disable service"],
    513: ["rlogin", "Critical", "Trust vulns", "Try login", "Disable service"],
    514: ["syslog", "Medium", "UDP flood", "Test logging", "Secure config"],
    993: ["IMAPS", "Low", "Config issues", "Test auth", "Check certs"],
    995: ["POP3S", "Low", "Config issues", "Test auth", "Check certs"],
    1433: ["MSSQL", "High", "Weak auth", "SQL commands", "Restrict access"],
    1521: ["Oracle", "High", "Default creds", "sqlplus", "Change passwords"],
    1723: ["PPTP", "High", "MS-CHAP vulns", "chapcrack", "Use L2TP/IPsec"],
    2049: ["NFS", "High", "No auth", "showmount", "Restrict exports"],
    3306: ["MySQL", "High", "Default credentials", "Use SQLmap", "Restrict & harden"],
    3389: ["RDP", "High", "BlueKeep", "Check with MSF", "Patch & firewall"],
    5060: ["SIP", "Medium", "VLAN hopping", "sipvicious", "Secure config"],
    5432: ["PostgreSQL", "High", "Default creds", "psql", "Change passwords"],
    5900: ["VNC", "High", "Weak auth", "vncviewer", "Use SSH tunnel"],
    6379: ["Redis", "High", "No auth", "redis-cli", "Enable auth"],
    8080: ["HTTP-alt", "Medium", "Unsecured admin panel", "Dir brute", "Restrict access"],
    8443: ["HTTPS-alt", "Medium", "Web vulns", "Nikto scan", "Secure config"],
    8888: ["HTTP-alt2", "Medium", "Admin panels", "Dir brute", "Restrict access"],
    9100: ["JetDirect", "High", "Unauth access", "Send print job", "Firewall"],
    9200: ["Elastic", "High", "No auth", "curl queries", "Enable security"],
    27017: ["MongoDB", "High", "No auth", "mongo shell", "Enable auth"],
    49152: ["Win-RPC", "High", "DCE/RPC vulns", "rpcdump.py", "Block externally"],
}

TOP_PORTS = sorted(PORT_INFO.keys())
SUBDOMAIN_WORDLIST = ['www', 'mail', 'ftp', 'admin', 'webmail', 'server', 'ns1', 'ns2', 'smtp']

# ====================== AUTHOR INFORMATION ======================
AUTHOR_INFO = {
    "name": "Akarsh Chaturvedi",
    "linkedin": "https://www.linkedin.com/in/akarsh-chaturvedi-259271236",
    "github": "https://github.com/AkarshYash",
    "tagline": "For more security tools and projects"
}

# ====================== CORE FUNCTIONALITY ======================
class TargetInfo:
    def __init__(self, target):
        self.target = target
        self.ip = None
        self.hostname = None
        self.server_info = None
        self.device_type = None
        self.subdomains = []
        
    def gather_info(self):
        try:
            domain = urlparse(self.target).netloc or self.target
            self.ip = socket.gethostbyname(domain)
            try:
                self.hostname = socket.gethostbyaddr(self.ip)[0]
            except socket.herror:
                self.hostname = "Unknown"
            self.device_type = self.detect_device_type()
            self.server_info = "Will be detected during port scan"
        except Exception as e:
            raise Exception(f"Failed to gather target info: {e}")
    
    def detect_device_type(self):
        if self.ip.startswith(('192.168.', '10.', '172.')):
            return "Likely internal network device"
        return "Unknown (scan to determine)"
    
    def find_subdomains(self):
        domain = urlparse(self.target).netloc or self.target
        if '.' not in domain:
            return []
            
        base_domain = '.'.join(domain.split('.')[-2:])
        self.subdomains = []
        
        for sub in SUBDOMAIN_WORDLIST:
            full_domain = f"{sub}.{base_domain}"
            try:
                ip = socket.gethostbyname(full_domain)
                self.subdomains.append((full_domain, ip))
            except socket.gaierror:
                pass
        
        return self.subdomains

class PortScanner:
    def __init__(self):
        self.open_ports = []
        self.scan_results = []
        self.current_scan_id = None
        self.scan_history = []
        self.cancel_scan = False
        
    def scan_port(self, ip, port):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1.0)
                result = s.connect_ex((ip, port))
                
                if result == 0:
                    try:
                        banner = s.recv(1024).decode(errors='ignore').strip()
                        service, version = self.detect_version(banner)
                        return (port, True, banner, service, version)
                    except Exception:
                        return (port, True, None, None, None)
                else:
                    return (port, False, None, None, None)
        except Exception as e:
            print(f"Error scanning port {port}: {e}")
            return (port, False, None, None, None)
    
    def detect_version(self, banner):
        version_patterns = {
            "Apache": r"Apache/([\d.]+)",
            "nginx": r"nginx/([\d.]+)",
            "IIS": r"Microsoft-IIS/([\d.]+)",
            "OpenSSH": r"OpenSSH_([\w.]+)"
        }
        
        for service, pattern in version_patterns.items():
            match = re.search(pattern, banner, re.IGNORECASE)
            if match:
                return service, match.group(1)
        return None, None
    
    def get_cves_for_service(self, service, version=None):
        try:
            url = f"https://services.nvd.nist.gov/rest/json/cves/1.0?keyword={service}"
            if version:
                url += f" {version}"
            response = requests.get(url, timeout=5)
            data = response.json()
            return data.get("result", {}).get("CVE_Items", [])[:3]
        except Exception:
            return []

# ====================== GUI APPLICATION ======================
class PortScannerApp:
    def __init__(self, root):
        self.root = root
        self.target_info = None
        self.scanner = PortScanner()
        try:
            # Test TTS engine availability
            self.tts_engine = pyttsx3.init()
            self.tts_engine.setProperty('rate', 150)
            self.tts_available = True
        except Exception as e:
            print(f"Text-to-speech initialization warning: {str(e)}")
            self.tts_available = False
        self.setup_ui()
        
    def setup_ui(self):
        self.root.title(f"🕵️‍♂️ ADVANCED PORT EXPLOITER v3.0 | By {AUTHOR_INFO['name']}")
        self.root.geometry("900x700")
        self.root.config(bg="#121212")
        
        # Header with author info
        header_frame = tk.Frame(self.root, bg="#1a1a1a")
        header_frame.pack(fill="x", pady=5)
        
        tk.Label(header_frame, 
                text="CYBER RECON PORT EXPLOITER", 
                fg="#ff5555", bg="#1a1a1a",
                font=("Courier", 16, "bold")).pack(pady=5)
        
        author_frame = tk.Frame(header_frame, bg="#1a1a1a")
        author_frame.pack(pady=5)
        
        tk.Label(author_frame,
                text=f"By {AUTHOR_INFO['name']}",
                fg="#00ff00", bg="#1a1a1a",
                font=("Courier", 10)).pack(side="left", padx=5)
                
        # LinkedIn button
        linkedin_btn = tk.Button(author_frame,
                               text="LinkedIn",
                               command=lambda: webbrowser.open(AUTHOR_INFO['linkedin']),
                               font=("Courier", 8),
                               bg="#0077b5", fg="white",
                               relief="flat",
                               borderwidth=0)
        linkedin_btn.pack(side="left", padx=2)
        
        # GitHub button
        github_btn = tk.Button(author_frame,
                             text="GitHub",
                             command=lambda: webbrowser.open(AUTHOR_INFO['github']),
                             font=("Courier", 8),
                             bg="#333333", fg="white",
                             relief="flat",
                             borderwidth=0)
        github_btn.pack(side="left", padx=2)
        
        # Main container
        self.main_frame = tk.Frame(self.root, bg="#121212")
        self.main_frame.pack(fill="both", expand=True, padx=10, pady=5)
        
        self.show_target_entry_screen()
    
    def show_target_entry_screen(self):
        self.clear_frame()
        
        tk.Label(self.main_frame, 
                text="Enter target URL or IP address:",
                fg="#00ff00", bg="#121212",
                font=("Courier", 12)).pack(pady=10)
        
        self.target_entry = tk.Entry(self.main_frame, width=40, 
                                   font=("Courier", 12),
                                   bg="#222222", fg="#ffffff",
                                   insertbackground="#ffffff")
        self.target_entry.pack(pady=10)
        
        tk.Button(self.main_frame, 
                 text="START ANALYSIS", 
                 command=self.start_analysis,
                 font=("Courier", 12, "bold"),
                 bg="#ff5555", fg="white",
                 activebackground="#ff3333",
                 activeforeground="white").pack(pady=20)
        
        # Author footer
        footer_frame = tk.Frame(self.main_frame, bg="#121212")
        footer_frame.pack(side="bottom", fill="x", pady=10)
        
        tk.Label(footer_frame,
                text=f"Developed by {AUTHOR_INFO['name']}",
                fg="#666666", bg="#121212",
                font=("Courier", 9)).pack(side="left", padx=10)
                
        tk.Button(footer_frame,
                 text="GitHub",
                 command=lambda: webbrowser.open(AUTHOR_INFO['github']),
                 font=("Courier", 8),
                 bg="#333333", fg="white",
                 relief="flat").pack(side="left", padx=2)
                 
        tk.Button(footer_frame,
                 text="LinkedIn",
                 command=lambda: webbrowser.open(AUTHOR_INFO['linkedin']),
                 font=("Courier", 8),
                 bg="#0077b5", fg="white",
                 relief="flat").pack(side="left", padx=2)
    
    def start_analysis(self):
        target = self.target_entry.get().strip()
        if not target:
            messagebox.showerror("Error", "Please enter a target")
            return
        
        try:
            self.target_info = TargetInfo(target)
            self.target_info.gather_info()
            self.show_target_info_screen()
        except Exception as e:
            messagebox.showerror("Error", str(e))
    
    def show_target_info_screen(self):
        self.clear_frame()
        
        # Target information
        info_frame = tk.LabelFrame(self.main_frame, 
                                 text=" TARGET INFORMATION ",
                                 fg="#00ff00", bg="#1a1a1a",
                                 font=("Courier", 12))
        info_frame.pack(pady=10, padx=20, fill="x")
        
        info_text = f"""
        Target: {self.target_info.target}
        IP Address: {self.target_info.ip}
        Hostname: {self.target_info.hostname}
        Device Type: {self.target_info.device_type}
        Server Info: {self.target_info.server_info}
        """
        
        tk.Label(info_frame, 
                text=info_text,
                fg="#ffffff", bg="#1a1a1a", 
                font=("Courier", 10),
                justify="left").pack(pady=10, padx=10)
        
        # Buttons frame
        buttons_frame = tk.Frame(self.main_frame, bg="#121212")
        buttons_frame.pack(pady=20)
        
        tk.Button(buttons_frame,
                 text="FIND SUBDOMAINS",
                 command=self.find_subdomains,
                 font=("Courier", 10, "bold"),
                 bg="#5555ff", fg="white",
                 activebackground="#3333ff",
                 activeforeground="white").pack(side="left", padx=10)
        
        tk.Button(buttons_frame,
                 text="SCAN PORTS",
                 command=self.show_port_scan_screen,
                 font=("Courier", 10, "bold"),
                 bg="#ff5555", fg="white",
                 activebackground="#ff3333",
                 activeforeground="white").pack(side="left", padx=10)
        
        tk.Button(buttons_frame,
                 text="BACK",
                 command=self.show_target_entry_screen,
                 font=("Courier", 10),
                 bg="#666666", fg="white",
                 activebackground="#555555",
                 activeforeground="white").pack(side="left", padx=10)
    
    def find_subdomains(self):
        self.clear_frame()
        
        tk.Label(self.main_frame,
                text="SUBDOMAIN DISCOVERY",
                fg="#00ff00", bg="#121212",
                font=("Courier", 14, "bold")).pack(pady=10)
        
        tk.Label(self.main_frame,
                text=f"Searching subdomains for {self.target_info.target}...",
                fg="#ffffff", bg="#121212",
                font=("Courier", 10)).pack()
        
        self.subdomain_text = scrolledtext.ScrolledText(self.main_frame,
                                                      width=80, height=15,
                                                      font=("Courier", 9),
                                                      bg="#1a1a1a", fg="#ffffff",
                                                      insertbackground="#ffffff")
        self.subdomain_text.pack(pady=10)
        
        self.subdomain_text.tag_config("red", foreground="#ff5555")
        self.subdomain_text.tag_config("green", foreground="#00ff00")
        
        self.subdomain_text.insert(tk.END, f"Starting subdomain scan...\n", "green")
        self.root.update()
        
        threading.Thread(target=self.run_subdomain_scan, daemon=True).start()
    
    def run_subdomain_scan(self):
        subdomains = self.target_info.find_subdomains()
        
        self.subdomain_text.insert(tk.END, "\n=== SUBDOMAIN RESULTS ===\n", "green")
        for domain, ip in subdomains:
            self.subdomain_text.insert(tk.END, f"{domain} -> {ip}\n", "green")
        
        if not subdomains:
            self.subdomain_text.insert(tk.END, "No subdomains found\n", "red")
        
        self.subdomain_text.insert(tk.END, "\nSubdomain scan complete!\n", "green")
        
        tk.Button(self.main_frame,
                 text="CONTINUE TO PORT SCAN",
                 command=self.show_port_scan_screen,
                 font=("Courier", 10, "bold"),
                 bg="#ff5555", fg="white",
                 activebackground="#ff3333",
                 activeforeground="white").pack(pady=10)
    
    def show_port_scan_screen(self):
        self.clear_frame()
        
        tk.Label(self.main_frame,
                text="PORT SCANNING",
                fg="#00ff00", bg="#121212",
                font=("Courier", 14, "bold")).pack(pady=10)
        
        tk.Label(self.main_frame,
                text=f"Target: {self.target_info.target} ({self.target_info.ip})",
                fg="#ffffff", bg="#121212",
                font=("Courier", 11)).pack()
        
        # Progress bar
        self.scan_progress = ttk.Progressbar(self.main_frame, 
                                           length=600,
                                           style="red.Horizontal.TProgressbar")
        self.scan_progress.pack(pady=5)
        
        # Output text area
        self.scan_text = scrolledtext.ScrolledText(self.main_frame,
                                                 width=90, height=20,
                                                 font=("Courier", 9),
                                                 bg="#1a1a1a", fg="#ffffff",
                                                 insertbackground="#ffffff")
        self.scan_text.pack(pady=10)
        
        self.scan_text.tag_config("red", foreground="#ff5555")
        self.scan_text.tag_config("green", foreground="#00ff00")
        self.scan_text.tag_config("yellow", foreground="#ffff00")
        
        # Button frame
        button_frame = tk.Frame(self.main_frame, bg="#121212")
        button_frame.pack(pady=10)
        
        tk.Button(button_frame,
                 text="START PORT SCAN",
                 command=self.start_port_scan,
                 font=("Courier", 10, "bold"),
                 bg="#ff5555", fg="white",
                 activebackground="#ff3333",
                 activeforeground="white").pack(side="left", padx=5)
        
        tk.Button(button_frame,
                 text="CANCEL",
                 command=self.cancel_scanning,
                 font=("Courier", 10),
                 bg="#666666", fg="white",
                 activebackground="#555555",
                 activeforeground="white").pack(side="left", padx=5)
        
        tk.Button(button_frame,
                 text="BACK",
                 command=self.show_target_info_screen,
                 font=("Courier", 10),
                 bg="#666666", fg="white",
                 activebackground="#555555",
                 activeforeground="white").pack(side="left", padx=5)
    
    def start_port_scan(self):
        self.scanner.cancel_scan = False
        self.scan_progress["maximum"] = len(TOP_PORTS)
        self.scan_progress["value"] = 0
        
        self.scan_text.insert(tk.END, f"Starting port scan on {self.target_info.ip}...\n", "green")
        self.root.update()
        
        threading.Thread(target=self.run_port_scan, daemon=True).start()
    
    def cancel_scanning(self):
        self.scanner.cancel_scan = True
        self.scan_text.insert(tk.END, "\nScan cancelled by user\n", "red")
    
    def run_port_scan(self):
        self.scanner.open_ports = []
        self.scanner.scan_results = []
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
            futures = {
                executor.submit(self.scanner.scan_port, self.target_info.ip, port): port 
                for port in TOP_PORTS
            }
            
            for future in concurrent.futures.as_completed(futures):
                if self.scanner.cancel_scan:
                    break
                    
                try:
                    result = future.result()
                    if result is None:
                        continue
                        
                    port, is_open, banner, service, version = result
                    
                    # Update progress
                    self.scan_progress["value"] = len(self.scanner.scan_results) + len([p for p in self.scanner.open_ports if p != port])
                    self.root.update()
                    
                    if is_open:
                        self.scanner.open_ports.append(port)
                        scan_result = {
                            "port": port,
                            "status": "open",
                            "banner": banner,
                            "service": service,
                            "version": version,
                            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                        }
                        self.scanner.scan_results.append(scan_result)
                        
                        # Get CVEs for open services
                        if service:
                            cves = self.scanner.get_cves_for_service(service, version)
                            scan_result["cves"] = cves
                        
                        # Update UI
                        msg = f"[+] Port {port} OPEN"
                        if service:
                            msg += f" - {service}"
                        if version:
                            msg += f" v{version}"
                        if banner:
                            msg += f"\n    Banner: {banner[:100]}"
                        
                        self.scan_text.insert(tk.END, msg + "\n", "green")
                    else:
                        self.scan_text.insert(tk.END, f"[-] Port {port} CLOSED\n", "red")
                    
                    self.scan_text.see(tk.END)
                    self.root.update()
                    
                except Exception as e:
                    self.scan_text.insert(tk.END, f"[!] Error scanning port: {e}\n", "red")
                    self.root.update()
        
        if not self.scanner.cancel_scan:
            self.scan_text.insert(tk.END, "\nScan complete!\n", "green")
            
            tk.Button(self.main_frame,
                     text="VIEW FULL REPORT",
                     command=self.show_vulnerability_report,
                     font=("Courier", 10, "bold"),
                     bg="#5555ff", fg="white",
                     activebackground="#3333ff",
                     activeforeground="white").pack(pady=10)
    
    def show_vulnerability_report(self):
        report_window = tk.Toplevel(self.root)
        report_window.title(f"🔐 VULNERABILITY REPORT | By {AUTHOR_INFO['name']}")
        report_window.geometry("1200x700")
        report_window.config(bg="#121212")
        
        # Header
        header_frame = tk.Frame(report_window, bg="#1a1a1a")
        header_frame.pack(fill="x", pady=5)
        
        tk.Label(header_frame, 
                text=f"VULNERABILITY REPORT FOR {self.target_info.target}",
                fg="#ff5555", bg="#1a1a1a",
                font=("Courier", 14, "bold")).pack(pady=5)
        
        tk.Label(header_frame,
                text=f"IP: {self.target_info.ip} | Scanned on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
                fg="#ffffff", bg="#1a1a1a",
                font=("Courier", 10)).pack(pady=5)
        
        # Results frame
        results_frame = tk.Frame(report_window, bg="#121212")
        results_frame.pack(fill="both", expand=True, padx=10, pady=10)
        
        # Treeview for results
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("Treeview", 
                       background="#1a1a1a",
                       foreground="#ffffff",
                       fieldbackground="#1a1a1a")
        style.configure("Treeview.Heading", 
                       background="#333333",
                       foreground="#00ff00",
                       font=("Courier", 10, "bold"))
        style.map("Treeview", background=[("selected", "#5555ff")])
        
        columns = ("Port", "Service", "Version", "Risk", "Vulnerabilities")
        tree = ttk.Treeview(results_frame, columns=columns, show="headings", height=20)
        
        # Configure columns
        tree.column("Port", width=80, anchor="center")
        tree.column("Service", width=150, anchor="center")
        tree.column("Version", width=100, anchor="center")
        tree.column("Risk", width=80, anchor="center")
        tree.column("Vulnerabilities", width=250)
        
        # Create headings
        for col in columns:
            tree.heading(col, text=col)
        
        # Add scrollbar
        scrollbar = ttk.Scrollbar(results_frame, orient="vertical", command=tree.yview)
        tree.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side="right", fill="y")
        tree.pack(side="left", fill="both", expand=True)
        
        # Details frame
        details_frame = tk.Frame(report_window, bg="#1a1a1a", padx=10, pady=10)
        details_frame.pack(fill="x", padx=10, pady=5)
        
        tk.Label(details_frame, 
                text="PORT DETAILS:",
                fg="#00ff00", bg="#1a1a1a",
                font=("Courier", 10, "bold")).pack(anchor="w")
        
        self.details_text = scrolledtext.ScrolledText(details_frame,
                                                   width=120, height=6,
                                                   font=("Courier", 9),
                                                   bg="#222222", fg="#ffffff",
                                                   insertbackground="#ffffff")
        self.details_text.pack(fill="x")
        self.details_text.tag_config("red", foreground="#ff5555")
        self.details_text.tag_config("green", foreground="#00ff00")
        self.details_text.tag_config("yellow", foreground="#ffff00")
        
        # Button frame
        button_frame = tk.Frame(report_window, bg="#121212")
        button_frame.pack(pady=10)
        
        tk.Button(button_frame,
                 text="READ THIS PORT DETAILS",
                 command=lambda: self.read_current_port_details(tree),
                 font=("Courier", 10, "bold"),
                 bg="#5555ff", fg="white",
                 activebackground="#3333ff",
                 activeforeground="white").pack(side="left", padx=5)
        
        tk.Button(button_frame,
                 text="AUDIO REPORT (DETAILED)",
                 command=self.voice_report,
                 font=("Courier", 10, "bold"),
                 bg="#aa00ff", fg="white",
                 activebackground="#8800cc",
                 activeforeground="white").pack(side="left", padx=5)
        
        tk.Button(button_frame,
                 text="EXPORT RESULTS",
                 command=lambda: self.export_results(report_window),
                 font=("Courier", 10, "bold"),
                 bg="#5555ff", fg="white",
                 activebackground="#3333ff",
                 activeforeground="white").pack(side="left", padx=5)
        
        tk.Button(button_frame,
                 text="CLOSE",
                 command=report_window.destroy,
                 font=("Courier", 10),
                 bg="#666666", fg="white",
                 activebackground="#555555",
                 activeforeground="white").pack(side="left", padx=5)
        
        # Add data to treeview and store details for voice reporting
        self.port_details = {}
        for result in self.scanner.scan_results:
            if result["status"] == "open":
                port = result["port"]
                service = result.get("service", "Unknown")
                version = result.get("version", "Unknown")
                
                # Get port info
                port_info = PORT_INFO.get(port, ["Unknown", "Medium", "Unknown", "N/A", "N/A"])
                
                # Format CVEs
                cves = result.get("cves", [])
                if cves:
                    cve_text = "\n".join([f"{cve['cve']['CVE_data_meta']['ID']}" 
                                        for cve in cves[:3]])
                else:
                    cve_text = "No known CVEs"
                
                # Add to treeview
                tree.insert("", "end", values=(
                    port,
                    service,
                    version,
                    port_info[1],  # Risk
                    cve_text
                ))
                
                # Store detailed info for voice reporting
                details = {
                    "port": port,
                    "service": service,
                    "version": version,
                    "risk": port_info[1],
                    "vulnerability": port_info[2],
                    "next_steps": port_info[3],
                    "solution": port_info[4],
                    "banner": result.get("banner", ""),
                    "cves": cves
                }
                self.port_details[port] = details
        
        # Bind selection event
        tree.bind("<<TreeviewSelect>>", lambda e: self.show_port_details(tree))
        
        # Author footer
        footer_frame = tk.Frame(report_window, bg="#121212")
        footer_frame.pack(fill="x", pady=5)
        
        tk.Label(footer_frame,
                text=f"Tool developed by {AUTHOR_INFO['name']}",
                fg="#666666", bg="#121212",
                font=("Courier", 8)).pack(side="left", padx=10)
                
        tk.Button(footer_frame,
                 text="GitHub",
                 command=lambda: webbrowser.open(AUTHOR_INFO['github']),
                 font=("Courier", 8),
                 bg="#333333", fg="white",
                 relief="flat").pack(side="left", padx=2)
                 
        tk.Button(footer_frame,
                 text="LinkedIn",
                 command=lambda: webbrowser.open(AUTHOR_INFO['linkedin']),
                 font=("Courier", 8),
                 bg="#0077b5", fg="white",
                 relief="flat").pack(side="left", padx=2)
    
    def show_port_details(self, tree):
        selected = tree.focus()
        if not selected:
            return
            
        values = tree.item(selected, "values")
        if not values:
            return
            
        port = int(values[0])
        details = self.port_details.get(port)
        if not details:
            return
            
        self.details_text.delete("1.0", tk.END)
        
        # Format details display
        details_text = f"""
        Port: {details['port']} - {details['service']} {details.get('version', '')}
        Risk Level: {details['risk']}
        Vulnerability: {details['vulnerability']}
        Next Steps: {details['next_steps']}
        Solution: {details['solution']}
        """
        
        if details['banner']:
            details_text += f"\nBanner: {details['banner'][:200]}"
        
        if details['cves']:
            details_text += "\n\nCVEs:\n" + "\n".join(
                f"- {cve['cve']['CVE_data_meta']['ID']} ({cve['impact']['baseMetricV2']['severity']})"
                for cve in details['cves'][:3]
            )
        
        self.details_text.insert(tk.END, details_text.strip(), "green")
    
    def read_current_port_details(self, tree):
        selected = tree.focus()
        if not selected:
            messagebox.showwarning("Warning", "No port selected")
            return
            
        values = tree.item(selected, "values")
        if not values:
            return
            
        port = int(values[0])
        details = self.port_details.get(port)
        if not details:
            return
            
        if not self.tts_available:
            messagebox.showwarning("TTS Not Available", 
                                  "Text-to-speech engine is not available on this system.")
            return
            
        try:
            engine = pyttsx3.init()
            engine.setProperty("rate", 150)
            voices = engine.getProperty('voices')
            
            # Try to use a female voice if available
            for voice in voices:
                if 'female' in voice.name.lower():
                    engine.setProperty('voice', voice.id)
                    break
            
            # Detailed port information
            report = f"""
            Detailed security analysis for port {details['port']}.
            This port is running {details['service']} service.
            Detected version: {details.get('version', 'version not identified')}.
            Security risk level: {details['risk']}.
            
            The main vulnerability associated with this configuration is: 
            {details['vulnerability']}.
            
            Recommended penetration testing steps:
            {details['next_steps']}.
            
            For remediation, the suggested solution is:
            {details['solution']}.
            """
            
            # Add banner information if available
            if details['banner']:
                report += f"\nService banner information: {details['banner'][:200]}"
            
            # Add CVE details if available
            if details['cves']:
                report += "\n\nKnown associated vulnerabilities: "
                for cve in details['cves'][:3]:  # Limit to top 3 CVEs
                    severity = cve['impact']['baseMetricV2']['severity'] if 'impact' in cve else 'unknown severity'
                    report += f"\n- {cve['cve']['CVE_data_meta']['ID']}, classified as {severity}. "
                    if 'description' in cve['cve']:
                        description = cve['cve']['description']['description_data'][0]['value']
                        report += f"Description: {description[:150]}."  # Limit description length
            
            # Add port type information
            port_type = "Well-known port" if details['port'] < 1024 else "Registered port" if details['port'] < 49152 else "Dynamic/private port"
            report += f"\n\nPort type: {port_type}. "
            
            engine.say(report)
            engine.runAndWait()
        except Exception as e:
            messagebox.showerror("Text-to-Speech Error", f"Failed to read details: {str(e)}")
    
    def voice_report(self):
        if not self.tts_available:
            messagebox.showwarning("TTS Not Available", 
                                  "Text-to-speech engine is not available on this system.")
            return
            
        try:
            engine = pyttsx3.init()
            engine.setProperty("rate", 140)  # Slightly slower for comprehensive report
            voices = engine.getProperty('voices')
            
            # Try to use a female voice if available
            for voice in voices:
                if 'female' in voice.name.lower():
                    engine.setProperty('voice', voice.id)
                    break
            
            # Introduction
            engine.say(f"Comprehensive vulnerability report generated by Cyber Recon Port Exploiter")
            engine.say(f"Target scanned: {self.target_info.target}")
            engine.say(f"I P address: {' '.join(self.target_info.ip)}")
            engine.say(f"Scan performed on {datetime.now().strftime('%B %d, %Y at %H:%M')}")
            engine.say(f"Found {len(self.scanner.open_ports)} open ports with potential vulnerabilities")
            engine.runAndWait()
            
            # Detailed port reports
            for port, details in self.port_details.items():
                engine.say(f"Port {details['port']} analysis:")
                
                # Basic service info
                engine.say(f"Service: {details['service']}")
                if details.get('version'):
                    engine.say(f"Version: {details['version']}")
                
                # Port classification
                port_type = "Well-known port" if details['port'] < 1024 else "Registered port" if details['port'] < 49152 else "Dynamic or private port"
                engine.say(f"This is a {port_type}")
                
                # Risk information
                engine.say(f"Risk assessment: {details['risk']} risk level")
                engine.say(f"Primary vulnerability: {details['vulnerability']}")
                
                # Testing recommendations
                engine.say(f"Recommended testing approach: {details['next_steps']}")
                
                # Remediation
                engine.say(f"Recommended solution: {details['solution']}")
                
                # CVEs if available
                if details['cves']:
                    engine.say(f"Found {len(details['cves'])} known vulnerabilities:")
                    for i, cve in enumerate(details['cves'][:3], 1):  # Limit to top 3
                        cve_id = cve['cve']['CVE_data_meta']['ID']
                        severity = cve['impact']['baseMetricV2']['severity'] if 'impact' in cve else 'unknown severity'
                        engine.say(f"Vulnerability {i}: {cve_id}, severity: {severity}")
                        
                        if 'description' in cve['cve']:
                            desc = cve['cve']['description']['description_data'][0]['value']
                            engine.say(f"Description: {desc[:100]}")  # Shortened description
            
                engine.say("End of port analysis. Moving to next port.")
                engine.runAndWait()
            
            # Conclusion
            engine.say("Vulnerability report complete")
            engine.say(f"Tool developed by {AUTHOR_INFO['name']}")
            engine.say(f"Visit {AUTHOR_INFO['github']} for more security tools")
            engine.runAndWait()
            
        except Exception as e:
            messagebox.showerror("Text-to-Speech Error", f"Failed to generate voice report: {str(e)}")
    
    def export_results(self, parent_window):
        file_path = filedialog.asksaveasfilename(
            parent=parent_window,
            defaultextension=".json",
            filetypes=[("JSON", "*.json"), ("CSV", "*.csv"), ("All Files", "*.*")]
        )
        
        if not file_path:
            return
            
        try:
            data = {
                "target": self.target_info.target,
                "ip": self.target_info.ip,
                "scan_date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "developer": AUTHOR_INFO['name'],
                "developer_links": {
                    "linkedin": AUTHOR_INFO['linkedin'],
                    "github": AUTHOR_INFO['github']
                },
                "results": self.scanner.scan_results
            }
            
            if file_path.endswith(".json"):
                with open(file_path, "w") as f:
                    json.dump(data, f, indent=2)
            elif file_path.endswith(".csv"):
                with open(file_path, "w", newline="") as f:
                    writer = csv.writer(f)
                    writer.writerow(["Port", "Status", "Service", "Version", "Banner", "Risk", "Vulnerabilities", "Recommendation"])
                    for result in self.scanner.scan_results:
                        port_info = PORT_INFO.get(result["port"], ["Unknown", "Medium", "Unknown", "N/A", "N/A"])
                        cves = result.get("cves", [])
                        cve_text = "; ".join([cve['cve']['CVE_data_meta']['ID'] for cve in cves])
                        
                        writer.writerow([
                            result["port"],
                            result["status"],
                            result.get("service", ""),
                            result.get("version", ""),
                            result.get("banner", "")[:200],
                            port_info[1],
                            cve_text,
                            port_info[4]
                        ])
            
            messagebox.showinfo("Success", f"Results exported to {file_path}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to export: {e}")
    
    def clear_frame(self):
        for widget in self.main_frame.winfo_children():
            widget.destroy()

# ====================== MAIN EXECUTION ======================
if __name__ == "__main__":
    root = tk.Tk()
    
    # Configure ttk styles
    style = ttk.Style()
    style.theme_use("clam")
    style.configure("red.Horizontal.TProgressbar", 
                   troughcolor="#1a1a1a",
                   background="#ff5555",
                   bordercolor="#1a1a1a",
                   lightcolor="#ff5555",
                   darkcolor="#ff5555")
    
    app = PortScannerApp(root)
    root.mainloop()
            
           