import tkinter as tk
from tkinter import messagebox, scrolledtext
import socket
import threading
from urllib.parse import urlparse
import time

def resolve_and_scan():
    url = entry.get().strip()
    if not url:
        messagebox.showerror("Input Error", "Please enter a URL")
        return

    try:
        domain = urlparse(url).netloc or url
        ip = socket.gethostbyname(domain)
        output_box.insert(tk.END, f"\n[+]> DOMAIN: {domain}\n")
        output_box.insert(tk.END, f"[+]> IP ADDRESS: {ip}\n")
        output_box.insert(tk.END, f"[+] INITIATING FULL PORT SCAN (1–65535)...\n\n")
        threading.Thread(target=scan_ports, args=(ip,)).start()
    except Exception as e:
        output_box.insert(tk.END, f"[-] DOMAIN RESOLUTION FAILED: {e}\n")

def scan_ports(ip):
    port_counter = 0
    for port in range(1, 65536):  # Full port range
        port_counter += 1
        try:
            s = socket.socket()
            s.settimeout(0.3)
            s.connect((ip, port))
            try:
                banner = s.recv(1024).decode().strip()
                msg = f"[{port_counter:05d}] [+] Port {port} OPEN - Banner: {banner}"
            except:
                msg = f"[{port_counter:05d}] [+] Port {port} OPEN"
            s.close()
        except:
            msg = f"[{port_counter:05d}] [-] Port {port} CLOSED"
        output_box.insert(tk.END, msg + "\n")
        output_box.see(tk.END)  # Auto-scroll

    output_box.insert(tk.END, "\n[✓] FULL SCAN COMPLETE.\n")

# ───────── HACKER STYLE GUI ─────────
root = tk.Tk()
root.title("🕵️‍♂️ Cyber Recon Terminal")
root.geometry("800x600")
root.config(bg="black")

# Header
header = tk.Label(root, text="🟢 RECON-PORT-EXPLOITER", bg="black", fg="lime", font=("Courier", 18, "bold"))
header.pack(pady=10)

# URL input
entry_label = tk.Label(root, text="> ENTER TARGET URL/IP", bg="black", fg="lime", font=("Courier", 12))
entry_label.pack()
entry = tk.Entry(root, width=60, font=("Courier", 12), bg="black", fg="lime", insertbackground="lime")
entry.pack(pady=5)

# Scan button
scan_btn = tk.Button(root, text="START FULL SCAN", command=resolve_and_scan, bg="#00ff00", fg="black", font=("Courier", 12, "bold"))
scan_btn.pack(pady=10)

# Terminal Output Box
output_box = scrolledtext.ScrolledText(root, width=100, height=25, bg="black", fg="lime", font=("Courier", 10))
output_box.pack(padx=10, pady=10)

root.mainloop()
