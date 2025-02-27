import nmap
import requests
import json
from datetime import datetime
from fpdf import FPDF

# Configuration
TELEGRAM_BOT_TOKEN = "<my_token_bot>"
TELEGRAM_CHAT_ID = "<my_chat_ID>"
CVE_API_URL = "https://cve.circl.lu/api/search/"

# Scan Nmap



def scan(target):
    print(f"[+] Lancement du scan sur {target}")
    nm = nmap.PortScanner()
    nm.scan(target, '22', '--unprivileged -')
    print("[DEBUG] Résultats bruts de Nmap :")
    print(nm.command_line())  # Vérifie la commande exécutée
    print(nm.scaninfo())  # Infos sur le scan
    print(nm.all_hosts())  # Liste des hôtes trouvésc
    results = []
    for host in nm.all_hosts():
        for proto in nm[host].all_protocols():
            ports = nm[host][proto].keys()
            for port in ports:
                service = nm[host][proto][port]['name']
                print(f"{host}:{port} --> {service}")
                vuln = check_vuln(service)
                if vuln:
                    results.append({
                        'host': host,
                        'port': port,
                        'service': service,
                        'vulnerabilities': vuln
                    })

def check_vuln(service):
    try:
        url = CVE_API_URL + service
        response = requests.get(url)
        if response.status_code == 200:
            data = response.json()
            vulns = []
            for vuln in data[:3]: #limitation des infos
                vulns.append(f"{vuln['id']} - {vuln['summary']}")
            return vulns
        else:
            return []
    except Exception as e:
        print(f"[!] Erreur lors de la vérification de {service}:{e}")
        return []
if __name__ == "__main__":
    scan("10.1.5.2")