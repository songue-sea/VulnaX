import nmap
import requests
import json


def scan_target(target):
    """Effectue un scan Nmap sur la cible et récupère les ports/services ouverts."""
    nm = nmap.PortScanner()
    nm.scan(target, arguments='-sV')

    results = []
    for host in nm.all_hosts():
        for port in nm[host]['tcp']:
            service_info = nm[host]['tcp'][port]
            cpe = service_info.get('cpe', 'N/A')  # Ex: cpe:/a:apache:http_server:2.4.49
            results.append({
                'host': host,
                'port': port,
                'service': service_info.get('name', 'unknown'),
                'version': service_info.get('version', 'unknown'),
                'cpe': cpe
            })
    return results


def get_cve_for_cpe(cpe):
    """Interroge l'API CVE pour récupérer les vulnérabilités liées au CPE donné."""
    api_url = f"https://services.nvd.nist.gov/rest/json/cves/1.0?cpeMatchString={cpe}"
    try:
        response = requests.get(api_url)
        data = response.json()
        cves = [entry['cve']['CVE_data_meta']['ID'] for entry in data.get('result', {}).get('CVE_Items', [])]
        return cves
    except Exception as e:
        print(f"Erreur lors de la récupération des CVEs : {e}")
        return []


def scan_and_check_vulnerabilities(target):
    """Scanne un hôte et cherche les vulnérabilités associées."""
    results = scan_target(target)
    for entry in results:
        if entry['cpe'] != 'N/A':
            entry['cve'] = get_cve_for_cpe(entry['cpe'])
        else:
            entry['cve'] = []
    return results


if __name__ == "__main__":
    target = input("Entrez l'IP ou le domaine à scanner : ")
    results = scan_and_check_vulnerabilities(target)
    print(json.dumps(results, indent=4))
