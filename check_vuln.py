import requests
CVE_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CPE_API_URL = f"{CVE_API_URL}?resultsPerPage=5&cpeName=cpe:2.3:"


def cve_from_keyword(keyword):
    url = f"{CVE_API_URL}?keywordSearch={keyword}&resultsPerPage=20"
    try:
        response = requests.get(url)
        if response.status_code == 200:
            data = response.json().get("vulnerabilities", [])
            return data
        else:
            return None
    except Exception as e:
        print("An error occurred:", e)

def get_cve_from_cpe(cpeName):
    url = f"{CPE_API_URL}{cpeName}"
    try:
        response = requests.get(url)
        if response.status_code  == 200:
            data = response.json()
            return data
        else:
            return None
    except Exception as e:
        print("An error occurred:", e)
        return None

def check_vuln(service):
    cpe_name = service.removeprefix("cpe:/")
    vuln = get_cve_from_cpe(cpe_name)
    if vuln:
        return vuln.get('vulnerabilities', [])
    else:
        return None


if __name__ == "__main__":
    print(check_vuln('cpe:/a:openbsd:openssh:5.3'))