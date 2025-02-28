import requests
CVE_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CPE_API_URL = f"{CVE_API_URL}?cpeName=cpe:2.3:"
def check_vuln(service):
   pass

def get_cve_from_cpe(cpeName):
    url = f"{CVE_API_URL}?cpeName={cpeName}"
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

if __name__ == "__main__":
    print(cve_from_keyword("oracle"))