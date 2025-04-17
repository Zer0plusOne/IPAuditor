import requests
import json

status = ["[ALTO RIESGO]","[RIESGO MODERADO]","[BAJO RIESGO]"]

class Colors:
    RESET = "\033[0m"
    WHITE = "\033[97m"
    YELLOW = "\033[93m"
    RED = "\033[91m"

def get_ipinfo(ip, token=None):
    url = f"https://ipinfo.io/{ip}/json"
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    response = requests.get(url, headers=headers)
    return response.json()

def get_abuseipdb(ip, api_key):
    url = "https://api.abuseipdb.com/api/v2/check"
    params = {"ipAddress": ip, "maxAgeInDays": 90}
    headers = {"Key": api_key, "Accept": "application/json"}
    response = requests.get(url, headers=headers, params=params)
    return response.json()

def get_ipqualityscore(ip, api_key):
    url = f"https://ipqualityscore.com/api/json/ip/{api_key}/{ip}"
    response = requests.get(url)
    return response.json()

def get_risk_status(abuse_score, fraud_score):
    if abuse_score >= 50 or fraud_score >= 50:
        return Colors.RED, status[0], "Esta IP presenta indicadores severos de comportamiento malicioso."
    elif abuse_score > 0 or fraud_score > 0:
        return Colors.YELLOW, status[1], "Esta IP tiene algunos indicios de riesgo, proceder con precaución."
    else:
        return Colors.WHITE, status[2], "No se detectaron amenazas significativas en esta IP."

def show_info(ip, ipinfo_token=None, abuseipdb_key=None, ipqs_key=None, save_report=False):
    print(f"\n{Colors.WHITE}[+] Información para IP: {ip}{Colors.RESET}\n")

    abuse_score = 0
    fraud_score = 0
    report = {"IP": ip}

    if ipinfo_token:
        info = get_ipinfo(ip, ipinfo_token)
        print(f"{Colors.WHITE}--- Geolocalización e ISP ---{Colors.RESET}")
        for key in ["ip", "hostname", "city", "region", "country", "loc", "org", "postal", "timezone"]:
            print(f"{Colors.WHITE}{key.capitalize()}: {info.get(key, 'N/A')}{Colors.RESET}")
        report["Geo_ISP"] = info

    if abuseipdb_key:
        abuse = get_abuseipdb(ip, abuseipdb_key)
        data = abuse.get("data", {})
        abuse_score = data.get('abuseConfidenceScore', 0)
        color = Colors.RED if abuse_score >= 50 else Colors.YELLOW if abuse_score > 0 else Colors.WHITE

        print(f"\n{Colors.WHITE}--- Reputación (AbuseIPDB) ---{Colors.RESET}")
        print(f"{Colors.WHITE}Abuso reportado: {data.get('totalReports', 0)} veces{Colors.RESET}")
        print(f"{color}Es riesgoso: {abuse_score}%{Colors.RESET}")
        report["AbuseIPDB"] = data

    if ipqs_key:
        quality = get_ipqualityscore(ip, ipqs_key)
        fraud_score = quality.get('fraud_score', 0)

        print(f"\n{Colors.WHITE}--- Análisis de conexión (IPQualityScore) ---{Colors.RESET}")

        vpn_color = Colors.RED if quality.get('vpn', False) else Colors.WHITE
        proxy_color = Colors.RED if quality.get('proxy', False) else Colors.WHITE
        hosting_color = Colors.YELLOW if quality.get('hosting', False) else Colors.WHITE
        risk_color = Colors.RED if fraud_score >= 50 else Colors.YELLOW if fraud_score > 0 else Colors.WHITE

        print(f"{vpn_color}Es VPN: {quality.get('vpn', False)}{Colors.RESET}")
        print(f"{proxy_color}Es Proxy: {quality.get('proxy', False)}{Colors.RESET}")
        print(f"{hosting_color}Es Hosting: {quality.get('hosting', False)}{Colors.RESET}")
        print(f"{risk_color}Riesgo: {fraud_score}{Colors.RESET}")
        report["IPQualityScore"] = quality

    # Evaluación general de la IP
    print(f"\n{Colors.WHITE}--- Evaluación General de la IP ---{Colors.RESET}")
    color, risk_status, message = get_risk_status(abuse_score, fraud_score)
    print(f"{color}{risk_status} {message}{Colors.RESET}")
    report["Evaluacion"] = {"Estado": risk_status, "Mensaje": message}

    if save_report:
        filename = f"informe_{ip.replace('.', '_')}.json"
        with open(filename, "w") as f:
            json.dump(report, f, indent=4)
        print(f"\n{Colors.YELLOW}[+] Informe guardado como {filename}{Colors.RESET}")

if __name__ == "__main__":
    ip_to_check = input("Introduce la IP a analizar: ")
    save = input("¿Deseas guardar el informe? (y/n): ").strip().lower()

    
    IPINFO_TOKEN = ""  
    ABUSEIPDB_KEY = "" 
    IPQS_KEY = ""      

    save_report = True if save == "y" else False
    show_info(ip_to_check, IPINFO_TOKEN, ABUSEIPDB_KEY, IPQS_KEY, save_report)
