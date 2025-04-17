# IPAuditor

**IPAuditor** is a Python tool to collect and display extended information about an IP address: geolocation, ISP, VPN/proxy/hosting detection, IP reputation, and overall risk evaluation.

---

## Features

- IP Geolocation (country, city, region, latitude/longitude, ISP).
- Detection of suspicious connections (VPN, Proxy, Hosting).
- IP reputation with abuse reports.
- Color-coded risk indicators:
  - White: normal data.
  - Yellow: potential risk.
  - Red: high risk.
- Optional JSON report generation.

## Requirements

- Python 3.7 or higher
- Python libraries:
  ```bash
  pip install requests
  ```

## API Keys Setup (Optional)

Register for free at:

- [ipinfo.io](https://ipinfo.io/signup) for geolocation.
- [AbuseIPDB](https://www.abuseipdb.com/register) for IP reputation.
- [IPQualityScore](https://www.ipqualityscore.com/signup) for VPN/Proxy/Hosting detection.

Insert your API Keys into the code:
```python
IPINFO_TOKEN = "your_token"
ABUSEIPDB_KEY = "your_key"
IPQS_KEY = "your_key"
```

## Usage

1. Run the script:
   ```bash
   python3 ipaudit.py
   ```
2. Enter the IP address you want to audit.
3. Choose whether to save the report (`y/n`).

## Example Output

```bash
[+] Information for IP: 8.8.8.8

--- Geolocation and ISP ---
IP: 8.8.8.8
City: Mountain View
Region: California
Country: US
ISP: Google LLC

--- Reputation (AbuseIPDB) ---
Reported abuse: 0 times
Risk: 0%

--- Connection Analysis (IPQualityScore) ---
Is VPN: False
Is Proxy: False
Is Hosting: False
Risk Score: 0

--- General IP Evaluation ---
[LOW RISK] No significant threats detected for this IP.
```

## License

This project is licensed under the MIT License.

---

> "In defense, information is power."

