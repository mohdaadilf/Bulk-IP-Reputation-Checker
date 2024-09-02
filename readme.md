# Bulk IP Reputation Lookup 🔍
This Python script aims to bulk check IPs reputation using multiple tools, currently focusing on VirusTotal, AbsueIPDB 
and IPQualityScore.  
The script utilizes the respective tools API to fetch information about the provided IP addresses. 
For more information on the APIs, please refer to the:   
- [Official VirusTotal documentation](https://docs.virustotal.com/reference/overview)  
- [Official AbsueIPDB documentation](https://docs.abuseipdb.com/#introduction)  
- [Official IPQualityScore documentation](https://www.ipqualityscore.com/documentation/proxy-detection-api/overview)  
- [Official OTXAlienVault documentation](https://otx.alienvault.com/api)

> [!NOTE] 
> ### Prerequisites    
  1. Ensure you have a separate Python file named `credentials.py`, where you need to supply your API keys.
Define the API key variable as `vt_api`, `aipdb_api` and `ipqs_api` within this file. Go to the respective tools 
docs/webpages to get your own api key (As of now OTXAlienVault doesn't need an API Key).
     2. You may also rename `credential.py.temp` to `credential.py` and edit the file as needed. `Credential.py` is already in `gitignore` as well.
2. Python 3.10 or later is recommended.
3. Some IPs to check against

### Disclaimer 
> [!WARNING]  
I am not responsible for any misuse of this script or its results. Use it responsibly and ensure compliance with all 
relevant laws and regulations. 

### Usage 
1. Ensure Python 3.10 or later is installed.
2. Provide your (VirusTotal) API key in the `credentials.py` file.
3. Save the IPs to check in `ips.txt`
4. The script can be run in 2 different ways:  
> [!NOTE]  
   A. You can either run `all.py` to check the IPs against all mentioned tools.   
   B. Or you can run `VTmain.py`, `AIPDBmain.py` or `IPQSmain.py` individually to check the IPs against specific tools.
    Running individual tools will give you some additional information, should you need it.   
   C. When running through the CLI you can set a custom timeout value. Default is 10 seconds.

> [!IMPORTANT]
> ### Additional Notes
- Certifi is used to eliminate any certificate issues.
- The script reads IP addresses from a file named `ips.txt` in the same directory. Ensure this file exists and contains the IP addresses you want to check.
- The sorted list of IPs (according to their result), along with their tags and analysis results, will be printed in the terminal.
- Add an argument to end of the scripts to set custom timeout value, default is 10.
```
Example to set timeout value to 30 seconds: python VTmain.py 30
```
  
### Example Output (all.py)

```bash
 1 {
   "ip": "x.x.x.x",,
   "AbuseIPDB": {
      "abuseConfidenceScore": 100,
      "isTor": true
   },
   "VT": {
      "malicious": 15,
      "suspicious": 2,
      "undetected": 20,
      "harmless": 54,
      "timeout": 0
   },
   "IPQS": {
      "fraud_score": 100,
      "isTor": true,
      "recent_abuse": true,
      "bot_status": true,
      "is_crawler": false,
      "proxy": true,
      "vpn": false
   },
      "OTX-A": {
      "reputation": 0,
      "validation": "x",
      "FP": "x"
    }
      ...
}
```
Please adjust the script and configurations according to your requirements and ensure compliance with all relevant terms of service.

#### Improvements to be made
- Perhaps one script execution with args rather than different scripts being executed.
- ~~Failover/Continuation of code even when one Tool fails~~
- ~~ASync requests, maybe?! => In progress. Reduced time for 8 IP searches from 20-25 seonds to 4-9 seconds!~~
- ~~Add more tools such as AlientVault~~