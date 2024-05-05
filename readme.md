# Bulk IP Reputation Lookup 🔍
This Python script aims to bulk check IPs reputation using multiple tools, currently focusing on VirusTotal, AbsueIPDB 
and IPQualityScore.  
The script utilizes the respective tools API to fetch information about the provided IP addresses. 
For more information on the APIs, please refer to the:   
- [Official VirusTotal documentation](https://docs.virustotal.com/reference/overview)  
- [Official AbsueIPDB documentation](https://docs.abuseipdb.com/#introduction)  
- [Official IPQualityScore documentation](https://www.ipqualityscore.com/documentation/proxy-detection-api/overview)  

> [!NOTE] 
> ### Prerequisites    
  1. Ensure you have a separate Python file named `credentials.py`, where you need to supply your API keys.
Define the API key variable as `vt_api`, `aipdb_api` and `ipqs_api` within this file. Go to the respective tools 
docs/webpages to get your own api key.
2. Python 3.10 or later is required to use the `truststore` package.
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

> [!IMPORTANT]
> ### Additional Notes
- The `truststore` package is utilized to inject truststore into the standard library SSL module, ensuring its functionality is used by every library by default. 
- The script reads IP addresses from a file named `ips.txt` in the same directory. Ensure this file exists and contains the IP addresses you want to check.
- The sorted list of IPs (according to their result), along with their tags and analysis results, will be printed in the terminal.

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
   }
      ...
}
```
Please adjust the script and configurations according to your requirements and ensure compliance with all relevant terms of service.

#### Improvements to be made
- Failover/Continuation of code even when one Tool fails
- ASync requests, maybe?!