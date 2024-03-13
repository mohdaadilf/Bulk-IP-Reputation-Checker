# Bulk IP Reputation Checker

This Python script aims to bulk check IPs reputation using multiple tools, currently focusing on VirusTotal. The script utilizes the VirusTotal API to fetch information about the provided IP addresses. For more information on the VirusTotal API, please refer to the [official documentation](https://docs.virustotal.com/reference/overview).

### Prerequisites

1. Ensure you have a separate Python file named `credentials.py`, where you need to supply your VirusTotal(VT) API key. Define the API key variable as `api` within this file (`vtapi`).
[Go to the VT and login to get your API key](https://www.virustotal.com/gui/my-apikey)

2. Python 3.10 or later is required to use the `truststore` package.

### Disclaimer

I am not responsible for any misuse of this script or its results. Use it responsibly and ensure compliance with all relevant laws and regulations.

### Usage

1. Ensure Python 3.10 or later is installed.
2. Provide your VirusTotal API key in the `credentials.py` file.
3. Run the script by executing `python VTmain.py` in your terminal.

### Additional Notes

- The `truststore` package is utilized to inject truststore into the standard library SSL module, ensuring its functionality is used by every library by default. 
- The script reads IP addresses from a file named `ips.txt` in the same directory. Ensure this file exists and contains the IP addresses you want to check.
- The sorted list of IPs, along with their tags and analysis results, will be printed in the terminal.

### Example Output

```bash
Sorted: [
   {
      "ip": "x.x.x.x",
      "link": "https://www.virustotal.com/ip-address/x.x.x.x/information/",
      "tags": ["tag1", "tag2"],
      "res": {
         "malicious": 5,
         "suspicious": 3,
         "undetected": 10
      }
   },
   ...
]
```
Please adjust the script and configurations according to your requirements and ensure compliance with all relevant terms of service.