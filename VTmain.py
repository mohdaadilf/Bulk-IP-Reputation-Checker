import json
import truststore
import requests
import ipaddress
from credentials import vtapi

class style():
    RED = '\033[31m'
    GREEN = '\033[32m'
    BLUE = '\033[34m'
    RESET = '\033[0m'


truststore.inject_into_ssl()  # Inject truststore into the standard library ssl module so the functionality is used
# by every library by default. Removing this might make it faster
all_ips = []  # to have the sorted list

with open("ips.txt") as f:
    ips = f.readlines()

ips = [x.strip() for x in ips]  # remove new line char
print(ips)  # to show the ips

# to do - check if 1. IP is Valid and 2. If IP is Priv/Public

for ip in ips:
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"

    headers = {
        "accept": "application/json",
        "x-apikey": vtapi
    }

    try:
        response = requests.get(url, headers=headers,
                                timeout=5)  # resp = requests.post(url, headers=headers, data=data, )
        response.raise_for_status()
        print(f"response:{response}")

    except requests.HTTPError as ex:
        # possibly check response for a message
        raise ex  # let the caller handle it
    except requests.Timeout:
        # request took too long
        print("Timeout")
    # response = requests.get(url, headers=headers)

    if response.ok:
        resp = json.loads(response.text)
        ip = resp["data"]["id"]
        link = resp["data"]["links"]["self"]
        tags = resp["data"]["attributes"]["tags"]
        res = resp["data"]["attributes"]["last_analysis_stats"]
        temp = {'ip': ip, 'link': link, 'tags': tags, 'res': res}
        all_ips.append(temp)
        print(f"IP:{ip}\nTags:{json.dumps(tags, indent=2)}\n\nResult{json.dumps(res, indent=3)}")
        # print(f"Temp:{temp}\n\n")
        # print(f"All_Ips:{json.dumps(all_ips, indent = 3)}")
    else:
        print(f"error:{resp}")

sorted_ips = sorted(all_ips, key=lambda x: x["res"]["malicious"], reverse=True)

print(f"{style.RED}Sorted: {json.dumps(sorted_ips, indent=3)}{style.RESET}")