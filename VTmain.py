import json
import truststore
import requests
import ipaddress
from credentials import vtapi
import os

os.system("color")  # enables ANSI escape sequences to color output; check
# https://stackoverflow.com/questions/287871/how-do-i-print-colored-text-to-the-terminal

# print(''.join([f'\033[{x}m{x} foo \33[0m \n' for x in range(0, 150)]))  # To check what colors are supported.
class style():
    RED = '\033[31m'
    RED_Highlighted = '\033[41m'
    GREEN = '\033[32m'
    YELLOW = '\033[33m'
    BLUE = '\033[36m'
    RESET = '\033[0m'


truststore.inject_into_ssl()  # Inject truststore into the standard library ssl module so the functionality is used
# by every library by default.

all_ips = []  # to have the sorted-final list

with open("ips.txt") as f:
    ips = f.readlines()
ips = [x.strip() for x in ips] # remove new line char
ips = list(set(ips))  # remove duplicates
print(ips)  # to show the ips

for ip in ips:
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        # 3. Handle invalid IP address format gracefully
        print(f"\n{style.RED}Entered IP '{ip}' is not a valid IP!{style.RESET}\n")
        continue

    if not address.is_private:
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
        headers = {
            "accept": "application/json",
            "x-apikey": vtapi
        }
        try:
            response = requests.get(url, headers=headers, timeout=5)
            response.raise_for_status()
            print(f"{response} for {ip}")

            resp = json.loads(response.text)
            ip = resp["data"]["id"]
            link = resp["data"]["links"]["self"]
            tags = resp["data"]["attributes"]["tags"]
            res = resp["data"]["attributes"]["last_analysis_stats"]
            if resp["data"]["attributes"]["last_analysis_stats"]["malicious"] > 2:
                print(f'{style.RED_Highlighted}{res}{style.RESET}')
            temp = {'ip': ip, 'link': link, 'tags': tags, 'res': res}
            all_ips.append(temp)
            # print(f"IP: {ip}\nTags: {json.dumps(tags, indent=2)}\nResult: {json.dumps(res, indent=3)}") # Printed
            # in 'sorted_ips' print(f"Temp:{temp}\n\n") print(f"All_Ips:{json.dumps(all_ips, indent = 3)}")
        except requests.HTTPError as ex:
            # possibly check response for a message
            print(f"Response for {address}: {style.YELLOW} {response.text}")
            raise ex  # let the caller handle it
        except requests.Timeout:
            # request took too long
            print("Timeout")
        # response = requests.get(url, headers=headers)
    elif address.is_private:
        print(f"\n{style.BLUE}Given IP {address} is Private{style.RESET}\n")
    else:
        print(f"{style.RED_Highlighted}Something gone terribly wrong. This line should never run{style.RESET}")

sorted_ips = sorted(all_ips, key=lambda x: (x["res"]["malicious"], x["res"]["suspicious"]), reverse=True)  # sort using
# malicious tag then suspicious tag
for i, result in enumerate(sorted_ips):
    if result['res']['malicious'] > 5:
        print(f"{style.RED_Highlighted} {i + 1} {json.dumps(result, indent=3)}{style.RESET}")
    elif result['res']['malicious'] > 2 or result['res']['suspicious'] > 1:
        print(f"{style.RED} {i + 1}: {json.dumps(result, indent=3)}{style.RESET}")
    elif result['res']['malicious'] > 0 or result['res']['suspicious'] > 0:
        print(f"{style.YELLOW} {i + 1}: {json.dumps(result, indent=3)}{style.RESET}")
    else:
        print(f"{style.GREEN} {i + 1}: {json.dumps(result, indent=3)}{style.RESET}")
