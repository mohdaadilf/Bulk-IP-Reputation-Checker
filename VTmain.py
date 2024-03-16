from credentials import vtapi
from common import *


for ip in ips:
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        # 3. Handle invalid IP address format gracefully
        print(f"\n{Style.RED}Entered IP '{ip}' is not a valid IP!{Style.RESET}\n")
        continue

    if not address.is_private:
        try:
            url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
            headers = {
                "accept": "application/json",
                "x-apikey": vtapi
            }
            response = requests.get(url, headers=headers, timeout=5)
            response.raise_for_status()
            print(f"{response} for {ip}")

            resp = json.loads(response.text)
            ip = resp["data"]["id"]
            link = resp["data"]["links"]["self"]
            tags = resp["data"]["attributes"]["tags"]
            res = resp["data"]["attributes"]["last_analysis_stats"]
            if resp["data"]["attributes"]["last_analysis_stats"]["malicious"] > 2:
                print(f'{Style.RED_Highlighted}{res}{Style.RESET}')
            temp = {'IP': ip, 'link': link, 'tags': tags, 'res': res}
            all_ips.append(temp)
            # print(f"IP: {ip}\nTags: {json.dumps(tags, indent=2)}\nResult: {json.dumps(res, indent=3)}") # Printed
            # in 'sorted_ips' print(f"Temp:{temp}\n\n") print(f"All_Ips:{json.dumps(all_ips, indent = 3)}")
        except requests.HTTPError as ex:
            # check response for a possible message
            print(f"Response for {address}: {Style.YELLOW} {response.text}")
            raise ex  # let the caller handle it
        except requests.Timeout:
            # request took too long
            print("Timeout")
        # response = requests.get(url, headers=headers)
    elif address.is_private:
        print(f"\n{Style.BLUE}Given IP {address} is Private{Style.RESET}\n")
    else:
        print(f"{Style.RED_Highlighted}Something gone terribly wrong. This line should never run{Style.RESET}")

sorted_ips = sorted(all_ips, key=lambda x: (x["res"]["malicious"], x["res"]["suspicious"]), reverse=True)  # sort using
# malicious tag then suspicious tag
for i, result in enumerate(sorted_ips):
    if result['res']['malicious'] > 5:
        print(f"{Style.RED_Highlighted} {i + 1} {json.dumps(result, indent=3)}{Style.RESET}")
    elif result['res']['malicious'] > 2 or result['res']['suspicious'] > 1:
        print(f"{Style.RED} {i + 1}: {json.dumps(result, indent=3)}{Style.RESET}")
    elif result['res']['malicious'] > 0 or result['res']['suspicious'] > 0:
        print(f"{Style.YELLOW} {i + 1}: {json.dumps(result, indent=3)}{Style.RESET}")
    else:
        print(f"{Style.GREEN} {i + 1}: {json.dumps(result, indent=3)}{Style.RESET}")
