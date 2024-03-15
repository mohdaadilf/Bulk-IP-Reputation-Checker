from credentials import aipdbapi
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
            days = 90
            url = 'https://api.abuseipdb.com/api/v2/check'
            querystring = {
                'ipAddress': ip,
                'maxAgeInDays': days
            }
            headers = {
                'Accept': 'application/json',
                'Key': aipdbapi
            }

            response = requests.request(method='GET', url=url, headers=headers, params=querystring)
            response.raise_for_status()
            print(f"{response} for {ip}")
            # Formatted output
            resp = json.loads(response.text)
            print(f'{json.dumps(resp, indent=4)}')
            ip = resp["data"]["ipAddress"]
            link = f"https://abuseipdb.com/check/{ip}"
            istor = resp["data"]["isTor"]
            res = resp["data"]["abuseConfidenceScore"]
            tr = resp["data"]["totalReports"]
            ndu = resp["data"]["numDistinctUsers"]
            iswhi = resp["data"]["isWhitelisted"]
            usage = resp["data"]["usageType"]
            if res > 25:
                print(f'{Style.RED_Highlighted}{res}{Style.RESET}')
            temp = {'ip': ip, 'link': link, 'isTor': istor, 'isWhitelisted':iswhi, 'abuseConfidenceScore': res,
                    'totalReports': tr, 'numDistinctUsers': ndu, 'usage': usage}
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

sorted_ips = sorted(all_ips, key=lambda x: (x['abuseConfidenceScore']), reverse=True)  # sort using
# malicious tag then suspicious tag
for i, result in enumerate(sorted_ips):
    if result['abuseConfidenceScore'] > 25:
        print(f"{Style.RED_Highlighted} {i + 1} {json.dumps(result, indent=3)}{Style.RESET}")
    elif result['abuseConfidenceScore'] > 10:
        print(f"{Style.RED} {i + 1}: {json.dumps(result, indent=3)}{Style.RESET}")
    elif result['abuseConfidenceScore'] > 2:
        print(f"{Style.YELLOW} {i + 1}: {json.dumps(result, indent=3)}{Style.RESET}")
    else:
        print(f"{Style.GREEN} {i + 1}: {json.dumps(result, indent=3)}{Style.RESET}")
