from credentials import ipqsapi
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
            url = f'https://ipqualityscore.com/api/json/ip/{ipqsapi}/{ip}'

            response = requests.request(method='GET', url=url)
            response.raise_for_status()
            print(f"{response} for {ip}")
            # Formatted output
            resp = json.loads(response.text)
            # print(f'{json.dumps(resp, indent=4)}')
            ip = resp["host"]
            link  = f"https://www.ipqualityscore.com/free-ip-lookup-proxy-vpn-test/lookup/{ip}"
            istor = resp["tor"]
            res = resp["fraud_score"]
            ra = resp["recent_abuse"]
            bt = resp["bot_status"]
            ic = resp["is_crawler"]
            p = resp["proxy"]
            v = resp["vpn"]
            if res > 25:
                print(f'{Style.RED_Highlighted}{res}{Style.RESET}')
            temp = {'ip': ip, 'link': link, 'fraud_score': res, 'isTor': istor, 'recent_abuse':ra,
                    'bot_status': bt, 'is_crawler': ic, 'proxy': p, 'vpn': v}
            all_ips.append(temp)
            # print(f"Result: {json.dumps(temp, indent=2)}") # Printed
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

sorted_ips = sorted(all_ips, key=lambda x: (x['fraud_score']), reverse=True)  # sort using
# fraud_score tag
for i, result in enumerate(sorted_ips):
    if result['fraud_score'] > 25:
        print(f"{Style.RED_Highlighted} {i + 1} {json.dumps(result, indent=3)}{Style.RESET}")
    elif result['fraud_score'] > 10:
        print(f"{Style.RED} {i + 1}: {json.dumps(result, indent=3)}{Style.RESET}")
    elif result['fraud_score'] > 2:
        print(f"{Style.YELLOW} {i + 1}: {json.dumps(result, indent=3)}{Style.RESET}")
    else:
        print(f"{Style.GREEN} {i + 1}: {json.dumps(result, indent=3)}{Style.RESET}")