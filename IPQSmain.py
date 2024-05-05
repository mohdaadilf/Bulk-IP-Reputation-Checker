from credentials import ipqs_api
from common import *

all_ipqs_ips = []


def ipqsmain(address, i):
    try:
        ipqs_url = f'https://ipqualityscore.com/api/json/ip/{ipqs_api}/{address}'
        ipqs_response = requests.request(method='GET', url=ipqs_url)
        ipqs_response.raise_for_status()
        print(f"IP {i}/{len(ips)} {ipqs_response} for {address} on IPQS")
        # Formatted output
        ipqs_response_json = json.loads(ipqs_response.text)
        # print(f'{json.dumps(resp, indent=4)}')
        if ipqs_response_json['success'] is False:
            ipqs_ip = 0
            ipqs_link = ipqs_istor = ipqs_res = ipqs_ra = ipqs_bt = ipqs_ic = ipqs_p = ipqs_v = None
        else:
            ipqs_ip = ipqs_response_json["host"]
            ipqs_link = f"https://www.ipqualityscore.com/free-ip-lookup-proxy-vpn-test/lookup/{address}"
            ipqs_istor = ipqs_response_json["tor"]
            ipqs_res = ipqs_response_json["fraud_score"]
            ipqs_ra = ipqs_response_json["recent_abuse"]
            ipqs_bt = ipqs_response_json["bot_status"]
            ipqs_ic = ipqs_response_json["is_crawler"]
            ipqs_p = ipqs_response_json["proxy"]
            ipqs_v = ipqs_response_json["vpn"]
            if ipqs_res > 75:
                print(f'\t{Style.RED_Highlighted}Fraud Score: {ipqs_res}{Style.RESET}')
        temp = {'IPQS_IP': ipqs_ip, 'IPQS_Link': ipqs_link, 'IPQS_Fraud_Score': ipqs_res, 'IPQS_isTor': ipqs_istor,
                'IPQS_Recent_abuse': ipqs_ra,
                'IPQS_bot_status': ipqs_bt, 'IPQS_is_crawler': ipqs_ic, 'IPQS_proxy': ipqs_p, 'IPQS_vpn': ipqs_v}
        all_ipqs_ips.append(temp)
        return ipqs_response_json
        # print(f"Result: {json.dumps(temp, indent=2)}") # Printed
        # in 'sorted_ips' print(f"Temp:{temp}\n\n") print(f"All_Ips:{json.dumps(all_ips, indent = 3)}")
    except requests.HTTPError as ex:
        # check response for a possible message
        print(f"IP {i}/{len(ips)} Response for {address}: {Style.YELLOW} {ipqs_response.text}{Style.RESET}")
        raise ex  # let the caller handle it
    except requests.Timeout:
        # request took too long
        print("IP {i}/{len(ips)} Timeout")
        # response = requests.get(url, headers=headers)


if __name__ == "__main__":
    # Code to execute when the file is run directly
    print("Executing directly")
    for i, ip in enumerate(ips):
        i += 1
        try:
            address = ipaddress.ip_address(ip)
        except ValueError:
            # 3. Handle invalid IP address format gracefully
            print(f"IP {i}/{len(ips)} {Style.RED}Entered IP '{ip}' is not a valid IP!{Style.RESET}")
            continue
        if not address.is_private:
            ipqs_response_json = ipqsmain(address, i)
            print(f"\tEntire output (For Debugging): {ipqs_response_json}")
        elif address.is_private:
            print(f"IP {i}/{len(ips)} {Style.BLUE}Given IP {address} is Private{Style.RESET}")
        else:
            print(f"IP {i}/{len(ips)} {Style.RED_Highlighted}Something gone terribly wrong. This line should never run{Style.RESET}")

    sorted_ipqs_ips = sorted(all_ipqs_ips, key=lambda x: (x['IPQS_Fraud_Score']), reverse=True)  # sort using
    # fraud_score tag
    print("\nMain Output:")
    for i, result in enumerate(sorted_ipqs_ips):
        if result['IPQS_Fraud_Score'] > 25:
            print(f"{Style.RED_Highlighted} {i + 1} {json.dumps(result, indent=3)}{Style.RESET}")
        elif result['IPQS_Fraud_Score'] > 10:
            print(f"{Style.RED} {i + 1}: {json.dumps(result, indent=3)}{Style.RESET}")
        elif result['IPQS_Fraud_Score'] > 2:
            print(f"{Style.YELLOW} {i + 1}: {json.dumps(result, indent=3)}{Style.RESET}")
        else:
            print(f"{Style.GREEN} {i + 1}: {json.dumps(result, indent=3)}{Style.RESET}")
