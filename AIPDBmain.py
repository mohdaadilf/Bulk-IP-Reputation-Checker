from credentials import aipdb_api
from common import *

all_aipdb_ips = []


def aipdbmain(address):
    try:
        aipdb_days = 90
        aipdb_url = 'https://api.abuseipdb.com/api/v2/check' \
                    ''
        aipdb_querystring = {
            'ipAddress': address,
            'maxAgeInDays': aipdb_days
        }
        aipdb_headers = {
            'Accept': 'application/json',
            'Key': aipdb_api
        }

        aipdb_response = requests.request(method='GET', url=aipdb_url, headers=aipdb_headers,
                                          params=aipdb_querystring)
        aipdb_response.raise_for_status()
        # print(f"{response} for {ip}")
        # Formatted output
        print(f"{aipdb_response} for {address} on AIPDB")
        aipdb_response_json = json.loads(aipdb_response.text)
        # print(f'{json.dumps(aipdb_response_json, indent=4)}')
        aipdb_ip = aipdb_response_json["data"]["ipAddress"]
        aipdb_link = f"https://abuseipdb.com/check/{address}"
        aipdb_istor = aipdb_response_json["data"]["isTor"]
        aipdb_res = aipdb_response_json["data"]["abuseConfidenceScore"]
        aipdb_tr = aipdb_response_json["data"]["totalReports"]
        aipdb_ndu = aipdb_response_json["data"]["numDistinctUsers"]
        aipdb_iswhi = aipdb_response_json["data"]["isWhitelisted"]
        aipdb_usage = aipdb_response_json["data"]["usageType"]
        if aipdb_res > 25:
            print(f'\t{Style.RED_Highlighted}{aipdb_res}{Style.RESET}')
        aipdb_temp = {'AIPDB_IP': aipdb_ip, 'AIPDB_link': aipdb_link, 'AIPDB_isTor': aipdb_istor,
                      'AIPDB_isWhitelisted': aipdb_iswhi,
                      'AIPDB_abuseConfidenceScore': aipdb_res, 'AIPDB_totalReports': aipdb_tr,
                      'AIPDB_numDistinctUsers': aipdb_ndu, 'AIPDB_usage': aipdb_usage}
        all_aipdb_ips.append(aipdb_temp)
        return aipdb_response_json
        # print(f"IP: {ip}\nTags: {json.dumps(tags, indent=2)}\nResult: {json.dumps(res, indent=3)}") # Printed
        # in 'sorted_ips' print(f"Temp:{temp}\n\n") print(f"All_Ips:{json.dumps(all_ips, indent = 3)}")
    except requests.HTTPError as ex:
        # check response for a possible message
        print(f"Response for {address}: {Style.YELLOW} {aipdb_response.text}{Style.RESET}")
        raise ex  # let the caller handle it
    except requests.Timeout:
        # request took too long
        print("Timeout")
        # response = requests.get(url, headers=headers)


if __name__ == "__main__":
    # Code to execute when the file is run directly
    print("Executing directly")
    for ip in ips:
        try:
            address = ipaddress.ip_address(ip)
        except ValueError:
            # 3. Handle invalid IP address format gracefully
            print(f"{Style.RED}Entered IP '{ip}' is not a valid IP!{Style.RESET}")
            continue
        if not address.is_private:
            response = aipdbmain(address)
            print(response)
        elif address.is_private:
            print(f"{Style.BLUE}Given IP {address} is Private{Style.RESET}")
        else:
            print(f"{Style.RED_Highlighted}Something gone terribly wrong. This line should never run{Style.RESET}")

    print(f"all vt ips: {all_aipdb_ips}")
    sorted_ips = sorted(all_aipdb_ips, key=lambda x: (x['AIPDB_abuseConfidenceScore']), reverse=True)  # sort using
    # AIPDB_abuseConfidenceScore tag
    for i, result in enumerate(sorted_ips):
        if result['AIPDB_abuseConfidenceScore'] > 25:
            print(f"{Style.RED_Highlighted} {i + 1} {json.dumps(result, indent=3)}{Style.RESET}")
        elif result['AIPDB_abuseConfidenceScore'] > 10:
            print(f"{Style.RED} {i + 1}: {json.dumps(result, indent=3)}{Style.RESET}")
        elif result['AIPDB_abuseConfidenceScore'] > 2:
            print(f"{Style.YELLOW} {i + 1}: {json.dumps(result, indent=3)}{Style.RESET}")
        else:
            print(f"{Style.GREEN} {i + 1}: {json.dumps(result, indent=3)}{Style.RESET}")
