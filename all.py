from credentials import aipdbapi, vtapi
from common import *

for i, ip in enumerate(ips):
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        # 3. Handle invalid IP address format gracefully
        print(f"\n{Style.RED}Entered IP '{ip}' is not a valid IP!{Style.RESET}\n")
        continue

    if not address.is_private:
        try:
            # AbuseIPDB
            days = 90
            url_aipdb = 'https://api.abuseipdb.com/api/v2/check'
            querystring_aipdb = {
                'ipAddress': ip,
                'maxAgeInDays': days
            }
            headers_aipdb = {
                'Accept': 'application/json',
                'Key': aipdbapi
            }
            response = requests.request(method='GET', url=url_aipdb, headers=headers_aipdb, params=querystring_aipdb)
            response.raise_for_status()
            print(f"{response} for {ip} on AbuseIPDB")
            # Formatted output
            resp = json.loads(response.text)
            # print(f'{json.dumps(resp, indent=4)}')
            ip_aipdb = resp["data"]["ipAddress"]
            link_aipdb = f"https://abuseipdb.com/check/{ip}"
            istor_aipdb = resp["data"]["isTor"]
            res_aipdb = resp["data"]["abuseConfidenceScore"]
            tr_aipdb = resp["data"]["totalReports"]
            ndu_aipdb = resp["data"]["numDistinctUsers"]
            temp = {'ip': ip_aipdb, 'abuseConfidenceScore': res_aipdb, 'isTor': istor_aipdb}
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

        # VirusTotal
        try:
            url_vt = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
            headers_vt = {
                "accept": "application/json",
                "x-apikey": vtapi
            }
            response = requests.get(url_vt, headers=headers_vt, timeout=5)
            response.raise_for_status()
            print(f"{response} for {ip} on VT")

            resp_vt = json.loads(response.text)
            ip_vt = resp_vt["data"]["id"]
            link_vt = resp_vt["data"]["links"]["self"]
            tags_vt = resp_vt["data"]["attributes"]["tags"]
            res_vt = resp_vt["data"]["attributes"]["last_analysis_stats"]
            # temp = {'ip': ip_vt, 'link': link_vt, 'tags': tags_vt, 'res': res_vt}
            all_ips[i].update({'Res': res_vt})
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

# print(json.dumps(all_ips, indent=3))

sorted_ips = sorted(all_ips, key=lambda x: (x["Res"]["malicious"], x['abuseConfidenceScore'], x["Res"]["suspicious"]),
                    reverse=True)  # sort using malicious tag then AbuseConfi and then Suspicious tag

for i, result in enumerate(sorted_ips):
    if result['abuseConfidenceScore'] > 25 or result['Res']['malicious'] > 5:
        print(f"{Style.RED_Highlighted} {i + 1} {json.dumps(result, indent=3)}{Style.RESET}")
    elif result['abuseConfidenceScore'] > 10 or result['Res']['malicious'] > 2 or result['Res']['suspicious'] > 1:
        print(f"{Style.RED} {i + 1}: {json.dumps(result, indent=3)}{Style.RESET}")
    elif result['abuseConfidenceScore'] > 2 or result['Res']['malicious'] > 0 or result['Res']['suspicious'] > 0:
        print(f"{Style.YELLOW} {i + 1}: {json.dumps(result, indent=3)}{Style.RESET}")
    else:
        print(f"{Style.GREEN} {i + 1}: {json.dumps(result, indent=3)}{Style.RESET}")
