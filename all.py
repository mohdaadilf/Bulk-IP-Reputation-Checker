from credentials import aipdbapi, vtapi, ipqsapi
from common import *

for i, ip in enumerate(ips):
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        # 3. Handle invalid IP address format gracefully
        print(f"\n{Style.RED}Entered IP '{ip}' is not a valid IP!{Style.RESET}\n")
        continue

    if not address.is_private:
        # AbuseIPDB
        try:
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
            response_vt_aipdb = requests.request(method='GET', url=url_aipdb, headers=headers_aipdb, params=querystring_aipdb)
            response_vt_aipdb.raise_for_status()
            print(f"{response_vt_aipdb} for {ip} on AbuseIPDB")
            # Formatted output
            resp = json.loads(response_vt_aipdb.text)
            # print(f'{json.dumps(resp, indent=4)}')
            ip_aipdb = resp["data"]["ipAddress"]
            link_aipdb = f"https://abuseipdb.com/check/{ip}"
            istor_aipdb = resp["data"]["isTor"]
            res_aipdb = resp["data"]["abuseConfidenceScore"]
            tr_aipdb = resp["data"]["totalReports"]
            ndu_aipdb = resp["data"]["numDistinctUsers"]
            temp_vt = {'IP': ip_aipdb, 'AbuseIPDB': {'abuseConfidenceScore': res_aipdb, 'isTor': istor_aipdb}}
            all_ips.append(temp_vt)
            # print(f"IP: {ip}\nTags: {json.dumps(tags, indent=2)}\nResult: {json.dumps(res, indent=3)}") # Printed
            # in 'sorted_ips' print(f"Temp:{temp}\n\n") print(f"All_Ips:{json.dumps(all_ips, indent = 3)}")
        except requests.HTTPError as ex:
            # check response_vt for a possible message
            print(f"Response for {address}: {Style.YELLOW} {response_vt_aipdb.text}{Style.RESET}")
            raise ex  # let the caller handle it
        except requests.Timeout:
            # request took too long
            print("Timeout")
        # response_vt = requests.get(url, headers=headers)

        # VirusTotal
        try:
            url_vt = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
            headers_vt = {
                "accept": "application/json",
                "x-apikey": vtapi
            }
            response_vt = requests.get(url_vt, headers=headers_vt, timeout=5)
            response_vt.raise_for_status()
            print(f"{response_vt} for {ip} on VT")

            resp_vt = json.loads(response_vt.text)
            ip_vt = resp_vt["data"]["id"]
            link_vt = resp_vt["data"]["links"]["self"]
            tags_vt = resp_vt["data"]["attributes"]["tags"]
            res_vt = resp_vt["data"]["attributes"]["last_analysis_stats"]
            # temp = {'ip': ip_vt, 'link': link_vt, 'tags': tags_vt, 'res': res_vt}
            all_ips[i].update({'VT': res_vt})
            # print(f"IP: {ip}\nTags: {json.dumps(tags, indent=2)}\nResult: {json.dumps(res, indent=3)}") # Printed
            # in 'sorted_ips' print(f"Temp:{temp}\n\n") print(f"All_Ips:{json.dumps(all_ips, indent = 3)}")
        except requests.HTTPError as ex:
            # check response_vt for a possible message
            print(f"Response for {address}: {Style.YELLOW} {response_vt.text}{Style.RESET}")
            raise ex  # let the caller handle it
        except requests.Timeout:
            # request took too long
            print("Timeout")
        # response = requests.get(url, headers=headers)

        # IPQualityScore:
        try:
            url = f'https://ipqualityscore.com/api/json/ip/{ipqsapi}/{ip}'

            response_ipqs = requests.request(method='GET', url=url)
            response_ipqs.raise_for_status()
            print(f"{response_ipqs} for {ip} on IPQualityScore")
            # Formatted output
            resp_ipqs = json.loads(response_ipqs.text)
            # print(f'{json.dumps(resp, indent=4)}')
            ip_ipqs = resp_ipqs["host"]
            link_ipqs = f"https://www.ipqualityscore.com/free-ip-lookup-proxy-vpn-test/lookup/{ip}"
            istor_ipqs = resp_ipqs["tor"]
            res_ipqs = resp_ipqs["fraud_score"]
            ra_ipqs = resp_ipqs["recent_abuse"]
            bt_ipqs = resp_ipqs["bot_status"]
            ic_ipqs = resp_ipqs["is_crawler"]
            p_ipqs = resp_ipqs["proxy"]
            v_ipqs = resp_ipqs["vpn"]
            if res_ipqs > 25:
                print(f'{Style.RED_Highlighted}{res_ipqs}{Style.RESET}')
            temp_ipqs = {'fraud_score': res_ipqs, 'isTor': istor_ipqs, 'recent_abuse': ra_ipqs, 'bot_status': bt_ipqs,
                         'is_crawler': ic_ipqs, 'proxy': p_ipqs, 'vpn': v_ipqs}
            all_ips[i].update({'IPQS': temp_ipqs})
            # print(f"Result: {json.dumps(temp, indent=2)}") # Printed
            # in 'sorted_ips' print(f"Temp:{temp}\n\n") print(f"All_Ips:{json.dumps(all_ips, indent = 3)}")
        except requests.HTTPError as ex:
            # check response_ipqs for a possible message
            print(f"Response for {address}: {Style.YELLOW} {response_ipqs.text}{Style.RESET}")
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

sorted_ips = sorted(all_ips, key=lambda x: (x["VT"]["malicious"], x['AbuseIPDB']['abuseConfidenceScore'],
                                            x["VT"]["suspicious"]), reverse=True)  # sort using
# malicious tag then AbuseConfi and then Suspicious tag

for i, result in enumerate(sorted_ips):
    if result['AbuseIPDB']['abuseConfidenceScore'] > 25 or result['VT']['malicious'] > 5 or result["IPQS"]['fraud_score'] > 25:
        print(f"{Style.RED_Highlighted} {i + 1} {json.dumps(result, indent=3)}{Style.RESET}")
    elif result['AbuseIPDB']['abuseConfidenceScore'] > 10 or result['VT']['malicious'] > 2 or result['VT']['suspicious'] > 1 or result["IPQS"]['fraud_score'] > 10:
        print(f"{Style.RED} {i + 1}: {json.dumps(result, indent=3)}{Style.RESET}")
    elif result['AbuseIPDB']['abuseConfidenceScore'] > 2 or result['VT']['malicious'] > 0 or result['VT']['suspicious'] > 0 or result["IPQS"]['fraud_score'] > 2:
        print(f"{Style.YELLOW} {i + 1}: {json.dumps(result, indent=3)}{Style.RESET}")
    else:
        print(f"{Style.GREEN} {i + 1}: {json.dumps(result, indent=3)}{Style.RESET}")
