from common import *
from VTmain import vtmain
from AIPDBmain import aipdbmain
from IPQSmain import ipqsmain

index = 0  # to update the final dict. You cannout use i in the following loop as some ips may be private and
# that will cause the dict update to fail.
for i, ip in enumerate(ips):
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        # 3. Handle invalid IP address format gracefully
        print(f"{Style.RED}Entered IP '{ip}' is not a valid IP!{Style.RESET}")
        continue

    if not address.is_private:
        # AbuseIPDB
        aipdb_response_json = aipdbmain(address)
        # print(f'{json.dumps(aipdb_response_json, indent=4)}')
        ip_aipdb = aipdb_response_json["data"]["ipAddress"]
        istor_aipdb = aipdb_response_json["data"]["isTor"]
        res_aipdb = aipdb_response_json["data"]["abuseConfidenceScore"]
        tr_aipdb = aipdb_response_json["data"]["totalReports"]
        ndu_aipdb = aipdb_response_json["data"]["numDistinctUsers"]
        temp_aipdb = {'IP': ip, 'AbuseIPDB': {'abuseConfidenceScore': res_aipdb, 'isTor': istor_aipdb}}
        all_ips.append(temp_aipdb)
        # print(f"IP: {ip}\nTags: {json.dumps(tags, indent=2)}\nResult: {json.dumps(res, indent=3)}") # Printed
        # in 'sorted_ips' print(f"Temp:{temp}\n\n") print(f"All_Ips:{json.dumps(all_ips, indent = 3)}")

        # VirusTotal
        vt_response_json = vtmain(address)
        ip_vt = vt_response_json["data"]["id"]
        link_vt = vt_response_json["data"]["links"]["self"]
        tags_vt = vt_response_json["data"]["attributes"]["tags"]
        res_vt = vt_response_json["data"]["attributes"]["last_analysis_stats"]
        # temp = {'ip': ip_vt, 'link': link_vt, 'tags': tags_vt, 'res': res_vt}
        all_ips[index].update({'VT': res_vt})
        # print(f"IP: {ip}\nTags: {json.dumps(tags, indent=2)}\nResult: {json.dumps(res, indent=3)}") # Printed
        # in 'sorted_ips' print(f"Temp:{temp}\n\n") print(f"All_Ips:{json.dumps(all_ips, indent = 3)}")

        # IPQualityScore:
        ipqs_response_json = ipqsmain(address)
        # print(f'{json.dumps(resp, indent=4)}')
        ip_ipqs = ipqs_response_json["host"]
        istor_ipqs = ipqs_response_json["tor"]
        res_ipqs = ipqs_response_json["fraud_score"]
        ra_ipqs = ipqs_response_json["recent_abuse"]
        bt_ipqs = ipqs_response_json["bot_status"]
        ic_ipqs = ipqs_response_json["is_crawler"]
        p_ipqs = ipqs_response_json["proxy"]
        v_ipqs = ipqs_response_json["vpn"]
        temp_ipqs = {'fraud_score': res_ipqs, 'isTor': istor_ipqs, 'recent_abuse': ra_ipqs, 'bot_status': bt_ipqs,
                     'is_crawler': ic_ipqs, 'proxy': p_ipqs, 'vpn': v_ipqs}
        all_ips[index].update({'IPQS': temp_ipqs})
        # print(f"Result: {json.dumps(temp, indent=2)}") # Printed
        # in 'sorted_ips' print(f"Temp:{temp}\n\n") print(f"All_Ips:{json.dumps(all_ips, indent = 3)}")
        index += 1

    elif address.is_private:
        print(f"{Style.BLUE}Given IP {address} is Private{Style.RESET}")
    else:
        print(f"{Style.RED_Highlighted}Something gone terribly wrong. This line should never run{Style.RESET}")

    # print(json.dumps(all_ips, indent=3))

sorted_ips = sorted(all_ips, key=lambda x: (x["VT"]["malicious"], x['AbuseIPDB']['abuseConfidenceScore'],
                                            x["VT"]["suspicious"]), reverse=True)  # sort using
# malicious tag then AbuseConfi and then Suspicious tag

for i, result in enumerate(sorted_ips):
    if result['AbuseIPDB']['abuseConfidenceScore'] > 25 or result['VT']['malicious'] > 5 or result["IPQS"][
        'fraud_score'] > 85:
        print(f"{Style.RED_Highlighted} {i + 1} {json.dumps(result, indent=3)}{Style.RESET}")
    elif result['AbuseIPDB']['abuseConfidenceScore'] > 10 or result['VT']['malicious'] > 2 or result['VT'][
        'suspicious'] > 1 or result["IPQS"]['fraud_score'] > 80:
        print(f"{Style.RED} {i + 1}: {json.dumps(result, indent=3)}{Style.RESET}")
    elif result['AbuseIPDB']['abuseConfidenceScore'] > 2 or result['VT']['malicious'] > 0 or result['VT'][
        'suspicious'] > 0 or result["IPQS"]['fraud_score'] > 50:
        print(f"{Style.YELLOW} {i + 1}: {json.dumps(result, indent=3)}{Style.RESET}")
    else:
        print(f"{Style.GREEN} {i + 1}: {json.dumps(result, indent=3)}{Style.RESET}")
