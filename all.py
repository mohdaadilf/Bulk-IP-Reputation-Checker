# all.py
import asyncio

import aiohttp

from AIPDBmain import aipdbmain
from IPQSmain import ipqsmain
from VTmain import vtmain
from common import *


async def process_ip(address, index, session):
    # AbuseIPDB
    aipdb_response_json = await aipdbmain(f'{address}', index)

    # VirusTotal
    vt_response_json = await vtmain(f'{address}', index, session)

    # IPQualityScore:
    ipqs_response_json = await ipqsmain(f'{address}', index)
    if ipqs_response_json['success'] is False:
        ipqs_ip = f'{address}'
        # ipqs_res = 0
        # ipqs_link = ipqs_istor = ipqs_ra = ipqs_bt = ipqs_ic = ipqs_p = ipqs_v = None
        ipqs_response_json['fraud_score'] = 0
        ipqs_response_json['tor'] = ipqs_response_json['recent_abuse'] = ipqs_response_json['bot_status'] = \
            ipqs_response_json['is_crawler'] = ipqs_response_json['proxy'] = ipqs_response_json['vpn'] = None

    temp = {
        'IP': address,
        'AbuseIPDB': {
            'abuseConfidenceScore': aipdb_response_json['data']['abuseConfidenceScore'],
            'isTor': aipdb_response_json['data']['isTor']
        },
        'VT': vt_response_json['data']['attributes']['last_analysis_stats'],
        'IPQS': {
            'fraud_score': ipqs_response_json['fraud_score'],
            'isTor': ipqs_response_json['tor'],
            'recent_abuse': ipqs_response_json['recent_abuse'],
            'bot_status': ipqs_response_json['bot_status'],
            'is_crawler': ipqs_response_json['is_crawler'],
            'proxy': ipqs_response_json['proxy'],
            'vpn': ipqs_response_json['vpn']
        }
    }
    return temp


async def main():
    async with aiohttp.ClientSession() as session:
        tasks = []
        for i, ip in enumerate(ips, start=1):
            try:
                address = ipaddress.ip_address(ip)
            except ValueError:
                print(f"IP {i}/{len(ips)} {Style.RED}Entered IP '{ip}' is not a valid IP!{Style.RESET}")
                continue
            if not address.is_private:
                tasks.append(process_ip(f'{address}', i, session))
            else:
                print(f"IP {i}/{len(ips)} {Style.BLUE}Given IP {address} is Private{Style.RESET}")

        all_results = await asyncio.gather(*tasks)
        print(f'ALL RESULTS {all_results}')
        sorted_results = sorted(all_results, key=lambda x: (
            x["VT"]["malicious"], x['AbuseIPDB']['abuseConfidenceScore'], x["VT"]["suspicious"]), reverse=True)

        print(f"\nMain Output:")
        for i, result in enumerate(sorted_results, start=1):
            if result:
                abuse_confidence = result['AbuseIPDB']['abuseConfidenceScore']
                vt_malicious = result['VT']['malicious']
                ipqs_fraud_score = result['IPQS']['fraud_score']

                if abuse_confidence > 25 or vt_malicious > 5 or ipqs_fraud_score > 85:
                    print(f"{Style.RED_Highlighted} {i} {json.dumps(result, indent=3)}{Style.RESET}")
                elif abuse_confidence > 10 or vt_malicious > 2 or result['VT'][
                    'suspicious'] > 1 or ipqs_fraud_score > 80:
                    print(f"{Style.RED} {i}: {json.dumps(result, indent=3)}{Style.RESET}")
                elif abuse_confidence > 2 or vt_malicious > 0 or result['VT'][
                    'suspicious'] > 0 or ipqs_fraud_score > 50:
                    print(f"{Style.YELLOW} {i}: {json.dumps(result, indent=3)}{Style.RESET}")
                else:
                    print(f"{Style.GREEN} {i}: {json.dumps(result, indent=3)}{Style.RESET}")


asyncio.run(main())
