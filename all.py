# all.py
import time

start_time = time.time()

import asyncio

import aiohttp, ipaddress, json

from AIPDBmain import aipdbmain
from IPQSmain import ipqsmain
from VTmain import vtmain
from OTXAmain import otxamain
from common import Style, ips, timeout_set


async def process_ip(address, index, session):
    # AbuseIPDB
    aipdb_response_json, aipdb_status_code = await aipdbmain(f'{address}', index, session)
    aipdb_false_resp = {}
    if aipdb_status_code != 200:
        aipdb_response_json = {
            'data': {
                'aipdb_ip': f'{address}',
                'abuseConfidenceScore': -1,
                'isTor': f"INVALID RESULT - {aipdb_response_json['errors'][0]['detail']}"
            }}

    # VirusTotal
    vt_response_json, vt_status_code = await vtmain(f'{address}', index, session)
    vt_false_resp = {}
    if vt_status_code != 200:
        vt_false_resp = {
            'data': {
                'attributes': {
                    'last_analysis_stats': {
                        "NOTE": f"{vt_response_json['error']['message']} error! These results cannot be trusted!",
                        "malicious": -1,
                        "suspicious": -1,
                    }}}}
        vt_response_json.update(vt_false_resp)
        # print(f'vt res:{vt_response_json}')

    # IPQualityScore:
    ipqs_response_json, ipqs_status_code = await ipqsmain(f'{address}', index, session)
    if not ipqs_response_json['success']:
        ipqs_ip = f'{address}'
        ipqs_response_json['fraud_score'] = -1
        ipqs_response_json['tor'] = ipqs_response_json['recent_abuse'] = ipqs_response_json['bot_status'] = \
            ipqs_response_json['is_crawler'] = ipqs_response_json['proxy'] = ipqs_response_json['vpn'] = \
            f"INVALID RESULTS - {ipqs_response_json['message']}"

    otxa_response_json, otxa_response_code = await otxamain(f'{address}', index, session)
    if otxa_response_code != 200:
        otxa_response_json['reputation'] = -1
        otxa_response_json['indicator'] = f"{address}"
        otxa_response_json["false_positive"] = otxa_response_json["validation"] = \
            f"INVALID RESULT - {otxa_response_json["validation"]}"

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
        },
        'OTX-A': {
            'reputation': otxa_response_json["reputation"],
            'validation': otxa_response_json["validation"],
            'FP': otxa_response_json["false_positive"]
        }

    }
    return temp


async def main():
    async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=timeout_set)) as session:
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

                if abuse_confidence == vt_malicious == ipqs_fraud_score == -1:
                    print(f"{Style.GREY} {i} {json.dumps(result, indent=3)}{Style.RESET}")
                elif abuse_confidence > 25 or vt_malicious > 5 or ipqs_fraud_score > 85:
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
end_time = time.time()
execution_time = end_time - start_time
print(f"Execution time: {execution_time} seconds!")
