import time

start_time_ipqs = time.time()
import asyncio
import ipaddress
import json

import aiohttp

from common import Style, ips
from credentials import ipqs_api

all_ipqs_ips = []


async def ipqsmain(address, i):
    try:
        ipqs_url = f'https://ipqualityscore.com/api/json/ip/{ipqs_api}/{address}'
        async with aiohttp.ClientSession() as session:
            async with session.get(ipqs_url) as response:
                ipqs_response_json = await response.json()
                # print(f"IP {i}/{len(ips)} {response.status} {response.reason} for {address} on IPQS")
                # print(ipqs_response_json)
                # print(f"response start {ipqs_response_json} responseend")
                if ipqs_response_json['success'] is False:
                    ipqs_ip = f'{address}'
                    ipqs_res = -1
                    ipqs_link = ipqs_istor = ipqs_ra = ipqs_bt = ipqs_ic = ipqs_p = ipqs_v = f"INVALID RESULT - {ipqs_response_json['message']}"
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
                temp = {'IPQS_IP': ipqs_ip, 'IPQS_Link': ipqs_link, 'IPQS_Fraud_Score': ipqs_res,
                        'IPQS_isTor': ipqs_istor,
                        'IPQS_Recent_abuse': ipqs_ra,
                        'IPQS_bot_status': ipqs_bt, 'IPQS_is_crawler': ipqs_ic, 'IPQS_proxy': ipqs_p,
                        'IPQS_vpn': ipqs_v}
                all_ipqs_ips.append(temp)
                return ipqs_response_json
    except aiohttp.ClientError as ex:
        print(f"IP {i}/{len(ips)} Error for {address} on IPQS: {ex}")


async def main():
    tasks = []
    for i, ip in enumerate(ips):
        i += 1
        try:
            address = ipaddress.ip_address(ip)
        except ValueError:
            print(f"IP {i}/{len(ips)} {Style.RED}Entered IP '{ip}' is not a valid IP!{Style.RESET}")
            continue
        if not address.is_private:
            task = asyncio.create_task(ipqsmain(address, i))
            tasks.append(task)
        elif address.is_private:
            print(f"IP {i}/{len(ips)} {Style.BLUE}Given IP {address} is Private{Style.RESET}")
        else:
            print(
                f"IP {i}/{len(ips)} {Style.RED_Highlighted}Something gone terribly wrong. This line should never run{Style.RESET}")

    await asyncio.gather(*tasks)

    sorted_ipqs_ips = sorted(all_ipqs_ips, key=lambda x: (x['IPQS_Fraud_Score']), reverse=True)
    print("\nMain Output:")
    for i, result in enumerate(sorted_ipqs_ips):
        if result['IPQS_Fraud_Score'] == -1:
            print(f"{Style.GREY} {i + 1} {json.dumps(result, indent=3)}{Style.RESET}")
        elif result['IPQS_Fraud_Score'] > 25:
            print(f"{Style.RED_Highlighted} {i + 1} {json.dumps(result, indent=3)}{Style.RESET}")
        elif result['IPQS_Fraud_Score'] > 10:
            print(f"{Style.RED} {i + 1}: {json.dumps(result, indent=3)}{Style.RESET}")
        elif result['IPQS_Fraud_Score'] > 2:
            print(f"{Style.YELLOW} {i + 1}: {json.dumps(result, indent=3)}{Style.RESET}")
        else:
            print(f"{Style.GREEN} {i + 1}: {json.dumps(result, indent=3)}{Style.RESET}")


if __name__ == "__main__":
    print("Executing directly")

    asyncio.run(main())
    print(f"Result received within {time.time() - start_time_ipqs} seconds!")
