import time

start_time_ipqs = time.time()
import asyncio
import ipaddress
import json

import aiohttp

from common import Style, ips
from credentials import otxa_api

all_ipqs_ips = []


async def otxamain(address, i):
    try:
        otxa_url = f'https://otx.alienvault.com/api/v1/indicators/IPv4/{address}/general'
        async with aiohttp.ClientSession() as session:
            async with session.get(otxa_url) as response:
                ipqs_response_json = await response.json()
                # print(f"IP {i}/{len(ips)} {response.status} {response.reason} for {address} on IPQS")
                # print(ipqs_response_json)
                print(f"response start {json.dumps(ipqs_response_json, indent=3)} responseend")
                if ipqs_response_json['success'] is False:
                  invalid_res  = f"INVALID RESULT - {ipqs_response_json['message']}"
                else:
                    if None:
                        print(f'\t{Style.RED_Highlighted}Fraud Score: {Style.RESET}')
                temp = {'test':'test'}
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
            task = asyncio.create_task(otxamain(address, i))
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
        if result[''] == -1:
            print(f"{Style.GREY} {i + 1} {json.dumps(result, indent=3)}{Style.RESET}")
        elif result[''] > 25:
            print(f"{Style.RED_Highlighted} {i + 1} {json.dumps(result, indent=3)}{Style.RESET}")
        elif result[''] > 10:
            print(f"{Style.RED} {i + 1}: {json.dumps(result, indent=3)}{Style.RESET}")
        elif result[''] > 2:
            print(f"{Style.YELLOW} {i + 1}: {json.dumps(result, indent=3)}{Style.RESET}")
        else:
            print(f"{Style.GREEN} {i + 1}: {json.dumps(result, indent=3)}{Style.RESET}")


if __name__ == "__main__":
    print("Executing directly")

    asyncio.run(main())
    print(f"Result received within {time.time() - start_time_ipqs} seconds!")

