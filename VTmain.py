import time
start_time_vt = time.time()
import asyncio
import ipaddress
import json

import aiohttp
from aiohttp import ClientSession

from common import Style, truststore, ips, timeout_set
from credentials import vt_api

truststore.inject_into_ssl()

all_vt_ips = []

async def vtmain(address, i, session):
    try:
        vt_url = f"https://www.virustotal.com/api/v3/ip_addresses/{address}"
        vt_headers = {
            "accept": "application/json",
            "x-apikey": vt_api
        }
        async with session.get(vt_url, headers=vt_headers) as response:
            vt_response_json = await response.json()
            print(f"IP {i}/{len(ips)} {Style.RESET}{response.status} {response.reason} for {address} on VT")
            # print(vt_response_json)
            if not response.ok:
                print(f"{await response.text()}")
                vt_ip = F'{address}'
                vt_link = vt_tags = None
                vt_res = {
                    "NOTE": f"{vt_response_json['error']['message']} error! These results cannot be trusted",
                    "malicious": -1,
                    "suspicious": -1,
                    'Result': 'INVALID RESULT'
                }
            elif response.ok:
                vt_ip = vt_response_json["data"]["id"]
                vt_link = vt_response_json["data"]["links"]["self"]
                vt_tags = vt_response_json["data"]["attributes"]["tags"]
                vt_res = vt_response_json["data"]["attributes"]["last_analysis_stats"]
                if vt_res["malicious"] > 2:
                    print(f'\t{Style.RED_Highlighted}Malicious %: {vt_res}{Style.RESET}')
            vt_temp = {'VT_IP': vt_ip, 'Vt_Link': vt_link, 'VT_Tags': vt_tags, 'VT_Res': vt_res}
            all_vt_ips.append(vt_temp)
            return vt_response_json, response.status

    except asyncio.TimeoutError:
        print(f"Request to {address} timed out after {timeout_set} seconds on VT")
        vt_response_json = {'IP': f"{address}", 'vt_res': {
                    "NOTE": f"{vt_response_json['error']['message']} error! These results cannot be trusted",
                    "malicious": -1,
                    "suspicious": -1,
                    'Result': 'INVALID RESULT'
                },
                      "vt_tags": f"INVALID RESULT - Request to {address} timed out after {timeout_set} seconds on VT"}

        all_vt_ips.append(vt_response_json)
        return vt_response_json, 0
    except aiohttp.ClientError as ex:
        print(f"IP {i}/{len(ips)} Error on VT for {address}: {Style.YELLOW} {str(ex)}{Style.RESET}")
        return None


async def main():
    async with ClientSession(timeout=aiohttp.ClientTimeout(total=timeout_set)) as session:
        tasks = []
        for i, ip in enumerate(ips, start=1):
            try:
                address = ipaddress.ip_address(ip)
            except ValueError:
                print(f"IP {i}/{len(ips)} {Style.RED}Entered IP '{ip}' is not a valid IP!{Style.RESET}")
                continue
            if not address.is_private:
                tasks.append(vtmain(address, i, session))
            else:
                print(f"IP {i}/{len(ips)} {Style.BLUE}Given IP {address} is Private{Style.RESET}")

        responses = await asyncio.gather(*tasks)

        sorted_vt_ips = sorted(all_vt_ips, key=lambda x: (x["VT_Res"]["malicious"], x["VT_Res"]["suspicious"]),
                               reverse=True)  # sort using malicious tag then suspicious tag
        print("\nMain Output:")
        for i, result in enumerate(sorted_vt_ips):
            if result['VT_Res']['malicious'] == -1:
                print(f"{Style.GREY} {i + 1} {json.dumps(result, indent=1)}{Style.RESET}")
            elif result['VT_Res']['malicious'] > 5:
                print(f"{Style.RED_Highlighted} {i + 1} {json.dumps(result, indent=3)}{Style.RESET}")
            elif result['VT_Res']['malicious'] > 2 or result['VT_Res']['suspicious'] > 1:
                print(f"{Style.RED} {i + 1}: {json.dumps(result, indent=3)}{Style.RESET}")
            elif result['VT_Res']['malicious'] > 0 or result['VT_Res']['suspicious'] > 0:
                print(f"{Style.YELLOW} {i + 1}: {json.dumps(result, indent=3)}{Style.RESET}")
            else:
                print(f"{Style.GREEN} {i + 1}: {json.dumps(result, indent=3)}{Style.RESET}")
        return responses


if __name__ == "__main__":
    asyncio.run(main())
    print(f"Result received within {time.time() - start_time_vt} seconds!")
