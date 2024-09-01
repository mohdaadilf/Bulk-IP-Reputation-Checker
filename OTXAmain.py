import time

start_time_otxa = time.time()
import asyncio
import ipaddress
import json

import aiohttp

from common import *

all_otxa_ips = []


async def otxamain(address, i, session):
    try:
        otxa_url = f'https://otx.alienvault.com/api/v1/indicators/IPv4/{address}/general'
        async with session.get(otxa_url) as response:
            # print(address)
            # print(await response.text())
            # print(response.status)
            print(f"IP {i}/{len(ips)} {response.status} {response.reason} for {address} on otxa")
            # print(otxa_response_json)
            #print(f"response start {json.dumps(otxa_response_json, indent=3)} responseend")
            if not response.ok:
                otxa_response_json = {'reputation': -1, 'indicator': f"{address}"}
                otxa_response_json["false_positive"] = otxa_response_json[
                    "validation"] = f"INVALID RESULT - {response.reason}"
            else:
                otxa_response_json = await response.json()
                if otxa_response_json["reputation"] > 50:
                    print(f'\t{Style.RED_Highlighted}Reputation: {otxa_response_json["reputation"]} {Style.RESET}')
            temp = {'IP': otxa_response_json['indicator'], 'reputation': otxa_response_json["reputation"],
                    'validation': otxa_response_json["validation"],
                    'fp': otxa_response_json["false_positive"]}
            all_otxa_ips.append(temp)
            return otxa_response_json, response.status

    except asyncio.TimeoutError:
        print(f"Request to {address} timed out after {timeout_set} seconds")
        otxa_response_json = {'IP': f"{address}", 'reputation': -1,
                              "validation": f"INVALID RESULT - Request to {address} timed out after {timeout_set} seconds"}
        all_otxa_ips.append(otxa_response_json)
        return otxa_response_json, 0
    except aiohttp.ClientError as ex:
        print(f"IP {i}/{len(ips)} Error for {address} on OTXAlienVault: {await response.text()} {ex}")


async def main():
    tasks = []
    async with (aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=timeout_set)) as session):
        for i, ip in enumerate(ips):
            i += 1
            try:
                address = ipaddress.ip_address(ip)
            except ValueError:
                print(f"IP {i}/{len(ips)} {Style.RED}Entered IP '{ip}' is not a valid IP!{Style.RESET}")
                continue
            if not address.is_private:
                task = asyncio.create_task(otxamain(address, i, session))
                tasks.append(task)
            elif address.is_private:
                print(f"IP {i}/{len(ips)} {Style.BLUE}Given IP {address} is Private{Style.RESET}")
            else:
                print(
                    f"IP {i}/{len(ips)} {Style.RED_Highlighted}Something gone terribly wrong. This line should never run{Style.RESET}")

        await asyncio.gather(*tasks)

    sorted_otxa_ips = sorted(all_otxa_ips, key=lambda x: (x['reputation']), reverse=True)
    print("\nMain Output:")
    for i, result in enumerate(sorted_otxa_ips):
        if result['reputation'] == -1:
            print(f"{Style.GREY} {i + 1} {json.dumps(result, indent=3)}{Style.RESET}")
        elif result['reputation'] > 25:
            print(f"{Style.RED_Highlighted} {i + 1} {json.dumps(result, indent=3)}{Style.RESET}")
        elif result['reputation'] > 10:
            print(f"{Style.RED} {i + 1}: {json.dumps(result, indent=3)}{Style.RESET}")
        elif result['reputation'] > 2:
            print(f"{Style.YELLOW} {i + 1}: {json.dumps(result, indent=3)}{Style.RESET}")
        else:
            print(f"{Style.GREEN} {i + 1}: {json.dumps(result, indent=3)}{Style.RESET}")


if __name__ == "__main__":
    print("Executing directly")

    asyncio.run(main())
    print(f"Result received within {time.time() - start_time_otxa} seconds!")
