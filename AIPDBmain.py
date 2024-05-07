import aiohttp
import asyncio
import json
import ipaddress
from credentials import aipdb_api
from common import *

# Define color codes
class Style:
    RESET = '\033[0m'
    RED = '\033[31m'
    RED_Highlighted = '\033[41m\033[97m'
    YELLOW = '\033[33m'
    GREEN = '\033[32m'
    BLUE = '\033[34m'

all_aipdb_ips = []


async def aipdbmain(address, i):
    try:
        aipdb_days = 90
        aipdb_url = 'https://api.abuseipdb.com/api/v2/check'
        aipdb_querystring = {
            'ipAddress': address,
            'maxAgeInDays': aipdb_days
        }
        aipdb_headers = {
            'Accept': 'application/json',
            'Key': aipdb_api
        }

        async with aiohttp.ClientSession() as session:
            async with session.get(aipdb_url, params=aipdb_querystring, headers=aipdb_headers) as response:
                aipdb_response = await response.json()
                print(f"IP {i}/{len(ips)} {Style.RESET}{response.status} {response.reason} for {address} on AIPDB")
                # print(await response.text())
                aipdb_ip = aipdb_response["data"]["ipAddress"]
                aipdb_link = f"https://abuseipdb.com/check/{address}"
                aipdb_istor = aipdb_response["data"]["isTor"]
                aipdb_res = aipdb_response["data"]["abuseConfidenceScore"]
                aipdb_tr = aipdb_response["data"]["totalReports"]
                aipdb_ndu = aipdb_response["data"]["numDistinctUsers"]
                aipdb_iswhi = aipdb_response["data"]["isWhitelisted"]
                aipdb_usage = aipdb_response["data"]["usageType"]
                if aipdb_res > 25:
                    print(f'\t{Style.RED_Highlighted}Abuse Confidence Score: {aipdb_res}{Style.RESET}')
                aipdb_temp = {'AIPDB_IP': aipdb_ip, 'AIPDB_link': aipdb_link, 'AIPDB_isTor': aipdb_istor,
                              'AIPDB_isWhitelisted': aipdb_iswhi,
                              'AIPDB_abuseConfidenceScore': aipdb_res, 'AIPDB_totalReports': aipdb_tr,
                              'AIPDB_numDistinctUsers': aipdb_ndu, 'AIPDB_usage': aipdb_usage}
                all_aipdb_ips.append(aipdb_temp)
                return aipdb_response

    except aiohttp.ClientError as ex:
        print(f"IP {i}/{len(ips)} Error for {address}: {Style.YELLOW}{ex} on AIPDB {Style.RESET}")
    except asyncio.TimeoutError:
        print(f"IP {i}/{len(ips)} Timeout")
    except Exception as e:
        print(f"IP {i}/{len(ips)} Error: {Style.YELLOW}{e} on AIPDB {Style.RESET}")


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
            task = asyncio.create_task(aipdbmain(f'{address}', i))
            tasks.append(task)
        elif address.is_private:
            print(f"IP {i}/{len(ips)} {Style.BLUE}Given IP {address} is Private{Style.RESET}")
        else:
            print(f"IP {i}/{len(ips)} {Style.RED_Highlighted}Something gone terribly wrong. This line should never run{Style.RESET}")

    responses = await asyncio.gather(*tasks)
    sorted_ips = sorted(all_aipdb_ips, key=lambda x: (x['AIPDB_abuseConfidenceScore']), reverse=True)
    print("\nMain Output:")
    for i, result in enumerate(sorted_ips):
        if result['AIPDB_abuseConfidenceScore'] > 25:
            print(f"{Style.RED_Highlighted} {i + 1} {json.dumps(result, indent=3)}{Style.RESET}")
        elif result['AIPDB_abuseConfidenceScore'] > 10:
            print(f"{Style.RED} {i + 1}: {json.dumps(result, indent=3)}{Style.RESET}")
        elif result['AIPDB_abuseConfidenceScore'] > 2:
            print(f"{Style.YELLOW} {i + 1}: {json.dumps(result, indent=3)}{Style.RESET}")
        else:
            print(f"{Style.GREEN} {i + 1}: {json.dumps(result, indent=3)}{Style.RESET}")


if __name__ == "__main__":
    print("Executing directly")
    asyncio.run(main())
