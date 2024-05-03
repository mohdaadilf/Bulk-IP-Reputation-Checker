from credentials import vt_api
from common import *

all_vt_ips = []


def vtmain(address):
    vt_resp = vt_link = vt_tags = vt_res = None
    try:
        vt_url = f"https://www.virustotal.com/api/v3/ip_addresses/{address}"
        vt_headers = {
            "accept": "application/json",
            "x-apikey": vt_api
        }
        vt_response = requests.get(vt_url, headers=vt_headers, timeout=5)
        vt_response.raise_for_status()
        print(f"{vt_response} for {address} on VT")
        vt_response_json = json.loads(vt_response.text)
        vt_ip = vt_response_json["data"]["id"]
        vt_link = vt_response_json["data"]["links"]["self"]
        vt_tags = vt_response_json["data"]["attributes"]["tags"]
        vt_res = vt_response_json["data"]["attributes"]["last_analysis_stats"]
        if vt_res["malicious"] > 2:
            print(f'\t{Style.RED_Highlighted}{vt_res}{Style.RESET}')
        vt_temp = {'VT_IP': vt_ip, 'Vt_Link': vt_link, 'VT_Tags': vt_tags, 'VT_Res': vt_res}
        all_vt_ips.append(vt_temp)
        return vt_response_json
        # print(f"IP: {ip}\nTags: {json.dumps(vt_tags, indent=2)}\nResult: {json.dumps(res, indent=3)}") # Printed
        # in 'sorted_vt_ips' print(f"Temp:{temp}\n\n") print(f"All_Ips:{json.dumps(all_vt_ips, indent = 3)}")
    except requests.HTTPError as ex:
        # check response for a possible message
        print(f"Response for {address}: {Style.YELLOW} {vt_response.text}{Style.RESET}")
        raise ex  # let the caller handle it
    except requests.Timeout:
        # request took too long
        print("Timeout")
    # response = requests.get(vt_url, headers=headers)


if __name__ == "__main__":
    # Code to execute when the file is run directly
    print("Executing directly")
    for ip in ips:
        try:
            address = ipaddress.ip_address(ip)
        except ValueError:
            # 3. Handle invalid IP address format gracefully
            print(f"{Style.RED}Entered IP '{ip}' is not a valid IP!{Style.RESET}")
            continue
        if not address.is_private:
            vt_response_json = vtmain(address)
            print(vt_response_json)
        elif address.is_private:
            print(f"{Style.BLUE}Given IP {address} is Private{Style.RESET}")
        else:
            print(f"{Style.RED_Highlighted}Something gone terribly wrong. This line should never run{Style.RESET}")

    print(f"all vt ips: {all_vt_ips}")
    sorted_vt_ips = sorted(all_vt_ips, key=lambda x: (x["VT_Res"]["malicious"], x["VT_Res"]["suspicious"]),
                           reverse=True)  # sort using
    # malicious tag then suspicious tag
    for i, result in enumerate(sorted_vt_ips):
        if result['VT_Res']['malicious'] > 5:
            print(f"{Style.RED_Highlighted} {i + 1} {json.dumps(result, indent=3)}{Style.RESET}")
        elif result['VT_Res']['malicious'] > 2 or result['VT_Res']['suspicious'] > 1:
            print(f"{Style.RED} {i + 1}: {json.dumps(result, indent=3)}{Style.RESET}")
        elif result['VT_Res']['malicious'] > 0 or result['VT_Res']['suspicious'] > 0:
            print(f"{Style.YELLOW} {i + 1}: {json.dumps(result, indent=3)}{Style.RESET}")
        else:
            print(f"{Style.GREEN} {i + 1}: {json.dumps(result, indent=3)}{Style.RESET}")
