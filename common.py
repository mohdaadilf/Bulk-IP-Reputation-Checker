import requests
import ipaddress
import json
import truststore
import os

os.system("color")  # enables ANSI escape sequences to color output; check


# https://stackoverflow.com/questions/287871/how-do-i-print-colored-text-to-the-terminal
# print(''.join([f'\033[{x}m{x} foo \33[0m \n' for x in range(0, 150)]))  # To check what colors are supported.
class Style:
    RED = '\033[31m'
    RED_Highlighted = '\033[41m'
    GREEN = '\033[32m'
    YELLOW = '\033[33m'
    BLUE = '\033[36m'
    RESET = '\033[0m'


truststore.inject_into_ssl()  # Inject truststore into the standard library ssl module so the functionality is used
# by every library by default.

all_ips = []  # to have the sorted-final list

with open("ips.txt") as f:
    ips = f.readlines()
ips = [x.strip() for x in ips]  # remove new line char
ips = list(set(ips))  # remove duplicates
print(f"Length: {len(ips)}\n{ips}")  # to show the ips

#  check https://www.iana.org/assignments/iana-ipv4-special-registry/iana-ipv4-special-registry.xhtml and
# https://bugs.python.org/issue42937
# Is a check on the non routable IPs such as 100.64.0.0/10 required?
# what about 192.0.0.0/24 etc. Improvements to be made~
