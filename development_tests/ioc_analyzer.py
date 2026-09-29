import ipaddress
import re

ioc = input("Enter an IOC: ")

try:
    ipaddress.ip_address(ioc)
    print("IOC:", ioc)
    print("Type: IP Address")

except ValueError:

    if ioc.startswith("http://") or ioc.startswith("https://"):
        print("IOC:", ioc)
        print("Type: URL")

    elif re.fullmatch(r"[a-fA-F0-9]{32}", ioc):
        print("IOC:", ioc)
        print("Type: MD5 Hash")

    elif re.fullmatch(r"[a-fA-F0-9]{40}", ioc):
        print("IOC:", ioc)
        print("Type: SHA-1 Hash")

    elif re.fullmatch(r"[a-fA-F0-9]{64}", ioc):
        print("IOC:", ioc)
        print("Type: SHA-256 Hash")

    elif "." in ioc:
        print("IOC:", ioc)
        print("Type: Domain")

    else:
        print("IOC:", ioc)
        print("Type: Unknown")