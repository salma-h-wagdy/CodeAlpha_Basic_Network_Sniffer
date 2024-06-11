import sys

sys.path.append("C:/Users/Salma/Anaconda/Lib/site-packages")
import site
print(site.getsitepackages())

from scapy.all import *
import textwrap


def main():
    sniff(prn=packet, store=False, timeout=TIMEOUT)


if __name__ == "__main__":
    main()