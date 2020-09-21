#!/usr/bin/python3  -W ignore::DeprecationWarning

import requests
import json
import sys
import csv
import time
import getpass
import ipaddress
import argparse
import apifunctions

#remove the InsecureRequestWarning messages
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

"""
test code to try and create simple http repy of data with json
"""

def main():
    print("in main function")
    debug = 1

if __name__ == "__main__":
    main()