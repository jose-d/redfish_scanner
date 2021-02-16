#!/usr/bin/python3

import argparse
import json
import logging
import re
import sys
import urllib.parse
from os import path
import requests
import urllib3
import yaml
from requests.exceptions import SSLError

class redFishLoc:

    def __init__(self, path):
        self.path = path
        self.children = []
        self.actions = []

    def __repr__(self):
        if len(self.actions) > 0:
            return(f"repr: {self.path}, actions: {','.join(self.actions)}")
        else:
            return(f"repr: {self.path}")

    def appendChild(self, child):
        self.children.append(child)

    def appendAction(self, actionName):
        self.actions.append(actionName)

def parseArguments():
    
    parser = argparse.ArgumentParser(description='Discover RedFish API available services.')
    requiredNamed = parser.add_argument_group('required arguments')
    requiredNamed.add_argument(
        '--url',
        help="RedFish device hostname or IP",
        required=True
    )
    requiredNamed.add_argument(
        "-o", "--output", 
        help="Directs the output to a name of your choice", 
        required=True
    )
    requiredNamed.add_argument(
        '--user', 
        help="HTTP basic auth user",
        required=True
    )
    requiredNamed.add_argument(
        '--pwd', 
        help="HTTP basic auth password",
        required=True
    )
    parser.add_argument(
        '--skipverify', 
        help="Skip HTTPS certificate validation",
        action='store_false', 
        required=False
    )

    return(parser.parse_args())


def getSubtrees(loc):

    try:
        url = urllib.parse.urljoin(urlPrefix, loc.path)
        r = requests.get(url, auth=(a.user, a.pwd), verify=a.skipverify)
    except SSLError as e:
        logging.error("Problem with SSL validation of HTTPS.")
        print(e)
        sys.exit(1)

    if "Actions" in r.json():
        for actionName in r.json()['Actions']:
            loc.appendAction(actionName)

    for child in r.json():
        if str(child) == "Actions":
            continue  # actions are logged above
        if str(child) == "MetricReport":
            continue  # causes loops

        if isinstance(r.json()[child], dict):
            if "@odata.id" in r.json()[child]:
                loc.appendChild(r.json()[child]['@odata.id'])

    try:
        for child in r.json()['Members']:
            if isinstance(child, dict):
                if "@odata.id" in child:
                    loc.appendChild(child['@odata.id'])
    except(KeyError):
        # Members are not mandatory data structure
        pass

    return(loc)


def prependHttpWhenMissing(url):
    if not re.match('(?:http|https)://', url):
        return f'http://{url}'
    return url


# =================================

logging.basicConfig(level=logging.INFO)

if __name__ == "__main__":
    
    a = parseArguments()

    if not a.skipverify:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    if path.exists(a.output):
        logging.error(f"Output path {a.output} exists.")
        sys.exit(1)


    urlPrefix = prependHttpWhenMissing(a.url)

    # stack with API endpoints to be explored
    loc_stack = []
    # list containing all discovered endpoints so far
    loc_list = []

    # get root of redfish API tree:
    root_loc = getSubtrees(redFishLoc("/redfish/v1"))
    loc_stack.append(root_loc)
    loc_list.append(root_loc.path)

    request_counter = 0

    while len(loc_stack) > 0:
        loc = loc_stack.pop()
        loc_stack_l = len(loc_stack)
        loc_list_l = len(loc_list)
        logging.info(
            f"stack size: {str(loc_stack_l)} | pages found: {str(loc_list_l)} | current loc: {str(loc.path)}")
        for child_path in loc.children:
            child_loc = getSubtrees(redFishLoc(child_path))
            request_counter = request_counter + 1
            if child_loc.path not in loc_list:
                loc_list.append(child_loc.path)
            loc_stack.append(child_loc)

    logging.info(f"http requests: {request_counter}")

    loc_list.sort()
    yaml_string = yaml.dump(loc_list, explicit_start=True, default_flow_style=False)

    with open(a.output, 'w') as text_file:
        text_file.write(yaml_string)
