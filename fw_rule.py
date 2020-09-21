#!/usr/bin/python3  -W ignore::DeprecationWarning

import requests
import json
import sys
import csv
import time
import getpass
import ipaddress
import argparse
import cgi,cgitb
import apifunctions

#remove the InsecureRequestWarning messages
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

"""
test code to try and create simple http repy of data with json
"""
"""
on mds side:
mgmt_cli -r true  show domains --format json
 .total for num of domains
 jq '.objects[] | .name'
"""
def get_domains(ip_addr):
    domain_list = []
    debug = 1
    term = "\n"

    try:
        domain_sid = apifunctions.login("roapi", "1qazxsw2", ip_addr, "")
        if(debug == 1):
            print("session id : " + domain_sid, end = term)

        get_domain_result =apifunctions.api_call(ip_addr, "show-domains", {}, domain_sid)
        
        if(debug == 1):
            print(json.dumps(get_domain_result), end = term)

        for x in range(get_domain_result['total']):
            #print(get_domain_result['objects'][x]['name'])
            domain_list.append(get_domain_result['objects'][x]['name'])

        #time.sleep(5)
        logout_result = apifunctions.api_call(ip_addr, "logout", {}, domain_sid)
        if(debug == 1):
            print(logout_result, end = term)
    except:
        print("Unable to get Domain List", end = term)
    return(domain_list)
#end of get_domains

"""
login to domain and see if host object with IP exist
"""
def search_domain_4_ip(ip_addr, cma, ip_2_find):
    debug = 0
    term = "\n"
    try:
        cma_sid = apifunctions.login("roapi", "1qazxsw2", ip_addr, cma)
        
        if(debug == 1):
            print("session id : " + cma_sid, end=term)
        
        check_host_obj = {"type" : "host", "filter" : ip_2_find, "ip-only" : "true"}
        check_host = apifunctions.api_call(ip_addr, "show-objects", check_host_obj, cma_sid)

        if(check_host['total'] == 0):
            print("no host exist", end=term)
        else:
            #print(json.dumps(check_host))
            for x in range(check_host['total']):
                print(check_host['objects'][x]['name'], end=term)
                print(check_host['objects'][x]['ipv4-address'], end=term)
                
                ###whereused_by_name(check_host['objects'][x]['name'], ip_addr, cma, cma_sid)
            ### test code
            print("################################", end=term)
            print(json.dumps(check_host), end=term)
            print("################################", end=term)

        #time.sleep(5)
        logout_result = apifunctions.api_call(ip_addr, "logout", {}, cma_sid)
        if(debug == 1):
            print(logout_result, end=term)
    except:
        if(cma_sid != ""):
            emergency_logout = apifunctions.api_call(ip_addr, "logout", {}, cma_sid)
        print("can't get into domain", end=term)
#end of search_domain_4_ip

"""
do a where used on the cma for a name
"""
def whereused_by_name(name, ip_addr, cma, sid):
    debug = 1
    term = "\n"

    print("Doing function Where Used", end=term)
    search_where_json = {
        "name" : name
    }

    where_used_result = apifunctions.api_call(ip_addr, "where-used", search_where_json, sid)

    if(debug == 1):
        print("^^^^^^^^^^^^^^^^^^^^", end=term)
        print(json.dumps(where_used_result), end=term)
        print("!!!!!!!!!!!!!!!!!!!!", end=term)

    try:
        dtotal = where_used_result['used-directly']['total']
        print("Total Where Used Directly : ", end=term)
        print(dtotal, end=term)

        len_obj          = len(where_used_result['used-directly']['objects'])
        len_access_rule  = len(where_used_result['used-directly']['access-control-rules'])
        len_threat_prev  = len(where_used_result['used-directly']['threat-prevention-rules'])
        len_nat_rules    = len(where_used_result['used-directly']['nat-rules'])

        if(debug == 1):
            print(len_obj, end=term)
            print(len_access_rule, end=term)
            print(len_threat_prev, end=term)
            print(len_nat_rules, end=term)

        print("Use in Object :", end=term)
        for x in range(len_obj):
            print("Use in " + where_used_result['used-directly']['objects'][x]['name'] + " which is a " + where_used_result['used-directly']['objects'][x]['type'], end=term)
            
            sub_search = where_used_result['used-directly']['objects'][x]['name']
            ### add on 07.30 
            print("################ Sub Search for " + sub_search + " ########################", end=term)
            whereused_by_name(sub_search, ip_addr, cma, sid)

            #print(where_used_result['used-directly']['objects'][x]['name'])
            #print(where_used_result['used-directly']['objects'][x]['type'])

        print("Use in Access Rule:<br>")
        for x in range(len_access_rule):
            print("use in policy : " + where_used_result['used-directly']['access-control-rules'][x]['layer']['name'] + " rule-number " + where_used_result['used-directly']['access-control-rules'][x]['position'], end=term)

            tmp_uid = where_used_result['used-directly']['access-control-rules'][x]['rule']['uid']
            tmp_layer = where_used_result['used-directly']['access-control-rules'][x]['layer']['name']

            get_access_rule = {
                'uid' : tmp_uid,
                'layer' : tmp_layer
            }

            access_rule_result = apifunctions.api_call(ip_addr, 'show-access-rule', get_access_rule, sid)

            rule_output(access_rule_result)

            #print(where_used_result['used-directly']['access-control-rules'][x]['position'])
            #print(where_used_result['used-directly']['access-control-rules'][x]['layer']['name'])
        
        print("Use in Threat Prevention Rules:", end=term)
        for x in range(len_threat_prev):
            print("feature not avaliable.  send greg what you searched for", end=term)
        
        print("Use in Nat Rules", end=term)
        for x in range(len_nat_rules):
            print("use in nat rules | policy " + where_used_result['used-directly']['nat-rules'][x]['package']['name'] + " nat-rule number " + where_used_result['used-directly']['nat-rules'][x]['position'], end=term)

            #print(where_used_result['used-directly']['nat-rules'][x]['position'])
            #print(where_used_result['used-directly']['nat-rules'][x]['package']['name'])
    except:
        print("Not used or not searchable", end=term)

    try:
        itotal = where_used_result['used-indirectly']['total']
        print("Total Where Used InDirectly :", end=term)
        print(itotal, end=term)
    except:
        pass
#end of whereused_by_name()


"""
main function
"""
def main():
    print("in main function")
    debug = 1
    term = "\n"

    mds_ip = "146.18.96.16"

    host_ip = "146.18.2.137"

    domain_list = get_domains(mds_ip)

    print(domain_list)

    for domain in domain_list:
        search_domain_4_ip(mds_ip, domain, host_ip)

if __name__ == "__main__":
    main()