#!/usr/bin/python3

'''
Description:  Python script to query IPv4 , Domain, or URL functions through the use of apivoid.com's Threat Analysis APIs
Reference:  https://www.apivoid.com/
Author:  Kris Rostkowski
'''

# imported modules
import requests
import json
import keyring
import re
import argparse
from pprint import pprint


# argparse function
# setup multiple arguments to call different apivoid functions
def get_args():

    parser = argparse.ArgumentParser(prog="apivoid lookup script",
                                     description="Python script to query IPv4 , Domain, or URL functions through the use of apivoid.com's Threat Analysis APIs ")
    parser.add_argument("-i", "--ipaddress", help="Input IPv4 address to run the IP reputation function")
    parser.add_argument("-d", "--domain", help="Input domain to run the domain blacklist function")
    parser.add_argument("-u", "--url", help="Input URL to run the URL reputation function")
    parser.add_argument("-sT", "--sitetrust", help="Input domain to run the Site Trustworthiness record function")
    parser.add_argument("-t", "--threatlog", help="Input domain to run the ThreatLog function")
    parser.add_argument("-sL", "--ssl", help="Input domain to run the SSL lookup function")

    args = parser.parse_args()

    return args


# check for valid IP address, supply error message, kill process
def ip_check(ip):

    ip_re = re.compile(
        "^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$")
    if ip_re.match(ip):
        return ip
    else:
        print(f"\nprocess killed, {ip} is not an ip address")
        exit()


# check for valid URLs, supply error message, kill process
def url_check(url):

    url_regex = re.compile("http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+")
    if url_regex.match(url):
        return url
    else:
        print(f"\nprocess killed, {url} is not a valid URL.  Please add http(s):// to your URL.")
        exit()


# ip reputation function
def ip_reputation(ip_rep):

    token = keyring.get_password("apivoid", "username")
    base_url = "https://endpoint.apivoid.com/iprep/v1/pay-as-you-go/?key="
    request = requests.get(base_url + token + "&ip=" + ip_rep)
    data = json.loads(request.text)
    anonymity = (data["data"]["report"]["anonymity"])
    blacklists = (data["data"]["report"]["blacklists"])
    information = (data["data"]["report"]["information"])

    # deleting unwanted data from dictionaries
    del (data["data"]["report"]["blacklists"]["engines"])

    print("\nAnonymity Information:")
    for key, value in anonymity.items():
        print("  ", key, ":", value)

    print("\nIP Blacklist:")
    for key, value in blacklists.items():
        print("  ", key, ":", value)

    print("\nServer Information:")
    for key, value in information.items():
        print("  ", key, ":", value)


# domain reputation function
def d_reputation(d_rep):

    token = keyring.get_password("apivoid", "username")
    base_url = "https://endpoint.apivoid.com/domainbl/v1/pay-as-you-go/?key="
    request = requests.get(base_url + token + "&host=" + d_rep)
    data = json.loads(request.text)
    report = (data["data"]["report"])
    blacklists = (data["data"]["report"]["blacklists"])
    category = (data["data"]["report"]["category"])
    server = (data["data"]["report"]["server"])

    # deleting unwanted data from dictionaries
    del (data["data"]["report"]["blacklists"]["engines"])
    del (data["data"]["report"]["blacklists"])
    del (data["data"]["report"]["category"])
    del (data["data"]["report"]["server"])

    print("\nReport:")
    for key, value in report.items():
        print("  ", key, ":", value)

    print("\nDomain Blacklist:")
    for key, value in blacklists.items():
        print("  ", key, ":", value)

    print("\nCategory:")
    for key, value in category.items():
        print("  ", key, ":", value)

    print("\nServer Information:")
    for key, value in server.items():
        print("  ", key, ":", value)


# url reputation function
def url_reputation(u_rep):

    token = keyring.get_password("apivoid", "username")
    base_url = "https://endpoint.apivoid.com/urlrep/v1/pay-as-you-go/?key="
    request = requests.get(base_url + token + "&url=" + u_rep)
    data = json.loads(request.text)
    dns_records = (data["data"]["report"]["dns_records"]["mx"])
    ns_lookup = (data["data"]["report"]["dns_records"]["ns"])
    domain_blacklist = (data["data"]["report"]["domain_blacklist"])
    geo_location = (data["data"]["report"]["geo_location"])
    risk_score = (data["data"]["report"]["risk_score"])
    security_checks = (data["data"]["report"]["security_checks"])
    site_category = (data["data"]["report"]["site_category"])

    # deleting unwanted data from dictionaries
    del (data["data"]["report"]["domain_blacklist"]["engines"])

    print("\nDNS Records:")
    pprint(dns_records)  # needs cleaning up

    print("\nNS Lookup:")
    pprint(ns_lookup)  # needs cleaning up

    print("\nDomain Blacklist:")
    for key, value in domain_blacklist.items():
        print("  ", key, ":", value)

    print("\nGeolocation:")
    for key, value in geo_location.items():
        print("  ", key, ":", value)

    print("\nRisk Score:")
    for key, value in risk_score.items():
        print("  ", key, ":", value)

    print("\nSecurity Checks:")
    for key, value in security_checks.items():
        print("  ", key, ":", value)

    print("\nSite Category:")
    for key, value in site_category.items():
        print("  ", key, ":", value)


# site trustworthiness function
def site_trust(s_trust):

    token = keyring.get_password("apivoid", "username")
    base_url = "https://endpoint.apivoid.com/sitetrust/v1/pay-as-you-go/?key="
    request = requests.get(base_url + token + "&host=" + s_trust)
    data = json.loads(request.text)
    blacklist = (data["data"]["report"]["domain_blacklist"])
    trust_score = (data["data"]["report"]["trust_score"])
    server_details = (data["data"]["report"]["server_details"])

    # deleting unwanted data from dictionaries
    del (data["data"]["report"]["domain_blacklist"]["engines"])

    print("\nBlacklist:")
    for key, value in blacklist.items():
        print("  ", key, ":", value)

    print("\nTrust Score:")
    for key, value in trust_score.items():
        print("  ", key, ":", value)

    print("\nServer Details:")
    for key, value in server_details.items():
        print("  ", key, ":", value)


# threat log function
def threat_log(t_log):

    token = keyring.get_password("apivoid", "username")
    base_url = "https://endpoint.apivoid.com/threatlog/v1/pay-as-you-go/?key="
    request = requests.get(base_url + token + "&host=" + t_log)
    data = json.loads(request.text)
    host = (data["data"])
    threatlog = (data["data"]["threatlog"])

    # deleting unwanted data from dictionaries
    del (data["data"]["threatlog"])

    print("\nHost Information:")
    for key, value in host.items():
        print("  ", key, ":", value)

    print("\nThreat Log:")
    for key, value in threatlog.items():
        print("  ", key, ":", value)


# ssl function
def get_ssl(s_look):

    token = keyring.get_password("apivoid", "username")
    base_url = "https://endpoint.apivoid.com/sslinfo/v1/pay-as-you-go/?key="
    request = requests.get(base_url + token + "&host=" + s_look)
    data = json.loads(request.text)
    certificate = (data["data"]["certificate"])
    extensions = (data["data"]["certificate"]["details"]["extensions"])
    issuer = (data["data"]["certificate"]["details"]["issuer"])
    signature = (data["data"]["certificate"]["details"]["signature"])
    subject = (data["data"]["certificate"]["details"]["subject"])
    validity = (data["data"]["certificate"]["details"]["validity"])

    # deleting unwanted data from dictionaries
    del (data["data"]["certificate"]["details"])

    print("\nCertificate Information:")
    for key, value in certificate.items():
        print("  ", key, ":", value)

    print("\nExtensions:")
    for key, value in extensions.items(): # need to adjust formatting
        print("  ", key, ":", value)

    print("\nIssuer:")
    for key, value in issuer.items():
        print("  ", key, ":", value)

    print("\nSignature Information:")
    for key, value in signature.items():
        print("  ", key, ":", value)

    print("\nSubject:")
    for key, value in subject.items():
        print("  ", key, ":", value)

    print("\nValidity:")
    for key, value in validity.items():
        print("  ", key, ":", value)

# main
def main():

    args = get_args()
    ip_rep = args.ipaddress
    d_rep = args.domain
    u_rep = args.url
    s_trust = args.sitetrust
    t_log = args.threatlog
    s_look = args.ssl

    if args.ipaddress:
        ip_check(ip_rep)
        ip_reputation(ip_rep)
    elif args.domain:
        d_reputation(d_rep)
    elif args.url:
        url_check(u_rep)
        url_reputation(u_rep)
    elif args.sitetrust:
        site_trust(s_trust)
    elif args.threatlog:
        threat_log(t_log)
    elif args.ssl:
        get_ssl(s_look)
    else:
        print("Not a valid request, please try again.")


if __name__ == "__main__":
    main()
