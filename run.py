"""
Feature request:

 -> CIDR block support
 -> CVE Numbers
 -> Applications from the directory list (bing script parse)
"""
#!/usr/bin/env python3
from shodan import Shodan, APIError
import argparse # arguments library
import ipaddress as ip # ip parser
from alive_progress import alive_bar
import csv

api = Shodan("") # API KEY

def arguments():
    parser = argparse.ArgumentParser(description='An API query tool to extract data out of Shodan\'s database. This tool will take a while to finish due to API throttle limitations.')
    parser.add_argument("-f", "--file", help="Reads a list of IP Addresses", default=None, type=str)
    parser.add_argument("-i", "--ip", help="Queries a single IP", default=None, type=str)
    parser.add_argument("-o", "--out", help="Output to file (required)", default=None, required=True, type=str)
    return parser.parse_args()

def ip_validation(ip_address):
    try:
        ip.ip_address(ip_address)
        return True
    except ValueError:
        return False

def infile(file):
    valid_ip_block = []

    try:
        with open(file) as infile:
            for ip in infile.readlines():
                if ip_validation(ip.strip()):
                    valid_ip_block.append(ip.strip())
    
        return valid_ip_block
    
    except EnvironmentError as e:
        return f"Unable to open file -> {e}"

def shodan_parse(host):

    try:
        input = api.host(host)
        return [
            input['ip_str'],
            input.get('hostnames', ''),
            input.get('ports', ''),
            input.get('org', ''),
            input.get('isp', ''),
            input.get('city', ''),
            input.get('country_name', ''),
            input.get('error', '')
            ]
        
    except APIError as e:
        print(f"{host} -> {e}")
        return [
            str(host),
            '',
            '',
            '',
            '',
            '',
            '',
            str(e)
        ]

def file_output(ip_block):
    """ Output Method """

    if type(ip_block) is list:
        hosts = []

        # Create CSV
        with open(args.out, 'w', encoding='UTF8', newline='') as outfile:
            writer = csv.writer(outfile)
            header = ["IP Address", "Hostnames", "Ports", "Organization", "ISP", "City", "Country", "Errors"]
            writer.writerow(header)
            with alive_bar(len(ip_block), dual_line=True, title="Shodan") as bar:

                for ip in ip_block:
                    bar.text = f"-> Scanning the IP Address: {ip}, please wait..."
                    outdata = shodan_parse(ip)
                    
                    # Parse hostname data
                    if type(outdata[1]) is list:
                        for hostname in outdata[1]:
                            if hostname not in hosts:
                                hosts.append(hostname)

                    writer.writerow(outdata)
                    bar()
        
        # Mutate hosts
        for domain in hosts:
            domain_split = domain.split('.')
            for i in range(len(domain_split)):
                mutate = ".".join(domain_split[i:len(domain_split)])
                if len(mutate.split('.')) > 1: 
                    if mutate not in hosts:
                        hosts.append(mutate)


        # Create parsed hosts file
        with open(f"{args.out}.hosts", 'w', encoding='UTF8', newline='') as outfile:
            for line in hosts:
                outfile.write(f"{line}\n")

    else:
        print(ip_block)

if __name__ == "__main__":
    args = arguments()
    
    if args.file is None and args.ip is None:
        print("A file name or IP Address is required.")
    
    if args.file and args.ip:
        print("Only one argument at a time.")

    elif args.file and args.out:
        ip_block = infile(args.file)
        file_output(ip_block)
        
    elif args.ip and args.out:
        if ip_validation(args.ip.strip()):
            ip_addr = args.ip.strip()
            file_output([ip_addr])

        else:
            print("Invalid IP Format.")
