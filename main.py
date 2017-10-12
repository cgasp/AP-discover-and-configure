#!/usr/bin/env python
# -*- coding: utf-8 -*-

import argparse
import paramiko
import time
from paramiko_expect import SSHClientInteraction
from netaddr import *
import os
import re
from ConfigParser import SafeConfigParser
import sys

__author__ = "cgasp"


def arg_parse():

    text_description = """
Script for Automatic Ruckus AP Provisioning.
It will scan the local network (default : 192.168.0.0/24) and look for Ruckus AP.
After it had detected Ruckus AP, it will try to connect in SSH and to configure the WLC/SCG IP.
It will connect to All Ruckus AP connected to network LAN scanned sequentially.

Usage : 

python main.py -u super -p sp-admin -a 192.168.0.1 -w 10.0.0.1

Limitation : 

Only IPv4 supported 

"""
    parser = argparse.ArgumentParser(description=text_description, formatter_class=argparse.RawTextHelpFormatter)

    # Parse config file for default values

    configfile = 'config.ini'

    parse_config = SafeConfigParser()
    parse_config.read(configfile)

    default_username = parse_config.get('default', 'username')
    default_password = parse_config.get('default', 'password')
    default_subnet = parse_config.get('default', 'subnet')
    default_wlc_ip = parse_config.get('default', 'wlc_ip')

    parser.add_argument('-u', '--username', dest='username', action='store', type=str, nargs='?',
                        default=default_username, help='username configuration\nDEFAULT: '+default_username)
    parser.add_argument('-p', '--password', dest='password', action='store', type=str, nargs='?',
                        default=default_password, help='password configuration\nDEFAULT: '+default_password)
    parser.add_argument('-s', '--subnet', dest='subnet', action='store', type=str, nargs='?',
                        default=default_subnet,
                        help='subnet and subnet mask e.g. -s 192.168.0.0/255.255.255.0 \nDEFAULT: '+default_subnet)
    parser.add_argument('-a', '--ap-ip', dest='ap_ip', action='store', type=str, help='IP of AP, if given no scanning will be done')

    parser.add_argument('-w', '--wlc_ip', dest='wlc_ip', action='store', type=str, nargs='?',
                        default=default_wlc_ip, help='WLC IP to configure\nDEFAULT: '+default_wlc_ip)

    return parser.parse_args()


def query_yes_no(question, default="yes"):
    valid = {"yes": True, "y": True, "ye": True,
             "no": False, "n": False}
    if default is None:
        prompt = " [y/n] "
    elif default == "yes":
        prompt = " [Y/n] "
    elif default == "no":
        prompt = " [y/N] "
    else:
        raise ValueError("invalid default answer: '%s'" % default)

    while True:
        sys.stdout.write(question + prompt)
        choice = raw_input().lower()
        if default is not None and choice == '':
            return valid[default]
        elif choice in valid:
            return valid[choice]
        else:
            sys.stdout.write("Please respond with 'yes' or 'no' "
                             "(or 'y' or 'n').\n")


def detect_and_return_ruckus_devices_ips():
    hosts = []
    ruckusap_ips = []
    i = 0
    with open('scan_output', 'r') as f:
        for line in f:
            hosts.append(line)
            if 'Ruckus Wireless' in line:
                ip_ruckus = re.findall(
                    r'(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)',
                    hosts[i - 2])[0]
                print "[INFO] Found : " + line + " IP : " + ip_ruckus
                ruckusap_ips.append(ip_ruckus)
            i += 1
    return ruckusap_ips


def scan_net(prefix):
    cmd = r'nmap_minimal\nmap.exe -sn '+prefix+r' > scan_output'
    os.system(cmd)
    return detect_and_return_ruckus_devices_ips()


def connect_and_configure(hostname, username, password, port, wlc_ip):
    print "[INFO] Establish connection to " + hostname
    try:
        try:
            client = paramiko.SSHClient()
            client.load_system_host_keys()
            # client.set_missing_host_key_policy(paramiko.WarningPolicy)
            client.set_missing_host_key_policy(paramiko.WarningPolicy())

            client.connect(hostname, port=port, username=username, password=password)

            try:
                # Create a client interaction class which will interact with the host
                interact = SSHClientInteraction(client, timeout=5, display=True)

                print "[INFO] Connected to " + hostname

                interact.expect('.*login:.*')

                # Run the first command and capture the cleaned output, if you want the output
                # without cleaning, simply grab current_output instead.

                interact.send(username)

                interact.expect('.*password.*')
                interact.send(password)

                interact.expect('.*rkscli:.*')

                print "[INFO] Logged in to " + hostname
                interact.send('set scg ip ' + wlc_ip)
                interact.expect('.*rkscli:.*')
                time.sleep(5)
                interact.send('get scg')
                interact.expect('.*rkscli:.*')

                print "[INFO] Complete AP Provisioned"

                client.close()
                print "[INFO] Connection closed"
                return True

            except:
                print "\n[WARNING]\tProblem in Login credentials\n" \
                      "\tAre the login credentials good ?\n" \
                      "\tHave you Factory Reset the AP ?"
                return False

        except:
            print "\n[WARNING]\tProblem in SSH connection\n\tHave the device ended to boot ?"
            return False

    except:
        print "\n[WARNING]\tProblem in connection"
        return False


def keep_scanning(network, prefixlen):
    ruckus_hosts = scan_net(str(network) + '/' + str(prefixlen))
    # Do once the config if not sucess - retry
    if not ruckus_hosts:
        while query_yes_no("\nNo Ruckus AP found - Scan again ?", default="yes"):
            # if not sucess - re-ask again
            ruckus_hosts = scan_net(str(network) + '/' + str(prefixlen))
            if ruckus_hosts:
                # if sucess break the loop
                break
    return ruckus_hosts


def keep_connecting(hostname, username, password, port, wlc_ip):
    # Do once the config if not sucess - retry
    if not(connect_and_configure(hostname, username, password, port, wlc_ip)):
        while query_yes_no("\n[?] Do you wish to retry ?", default="yes"):
            # if not sucess - re-ask again
            if connect_and_configure(hostname, username, password, port, wlc_ip):
                # if sucess break the loop
                break


def main():
    # Load arguments
    args = arg_parse()
    range_ip = IPNetwork(args.subnet)
    print "[INFO] scanning network .... (take some seconds - depending network size)"

    ruckus_hosts = []
    if not args.ap_ip:
        # Scan network to get list of Ruckus AP
        ruckus_hosts = keep_scanning(range_ip.network, range_ip.prefixlen)
    elif IPAddress(args.ap_ip).version == 4:
        ruckus_hosts.extend(args.ap_ip.split(','))

    # If Ruckus AP retrieved
    if ruckus_hosts:
        for host in ruckus_hosts:
            if query_yes_no("[?] Configure " + host + " ?", "yes"):
                keep_connecting(host, args.username, args.password, 22, args.wlc_ip)
    else:
        print "[WARNING] No Ruckus device Found\n" \
              "\tIs the device connected in the network ?"

    print "[INFO] Application done - Bye ! "
    os.system('pause')

if __name__ == '__main__':
    main()
