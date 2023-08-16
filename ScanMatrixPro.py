#!/usr/bin/python3
# -*- coding: utf-8 -*-

import nmap
import xml.etree.ElementTree


class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'


def line():
	print("========================================================================")


def syn_scan():
	try:
		host_address = input(Colors.BLUE + "Provide a valid Host/Hostname address\n" + Colors.ENDC + ': ')
		print(Colors.WARNING + f"Host: {host_address}" + Colors.ENDC)
		line()
		print(Colors.WARNING + 'Starting Scan...' + Colors.ENDC)
		line()
		nm.scan(host_address, '1-1024', arguments='-v -sS')
		for host in nm.all_hosts():
			print(Colors.HEADER + "Nmap version: " + Colors.ENDC + f"{nm.nmap_version()}")
			print(Colors.HEADER + "Scan Information: " + Colors.ENDC + f"{nm.scaninfo()}")
			print(Colors.HEADER + 'Host: ' + Colors.ENDC + f'{host} | {nm[host].hostname()}')
			print(Colors.HEADER + 'State: ' + Colors.ENDC + f'{nm[host].state()}')
			for proto in nm[host].all_protocols():
				line()
				print(f'Protocol : {proto}')	
				lport = nm[host][proto].keys()
				for port in lport:
					state = nm[host][proto][port]['state']
					service_name = nm[host][proto][port]['name']
					print(Colors.WARNING + f'Port : {port}\t' + 
						Colors.GREEN + f'State : {state}\t' + 
						Colors.BLUE + f'Service : {service_name}' + Colors.ENDC)
		line()
	except xml.etree.ElementTree.ParseError:
			print(Colors.FAIL + "Permission error | Try running with: sudo ./scanmatrixpro.py" + Colors.ENDC)
			line()
			exit()
	except nmap.PortScannerError:
			print(Colors.FAIL + "Permission error | Try running with: sudo ./scanmatrixpro.py" + Colors.ENDC)
			line()
			exit()


nm = nmap.PortScanner()

print(Colors.HEADER + "============================" + Colors.ENDC)
print(Colors.HEADER + "  Welcome to SCANMATRIXPRO  " + Colors.ENDC)
print(Colors.HEADER + "============================" + Colors.ENDC)

while True:
	type_scan = input(Colors.BLUE + "Select a Scan type:" + Colors.ENDC + "\n[1] SYN Scan\n[2] UDP Scan\n[3] Silence Scan\n[4] Network Status\n[*] Any other for exit\n: ")
	# print(Colors.WARNING + f"Scan type selected: [{type_scan}]" + Colors.ENDC)
	line()
	if type_scan == '1':
		try:
			syn_scan()
		except:
			print(Colors.FAIL + "Unexpected error" + Colors.ENDC)
			print()
	else:
		exit()