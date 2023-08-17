#!/usr/bin/python3
# -*- coding: utf-8 -*-

import nmap
import xml.etree.ElementTree
import time


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
		host_address = input(Colors.BLUE + "Provide a valid Host address\n" + Colors.ENDC + ': ')
		print(Colors.WARNING + f"Host: {host_address}" + Colors.ENDC)
		line()
		print(Colors.GREEN + 'Starting Scan' + Colors.ENDC)
		line()
		nm.scan(host_address, '1-1024', arguments='-v -sS')
		time.sleep(3)
		for host in nm.all_hosts():
			if nm[host].state() == "down":
				print(Colors.FAIL + "Non-existent or inactive host" + Colors.ENDC)
				line()
			else:
				print(Colors.HEADER + "Nmap version: " + Colors.ENDC + f"{nm.nmap_version()}")
				print(Colors.HEADER + "Scan type: " + Colors.ENDC + "SYN Scan")
				print(Colors.HEADER + 'Host: ' + Colors.ENDC + f'{host} | {nm[host].hostname()}')
				print(Colors.HEADER + 'State: ' + Colors.ENDC + f'{nm[host].state()}')
				for proto in nm[host].all_protocols():
					line()
					print(f'Protocol : {proto}')	
					lport = nm[host][proto].keys()
					for port in lport:
						state = nm[host][proto][port]['state']
						service_name = nm[host][proto][port]['name']
						print("[+] " + Colors.WARNING + f'Port : {port}\t' + 
							  	    Colors.GREEN + f'State : {state}\t' + 
							  		Colors.BLUE + f'Service : {service_name}' + Colors.ENDC)
		line()
	except xml.etree.ElementTree.ParseError:
			print(Colors.FAIL + "Permission error | Try running with: sudo ./scanmatrixpro.py" + Colors.ENDC)
			line()
	except nmap.PortScannerError:
			print(Colors.FAIL + "Permission error | Try running with: sudo ./scanmatrixpro.py" + Colors.ENDC)
			line()


nm = nmap.PortScanner()

print(Colors.HEADER + "  ____                      __  __         _          _              ____               " + Colors.ENDC)
print(Colors.HEADER + " / ___|   ___  __ _  _ __  |  \/  |  __ _ | |_  _ __ (_)__  __      |  _ \  _ __  ___   " + Colors.ENDC)
print(Colors.HEADER + " \___ \  / __|/ _` || '_ \ | |\/| | / _` || __|| '__|| |\ \/ /_____ | |_) || '__|/ _ \  " + Colors.ENDC)
print(Colors.HEADER + "  ___) || (__| (_| || | | || |  | || (_| || |_ | |   | | >  <|_____||  __/ | |  | (_) | " + Colors.ENDC)
print(Colors.HEADER + " |____/  \___|\__,_||_| |_||_|  |_| \__,_| \__||_|   |_|/_/\_\      |_|    |_|   \___/  " + Colors.ENDC)
print("")
print(Colors.FAIL + "                                                      ScanMatrix-Pro v1.1 - by Renan D. " + Colors.ENDC)
                                                                                       

while True:
	try:
		type_scan = int(input(Colors.BLUE + "Select a Scan type:" + Colors.ENDC + "\n[1] SYN Scan\n[2] UDP Scan\n[3] Silence Scan\n[4] Network Status\n[5] Exit\n: "))
		line()
		if type_scan == 1:
			try:
				syn_scan()
			except:
				print(Colors.FAIL + "Unexpected error" + Colors.ENDC)
		elif type_scan == 5:
			exit()
	except ValueError:
		line()
		print(Colors.FAIL + "Value error | Try running with: 1, 2, 3, 4 or 5" + Colors.ENDC)
		line()