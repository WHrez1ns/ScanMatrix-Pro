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


def nmap_scan(argument, scan_type_name):
	try:
		host_address = input(Colors.BLUE + "Provide a valid Host address\n" + Colors.ENDC + ': ')
		if host_address == '':
			host_address = "0.0.0.0"
		print(Colors.WARNING + f"Host: {host_address}" + Colors.ENDC)
		line()
		range = input(Colors.BLUE + "Provide a valid Range or Port/Ports | Example: 1-1024 \n" + Colors.ENDC + ': ')
		if range == '':
			range = "1-1024"
		print(Colors.WARNING + f"Range: {range}" + Colors.ENDC)
		line()
		save_in_file = input(Colors.BLUE + "Save result to an external file? | Y/N \n" + Colors.ENDC + ': ').upper()
		if save_in_file == 'Y' or save_in_file == 'YES':
			save_in_file = True
		else:
			save_in_file = False
		print(Colors.WARNING + f"Save result: {save_in_file}" + Colors.ENDC)
		line()
		print(Colors.GREEN + 'Starting Scan' + Colors.ENDC)
		line()
		nm.scan(host_address, range, arguments=argument)
		time.sleep(3)
		for host in nm.all_hosts():
			if nm[host].state() == "down":
				print(Colors.FAIL + "Non-existent or inactive host" + Colors.ENDC)
				line()
			else:
				if save_in_file:
					with open('scan_report.txt', 'w') as report:
						report.write("========================================================================\n")
						report.write(f"Nmap version: {nm.nmap_version()}\n")
						report.write(f"Scan type: {scan_type_name}\n")
						report.write(f"Host: {host} | {nm[host].hostname()}\n")
						report.write(f"State: {nm[host].state()}\n")
						report.write("========================================================================\n")
				print(Colors.HEADER + "Nmap version: " + Colors.ENDC + f"{nm.nmap_version()}")
				print(Colors.HEADER + "Scan type: " + Colors.ENDC + scan_type_name)
				print(Colors.HEADER + 'Host: ' + Colors.ENDC + f'{host} | {nm[host].hostname()}')
				print(Colors.HEADER + 'State: ' + Colors.ENDC + f'{nm[host].state()}')
				for proto in nm[host].all_protocols():
					line()
					print(f'Protocol : {proto}')	
					lport = nm[host][proto].keys()
					for port in lport:
						state = nm[host][proto][port]['state']
						service_name = nm[host][proto][port]['name']
						if save_in_file:
							with open('scan_report.txt', 'a') as report:
								report.write(f"[+] Port : {port}\tState : {state}\tService : {service_name}\n")
						print("[+] " + Colors.WARNING + f'Port : {port}\t\t' + 
							  	    Colors.GREEN + f'State : {state}\t\t' + 
							  		Colors.BLUE + f'Service : {service_name}' + Colors.ENDC)
		line()
	except xml.etree.ElementTree.ParseError:
			print(Colors.FAIL + "Permission error | Try running with: sudo ./scanmatrixpro.py" + Colors.ENDC)
			line()
	except nmap.PortScannerError:
			print(Colors.FAIL + "Permission error | Try running with: sudo ./scanmatrixpro.py" + Colors.ENDC)
			line()

def fingerprint_scan(argument):
	try:
		host_address = input(Colors.BLUE + "Provide a valid Host address | Recommended: 0.0.0.0\n" + Colors.ENDC + ': ')
		if host_address == '':
			host_address = "0.0.0.0"
		print(Colors.WARNING + f"Host: {host_address}" + Colors.ENDC)
		line()
		save_in_file = input(Colors.BLUE + "Save result to an external file? | Y/N \n" + Colors.ENDC + ': ').upper()
		if save_in_file == 'Y' or save_in_file == 'YES':
			save_in_file = True
		else:
			save_in_file = False
		print(Colors.WARNING + f"Save result: {save_in_file}" + Colors.ENDC)
		line()
		# fiware fingerprint
		fiware_range = "1026, 1883, 4041, 8666, 9001, 27017"
		fiware_ports = ["1026", "1883", "4041", "8666", "9001", "27017"]
		fiware_status = []
		# phpmyadmin fingerprint
		phpmyadmin_range = "80, 443, 3306"
		phpmyadmin_ports = ["80", "443", "3306"]
		phpmyadmin_status = []
		# fiware scan
		nm.scan(host_address, fiware_range, arguments=argument)
		time.sleep(3)
		for host in nm.all_hosts():
			if nm[host].state() == "down":
				print(Colors.FAIL + "Non-existent or inactive host" + Colors.ENDC)
				line()
			else:
				if save_in_file:
					with open('fingerprint_report.txt', 'w') as report:
						report.write("========================================================================\n")
						report.write("* Fingerprint Analysis *\n")
						report.write("========================================================================\n")
				print(Colors.HEADER + "* Fingerprint Analysis *" + Colors.ENDC)
				for proto in nm[host].all_protocols():
					line()
					print(f'Protocol : {proto}')
					lport = nm[host][proto].keys()
					for port in lport:
						state = nm[host][proto][port]['state']
						service_name = nm[host][proto][port]['name']
						if save_in_file:
							with open('fingerprint_report.txt', 'a') as report:
								report.write(f"[+] Port : {port}\tState : {state}\tService : {service_name}\n")
						print("[+] " + Colors.WARNING + f'Port : {port}\t\t' + 
							  	    Colors.GREEN + f'State : {state}\t\t' + 
							  		Colors.BLUE + f'Service : {service_name}' + Colors.ENDC)
						if not port in fiware_ports and state == "open":
							fiware_status.append(1)
						else:
							fiware_status.append(0)
				if not 0 in fiware_status:
					line()
					print("[!] " + Colors.WARNING + '"Fiware" Detected on server' + Colors.ENDC)
					if save_in_file:
						with open('fingerprint_report.txt', 'a') as report:
							report.write("========================================================================\n")
							report.write('[!] "Fiware" Detected on server\n')
							report.write("========================================================================\n")
				else:
					line()
					print("[!] " + Colors.FAIL + '"Fiware" Undetected' + Colors.ENDC)
					with open('fingerprint_report.txt', 'a') as report:
							report.write("========================================================================\n")
							report.write('[!] "Fiware" Undetected\n')
							report.write("========================================================================\n")
		line()
		# phpmyadmin scan
		nm.scan(host_address, phpmyadmin_range, arguments=argument)
		time.sleep(3)
		for host in nm.all_hosts():
			if nm[host].state() == "down":
				print(Colors.FAIL + "Non-existent or inactive host" + Colors.ENDC)
				line()
			else:
				for proto in nm[host].all_protocols():
					print(f'Protocol : {proto}')
					lport = nm[host][proto].keys()
					for port in lport:
						if save_in_file:
							with open('fingerprint_report.txt', 'a') as report:
								report.write(f"[+] Port : {port}\tState : {state}\tService : {service_name}\n")
						state = nm[host][proto][port]['state']
						service_name = nm[host][proto][port]['name']
						print("[+] " + Colors.WARNING + f'Port : {port}\t\t' + 
							  	    Colors.GREEN + f'State : {state}\t\t' + 
							  		Colors.BLUE + f'Service : {service_name}' + Colors.ENDC)
						if not port in phpmyadmin_ports and state == "open":
							phpmyadmin_status.append(1)
						else:
							phpmyadmin_status.append(0)
				if not 0 in phpmyadmin_status:
					line()
					print("[!] " + Colors.WARNING + '"PhpMyAdmin" Can be on server' + Colors.ENDC)
					if save_in_file:
						with open('fingerprint_report.txt', 'a') as report:
							report.write("========================================================================\n")
							report.write('[!] "PhpMyAdmin" Can be on server\n')
							report.write("========================================================================\n")
				else:
					line()
					print("[!] " + Colors.FAIL + '"PhpMyAdmin" Undetected' + Colors.ENDC)
					with open('fingerprint_report.txt', 'a') as report:
							report.write("========================================================================\n")
							report.write('[!] "PhpMyAdmin" Undetected\n')
							report.write("========================================================================\n")
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
print(Colors.HEADER + " |____/  \___|\__,_||_| |_||_|  |_| \__,_| \__||_|   |_|/_/\_\      |_|    |_|   \___/  \n" + Colors.ENDC)
print(Colors.FAIL + "                                                      ScanMatrix-Pro v3.0 - by Renan D. " + Colors.ENDC)
                                                                                       

while True:
	try:
		type_scan = int(input(Colors.BLUE + "Select a option:" + Colors.ENDC + "\n[1] TCP SYN scan\n[2] TCP connect scan\n[3] UDP scan\n[4] Aggressive scan\n[5] Custom scan\n[6] Fingerprint Analysis\n[7] Exit\n: "))
		line()
		# TCP SYN scan
		if type_scan == 1:
			try:
				nmap_scan('-sS', 'TCP SYN scan')
			except:
				print(Colors.FAIL + "Unexpected error" + Colors.ENDC)
		# TCP connect scan
		elif type_scan == 2:
			try:
				nmap_scan('-sT', 'TCP connect scan')
			except:
				print(Colors.FAIL + "Unexpected error" + Colors.ENDC)
		# UDP scan
		elif type_scan == 3:
			try:
				nmap_scan('-sU', 'UDP scan')
			except:
				print(Colors.FAIL + "Unexpected error" + Colors.ENDC)
		# Aggressive scan
		elif type_scan == 4:
			try:
				nmap_scan('-A', 'Aggressive scan')
			except:
				print(Colors.FAIL + "Unexpected error" + Colors.ENDC)
		# Custom Scan
		elif type_scan == 5:
			try:
				custom_arguments = input(Colors.BLUE + "Provide a valid Arguments | Example: --open -sS" + Colors.ENDC + "\n: ")
				print(Colors.WARNING + f"Arguments: {custom_arguments}" + Colors.ENDC)
				line()
				nmap_scan(custom_arguments, 'Custom Scan')
			except:
				print(Colors.FAIL + "Unexpected error" + Colors.ENDC)
		# Fingerprint Detect
		elif type_scan == 6:
			fingerprint_scan("")
		# Exit
		elif type_scan == 7:
			print(Colors.HEADER + 'Until later :D')
			exit()
		# Error
		else:
			print(Colors.FAIL + "Non-existent option | Try running with: 1, 2, 3, 4, 5, 6 or 7" + Colors.ENDC)
			line()
	except ValueError:
		line()
		print(Colors.FAIL + "Value error | Try running with: 1, 2, 3, 4, 5, 6 or 7" + Colors.ENDC)
		line()