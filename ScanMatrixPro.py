# funcionando no linux

import nmap

nm = nmap.PortScanner()
nm.scan('avalontech.net.br', '22-443')