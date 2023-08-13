import socket
import time


def portscan():
    print("-----------------------------")
    host = input("Domain/IP: ")
    print("-----------------------------")
    for port in ports:
        port = int(port)
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.settimeout(0.5)
        code = client.connect_ex((host, port))
        if (code == 0):
            print(port, "OPEN")

wordlist = open("simple_wordlist.txt", "r")
ports = wordlist.read().splitlines()
response = "S"

while response:
    portscan()
    print("-----------------------------")
    print("Deseja continuar?")
    response = input("s/n: ").upper()
    if response != "S":
        print("-----------------------------")
        print("Encerrando...")
        print("-----------------------------")
        time.sleep(1.5)
        exit()