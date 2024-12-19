import os
import sys
import time
import colorama
from colorama import *

commands = [Fore.LIGHTGREEN_EX + 'nslookup', 'ping', 'ipconfig', 'ipconfig /all', 'whoami', 'exit']

def nslookup():
    domain = input(Fore.LIGHTGREEN_EX + "Enter domain: ")
    print(Fore.LIGHTGREEN_EX + f"[NSLOOKUP] Getting info about {domain}...")
    time.sleep(0.1)
    os.system(f"nslookup {domain}")
    if not domain:
        print(Fore.LIGHTRED_EX + "Invalid input! Please enter a valid domain.")
        return

def ping():
    domain2 = input(Fore.LIGHTGREEN_EX + "Enter domain to check ping stats: ")
    print(Fore.LIGHTGREEN_EX + "[PING] Checking ping stats...")
    time.sleep(0.1)
    os.system(f'ping {domain2}')
    if not domain2:
        print(Fore.LIGHTRED_EX + "Invalid input! Please enter a valid domain.")
        return

def ipconfig():
    print(Fore.LIGHTGREEN_EX + "[IPCONFIG] Getting ipconfig...")
    time.sleep(0.1)
    os.system('ipconfig')

def ipconfig_all():
    print(Fore.LIGHTGREEN_EX + "[IPCONFIG /ALL] Getting ipconfig all...")
    time.sleep(0.1)
    os.system('ipconfig /all')

def whoami():
    print(Fore.LIGHTGREEN_EX + "[WHOAMI] Getting info...")
    time.sleep(0.1)
    os.system('whoami')

def main(command_list):
    while True:
        user_input = input(Fore.LIGHTGREEN_EX + f"{', '.join(command_list)}\n\n"
                                                f"Please enter a command:  ")
        if user_input == "nslookup":
            nslookup()
        elif user_input == "ping":
            ping()
        elif user_input == "ipconfig":
            ipconfig()
        elif user_input == "ipconfig /all":
            ipconfig_all()
        elif user_input == "whoami":
            whoami()
        elif user_input == "exit":
            print(Fore.LIGHTGREEN_EX + "Exiting...")
            sys.exit()
        elif user_input not in commands:
            print(Fore.LIGHTRED_EX + f"Please make sure your command is on the commands list: {', '.join(command_list)}")


if __name__ == '__main__':
    main(command_list=commands)
