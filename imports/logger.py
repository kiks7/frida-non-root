from termcolor import colored
import os

debug = False

def set_debug(value):
    global debug
    if value:
        debug = value

def print_info(message):
    print(colored("[*] " + message, "cyan"))

def print_debug(message):
    if debug:
        print(colored("[!] " + message, "white", attrs=['bold']))

def print_ok(message):
    print(colored("[+] " + message, "green"))

def print_error(message):
    print(colored("[-] " + message, "red"))

def print_warning(message):
    print(colored("[!!] " + message, "yellow"))