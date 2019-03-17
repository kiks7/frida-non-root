from termcolor import colored
import os

debug = False

def set_debug(value):
    global debug
    if value:
	debug = value

def print_info(str):
	print colored("[*] " + str,"cyan")

def print_debug(str):
    if debug:
    	print colored("[!] "+ str,"white",attrs=['bold'])

def print_ok(str):
    print colored("[+] "+ str,"green")

def print_error(str):
    print colored("[-] "+ str,"red")

def print_warning(str):
    print colored("[!!] " + str,"yellow")
