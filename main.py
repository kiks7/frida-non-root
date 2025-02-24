#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys
import argparse
import subprocess
import re
from shutil import copyfile
import os
from xml.dom import minidom

sys.path.insert(0, './imports/')
from logger import *

devnull = open(os.devnull, 'w')

parser = argparse.ArgumentParser()
parser.add_argument('-i', '--input-file', required=True, help='Input folder')
parser.add_argument('-o', '--out', required=True, help='Output APK name')
parser.add_argument('-f', '--fix', action='store_true', default=False, required=False, help='Fix 32bits only native libs in the APK, it can fix Java.lang.UnsatisfiedLinkError error')
parser.add_argument('-d', '--debug', action='store_true', default=False, required=False, help='Run in debug mode')
parser.add_argument('-ns', '--not-sign', action='store_false', default=False, required=False, help='Do not Sign APK. if you want to sign by yourself')
parser.add_argument('-a', '--arch', required=False, default='all', choices=['all', 'armeabi', 'armeabi-v7a', 'arm64-v8a', 'x86', 'x86_64'], help='Arch target (depends on device version)')

args = vars(parser.parse_args())

def check_smali_path(path):
    # Check if smali/ folder is present or another name (smali_classes2/3/..)
    if os.path.isfile(path):
        return path
    else:
        # Search for another smali* folder
        folders = os.listdir('unpacked/')
        smali_folders = []
        for fold in folders:
            if 'smali' in fold:
                new_path = path.replace('/smali/', '/' + fold + '/')
                if os.path.isfile(new_path):
                    return new_path
                smali_folders.append(fold)
        print_error('Couldn\'t locate the MainActivity in smali dirs')
        sys.exit()

def get_main_act(target):
    main_act = None
    # decode with apktool
    print_info('Decoding APK to read AndroidManifest (decoding resources)')
    subprocess.call(['apktool', 'd', '-o', 'temp', target])
    # parse the file and search for main activity
    print_info('Getting MainActivity from the Android Manifest')
    xmldoc = minidom.parse('temp/AndroidManifest.xml')
    activities = xmldoc.getElementsByTagName('activity')

    for act in activities:
        activity_name = act.attributes['android:name'].value
        # for each activity
        intents = act.getElementsByTagName('intent-filter')
        if len(intents):
            # if at least 1 intent
            for intent in intents:
                categs = intents[0].getElementsByTagName('category')
                for cat in categs:
                    # category example is <category android:name="android.intent.category.LAUNCHER"/>
                    if 'android.intent.category.LAUNCHER' == cat.attributes['android:name'].value:
                        # if android.intent.category.LAUNCHER means this is the main activity
                        print_ok(activity_name + ' is the LAUNCHER activity')
                        return check_smali_path('unpacked/smali/' + activity_name.replace(".", "/") + '.smali')

def inject_smali(target):
    print_info("Decoding APK")
    subprocess.call(['apktool', '-r', 'd', '-o', 'unpacked', target])
    print_debug("Reading smali file")
    main_act = get_main_act(target)
    with open(main_act, 'r') as f:
        source = f.readlines()
    # search for main
    print_debug("Looking for constructor")
    found = False
    for line in source:
        if "# direct methods" in line:
            # Generally the constructor is the first method
            print_info("Injecting smali code into " + main_act)
            # We need at least to use 1 local reg so if .local 0 we can replace with .locals 1
            # TODO: check if this is correct:
            source[source.index(line) + 2] = source[source.index(line) + 2].replace('0', '1')
            source[source.index(line) + 3] = '\n    const-string v0, "frida-gadget"\n    invoke-static {v0}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V\n'
            found = True
            break
    # write on file
    print_debug("Writing new file")
    with open(main_act, 'w') as f:
        f.writelines(source)
    if found:
        print_ok('Smali injected')
    else:
        print_error('Smali NOT injected. can\'t find the constructor')
        sys.exit()

def insert_frida_lib():
    # Create lib's folder if they don't exist .. and put frida-gadgets libs (for every arch)
    sub_folders = ['armeabi', 'arm64-v8a', 'armeabi-v7a', 'x86', 'x86_64']
    # Create lib folder if it doesn't exist..
    try:
        os.mkdir('unpacked/lib')
    except:
        print_debug('lib/ folder exists')

    if args['fix']:
        # a target app can have libs compiled in 32 bit and not in 64, and vice versa
        # if they are 32 bit and you include the frida-gadget on 64 bit's folder
        # it will search for these libs in this folder and fail (you cannot put 32 libs in 64 bit folder)
        print_info('Trying to fix UnsatisfyLink exception')
    else:
        # if you don't want to fix ...
        if args['arch'] == 'all':
            print_warning('Copying frida-gadgets in all libs .. if the app crashes try to specify more specific arch because maybe app\'s libs are not for both arch.')
            # Put libfrida into all lib's dir (for all archs)
            # you have no problems if the binary has shared libs for both 32 and 64 bit
            for folder in sub_folders:
                try:
                    os.mkdir('unpacked/lib/' + folder)
                    print_debug('unpacked/lib/' + folder + ' successfully created')
                except Exception as ez:
                    print_debug('lib/' + folder + ' already exists')
                    continue

            copyfile('res/frida-gadget-12.4.0-android-arm.so', 'unpacked/lib/armeabi/libfrida-gadget.so')
            copyfile('res/frida-gadget-12.4.0-android-arm.so', 'unpacked/lib/armeabi-v7a/libfrida-gadget.so')
            copyfile('res/frida-gadget-12.4.0-android-arm64.so', 'unpacked/lib/arm64-v8a/libfrida-gadget.so')
            copyfile('res/frida-gadget-12.4.0-android-x86.so', 'unpacked/lib/x86/libfrida-gadget.so')
            copyfile('res/frida-gadget-12.4.0-android-x86_64.so', 'unpacked/lib/x86_64/libfrida-gadget.so')
        else:
            # Use a specific arch
            # Create lib root folder
            try:
                os.mkdir('unpacked/lib/' + args['arch'] + '/')
            except:
                print_debug('folder already exists')
            # Find the right frida gadget!
            if 'arm' in args['arch']:
                if 'arm64' in args['arch']:
                    t_file = 'frida-gadget-12.4.0-android-arm64.so'
                else:
                    t_file = 'frida-gadget-12.4.0-android-arm.so'
            if 'x86' in args['arch']:
                t_file = 'frida-gadget-12.4.0-android-x86.so'
            if 'x86_64' in args['arch']:
                t_file = 'frida-gadget-12.4.0-android-x86_64.so'

            # Copy the frida-gadget file into appropriate lib
            copyfile('res/' + t_file, 'unpacked/lib/' + args['arch'] + '/libfrida-gadget.so')

def build_apk():
    # Build APK and Sign it
    subprocess.call(['apktool', 'b', '-o', 'repacked.apk', 'unpacked/'])
    print_ok('APK build Successful')

def sign_apk():
    cert_gen_cmd = 'keytool -genkey -keystore ssl.key -keyalg RSA -keysize 2048 -validity 10000 -alias sslpin -dname "cn=Unknown, ou=Unknown, o=Unknown, c=Unknown" -storepass test12 -keypass test12'
    sign_apk_cmd = 'jarsigner -sigalg SHA1withRSA -digestalg SHA1 -keystore ssl.key -storepass test12 repacked.apk sslpin'
    subprocess.call(cert_gen_cmd, shell=True)
    subprocess.call(sign_apk_cmd, shell=True)
    subprocess.call('rm ssl.key', shell=True)
    print_ok('APK signed')

set_debug(args['debug'])
# apk file in input
out_redir = target = args['input_file']

print_info('Cleaning stuff if they already exist')
subprocess.call('rm -rf temp/ ; rm -rf unpacked/ ; rm ssl.key; rm repacked.apk', shell=True, stderr=devnull, stdout=devnull)

inject_smali(target)
print_info('Inserting frida-gadgets')
insert_frida_lib()
print_ok('Frida-gadgets inserted')
print_info('Building APK ..')
build_apk()
if not args['not_sign']:
    print_info('Signing APK ...')
    sign_apk()

print_info('Using zipalign')
subprocess.call('zipalign 4 repacked.apk repacked_aligned.apk', shell=True)

print_info('Cleaning stuff .. ')
if not args['debug']:
    # if debugging do not remove temp/ and unpacked.
    subprocess.call('rm -rf temp/ ; rm -rf unpacked/', shell=True)

subprocess.call('mv repacked_aligned.apk ' + args['out'], shell=True)
devnull.close()

print_ok(''' 
░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░
░░░░░░░▄▄▀▀▀▀▀▀▀▀▀▀▄▄█▄░░░░▄░░░░█░░░░░░░
░░░░░░█▀░░░░░░░░░░░░░▀▀█▄░░░▀░░░░░░░░░▄░
░░░░▄▀░░░░░░░░░░░░░░░░░▀██░░░▄▀▀▀▄▄░░▀░░
░░▄█▀▄█▀▀▀▀▄░░░░░░▄▀▀█▄░▀█▄░░█▄░░░▀█░░░░
░▄█░▄▀░░▄▄▄░█░░░▄▀▄█▄░▀█░░█▄░░▀█░░░░█░░░
▄█░░█░░░▀▀▀░█░░▄█░▀▀▀░░█░░░█▄░░█░░░░█░░░
██░░░▀▄░░░▄█▀░░░▀▄▄▄▄▄█▀░░░▀█░░█▄░░░█░░░
██░░░░░▀▀▀░░░░░░░░░░░░░░░░░█░▄█░░░░█░░░
██░░░░░░░░░░░░░░░░░░░░░█░░░░██▀░░░░█▄░░░
██░░░░░░░░░░░░░░░░░░░░░█░░░░█░░░░░░░▀▀█▄
██░░░░░░░░░░░░░░░░░░░░█░░░░░█░░░░░░░▄▄██
░██░░░░░░░░░░░░░░░░░░▄▀░░░░░█░░░░░░░▀▀█▄
░▀█░░░░░░█░░░░░░░░░▄█▀░░░░░░█░░░░░░░▄▄██
░▄██▄░░░░░▀▀▀▄▄▄▄▀▀░░░░░░░░░█░░░░░░░▀▀█▄
░░▀▀▀▀░░░░░░░░░░░░░░░░░░░░░░█▄▄▄▄▄▄▄▄▄██
░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░
''')
