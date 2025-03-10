#!/usr/bin/env python
import sys
from imports.logger import *
import argparse
import subprocess
import re
from shutil import copyfile
import os
from xml.dom import minidom
import time
import shutil

devnull = open(os.devnull, 'w')

parser = argparse.ArgumentParser()
parser.add_argument('-i', '--input-file',required=True,help='APK')
parser.add_argument('-o', '--out',required=True,help='Output APK name')
parser.add_argument('-d', '--debug', action='store_true' ,default=False, required=False, help='debug mode')
parser.add_argument('-ns', '--not-sign', action='store_true', default=False, required=False, help='Do not sign APK (if you want to sign by yourself)')
parser.add_argument('-t', '--target-method',required=False,help='Specify a specific class and method (format class:method). Default is the LAUNCHER activity')
parser.add_argument('-g', '--frida-gadget-version',required=False,help='The base filename of the frida gadgets to insert (e.g. res/frida-gadget-16.3.3-android-). Default is res/frida-gadget-16.3.3-android-', default='res/frida-gadget-16.3.3-android-')
parser.add_argument('-a', '--arch',required=False,default='all',choices= ['all','armeabi','armeabi-v7a','arm64-v8a','x86','x86_64'],help='Arch target (depends on device version)')

args = vars(parser.parse_args())

def write_lines_after_keyword(filename, keyword, lines_to_write):
    with open(filename, 'r') as file:
        lines = file.readlines()
    index = None
    for i, line in enumerate(lines):
        if keyword in line:
            index = i
            break
    lines_to_insert = lines_to_write + ['\n']
    lines[index+1:index+1] = lines_to_insert

    with open(filename, 'w') as file:
        file.writelines(lines)

def check_smali_path(path):
    # Check if smali/ folder is present or another name (smali_classes2/3/..)
    if os.path.isfile(path):
        return path
    else:
        # Search for another smali* fodler  
        folders = os.listdir('unpacked/')
        smali_folders = []
        for fold in folders:
            if 'smali' in fold:
                new_path = path.replace('/smali/','/'+fold+'/')
                if os.path.isfile(new_path):
                    return new_path
                smali_folders.append(fold)  
        print_error('Failed to locate the target method in smalis dirs')   
        return False
    
def get_main_act(target):
    main_act = None
    # parse th file and search for main activity
    print_info('Getting MainActivity from the Android Manifest')
    xmldoc = minidom.parse('temp/AndroidManifest.xml')
    activities = xmldoc.getElementsByTagName('activity')

    # Search for the android.intent.category.LAUNCHER cateogory
    for act in activities:
        # for each activity
        activity_name = act.attributes['android:name'].value
        intents = act.getElementsByTagName('intent-filter')
        if len(intents):
             # if there is at least 1 intent
             for intent in intents:
                categs = intent.getElementsByTagName('category')
                for cat in categs:
                    # <category android:name="android.intent.category.LAUNCHER"/>
                    if cat.attributes['android:name'].value == "android.intent.category.LAUNCHER":
                        print_ok(activity_name + ' is the LAUNCHER activity')
                        return check_smali_path('unpacked/smali/' + activity_name.replace(".", "/") + '.smali')


def inject_smali(target, target_class_filename, target_method):
    print_debug("Reading smali file")
    print_info("Target class (filename): {}".format(target_class_filename))
    print_info("Target method: {}".format(target_method))
    with open(target_class_filename, 'r') as f:
        source = f.readlines()
    print_debug("Looking for the target method ..")
    found = False
    # We want to search for lines that contains:
    # - .method <SOMETHING> target_method(<ARGS)
    target_method_search = target_method + "("

    for line in source:
        if line.startswith(".method "):
            if target_method_search in line:
                print_debug("Method found in smali")
                found = True
                # We need at least to use 1 local regs so if .local 0 we can replace with .locals 1 
                source[source.index(line)+2] = source[source.index(line)+2].replace('0','1')    
                source[source.index(line)+3] = '\n    const-string v0, "frida-gadget"\n    invoke-static {v0}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V\n' + source[source.index(line)+3]
                break

    if found:
        with open(target_class_filename, 'w') as f:
             f.writelines(source)
        print_ok('Smali injected')
        return True
    else:
        return False

def insert_frida_lib(frida_gadget_base_filename):
    # Create lib's folder if they dont exist .. and put frida-gadgets libs (for every arch)
    sub_folders = ['armeabi','arm64-v8a','armeabi-v7a','x86','x86_64']
    # Create lib folder if it doesnt exist..
    try:
        os.mkdir('unpacked/lib')
    except:
        print_debug('lib/ folder exists')

    if args['arch'] == 'all':
        print_warning('Copying frida-gadgets in all libs .. if targeted app crashes then try to be more specific')
        # Put libfrida into all lib's dir (for all archs)
        # you have no problems if the binary has shared libs for both 32 and 64 bit
        for folder in sub_folders:
            try:
                os.mkdir('unpacked/lib/'+folder)
                print_debug('unpacked/lib/'+folder+' succesfully created')
            except Exception as ez:
                print_debug('lib/'+folder+' already exists')
                continue

        copyfile('{}-arm.so'.format(frida_gadget_base_filename),'unpacked/lib//armeabi/libfrida-gadget.so')
        copyfile('{}-arm.so'.format(frida_gadget_base_filename),'unpacked/lib/armeabi-v7a/libfrida-gadget.so')
        copyfile('{}-arm64.so'.format(frida_gadget_base_filename),'unpacked/lib/arm64-v8a/libfrida-gadget.so')
        copyfile('{}-x86.so'.format(frida_gadget_base_filename),'unpacked/lib/x86/libfrida-gadget.so')
        copyfile('{}-x86_64.so'.format(frida_gadget_base_filename),'unpacked/lib/x86_64/libfrida-gadget.so')
    else: 
        # Use a specific arch
        # Create lib root folder
        try:
            os.mkdir('unpacked/lib/'+args['arch']+'/')
        except:
            print_debug('folder already exist')

        # Find the right frida gadget !
        t_arch = args["arch"]
        if t_arch == "arm64-v8a":
            t_arch = "arm64"
        t_file = frida_gadget_base_filename + t_arch + ".so"
        # Copy the frida-gadget file into appropriate lib
        copyfile(t_file, 'unpacked/lib/'+args['arch']+'/libfrida-gadget.so')

def build_apk():
    # Build APK

    # Do not compress frida-gadgets library !
    lines = [
            "- lib/armeabi/libfrida-gadget.so\n",
            "- lib/armeabi-v7a/libfrida-gadget.so\n",
            "- lib/arm64-v8a/libfrida-gadget.so\n",
            "- lib/x86/libfrida-gadget.so\n",
            "- lib/x86_64/libfrida-gadget.so"
            ]

    write_lines_after_keyword("unpacked/apktool.yml", "doNotCompress", lines)
    subprocess.call(['apktool','b','-o','repacked.apk', 'unpacked/'],)
    print_ok('APK build Successfull')

def sign_apk(filename, filename_out):
    cert_gen_cmd = 'keytool -genkey -keystore working/certificate.key -keyalg RSA -keysize 2048 -validity 10000 -alias sslpin -dname "cn=Unknown, ou=Unknown, o=Unknown, c=Unknown" -storepass test12 -keypass test12'
    sign_apk_cmd = 'echo test12 | apksigner sign --ks working/certificate.key --v1-signing-enabled true --v2-signing-enabled true --out {} {}'.format(filename_out, filename)
    subprocess.call(cert_gen_cmd, shell=True)
    subprocess.call(sign_apk_cmd, shell=True)
    print_ok('APK signed')

def verify_dependencies():
    # Windows not supported
    if os.name == "nt":
        print_warning("Windows not supported. Use a VM or docker")
        return False

    tools = [
            "apktool",
            "zipalign",
            "keytool",
            "apksigner",
            ]

    for tool in tools:
        try:
            subprocess.check_output("which {}".format(tool), shell=True, stderr=subprocess.PIPE)
        except subprocess.CalledProcessError as e:
            print("{} is required. Required tools:".format(tool))
            for tool in tools:
                print("\t- {}".format(tool))
            return False
    return True

def clean_directory():
    try:
        shutil.rmtree("temp/")
    except FileNotFoundError:
        pass
    try:
        shutil.rmtree("unpacked/")
    except FileNotFoundError:
        pass
    try:
        os.remove("working/certificate.key")
    except FileNotFoundError:
        pass
    try:
        os.remove("repacked.apk")
    except FileNotFoundError:
        pass
    try:
        os.remove("repacked_aligned.apk")
    except FileNotFoundError:
        pass
    try:
        os.remove("repacked_aligned.apk")
    except FileNotFoundError:
        pass
    try:
        os.remove("repacked_signed.apk.idsig")
    except FileNotFoundError:
        pass


if __name__ == "__main__":
    set_debug(args['debug'])
    # apk file in inout
    target = args['input_file']
    if not verify_dependencies():
        print_error("Depenencies failed")
        sys.exit()

    print_info('Cleaning stuff if they already exists')
    clean_directory()

    print_info('Decoding APK to read AndroidManifest (decoding resources)')
    subprocess.call(['apktool','d','-o','temp', target])

    # Needed to avoid further issues on re-packaging
    print_info("Decoding APK without decoding resources")
    subprocess.call(['apktool', '-r', 'd', '-o', 'unpacked', target])


    arg_target_class_method = args["target_method"]
    if arg_target_class_method:
        print_info("Target class and method: {}".format(arg_target_class_method))
        try:
            arg_target_class = arg_target_class_method.split(":")[0]
            target_method = arg_target_class_method.split(":")[1]
        except IndexError:
            print_error("Target class in bad format. CLASS:METHOD")
            sys.exit()
        target_class = check_smali_path('unpacked/smali/' + arg_target_class.replace(".", "/") + '.smali')
    else:
        target_class = get_main_act(target)
        target_method = "onCreate"

    if not target_class:
        print_error("Could not find the {} method".format(target_class))
        sys.exit()

    if not inject_smali(target, target_class, target_method):
        print_error("Failed to inject smail, method not found.")
        sys.exit()

    print_info('Inserting frida-gadgets')
    insert_frida_lib(args["frida_gadget_version"])
    print_info('Building APK ..')
    build_apk()

    if not args['not_sign']:
        print_info('Using zipalign')
        subprocess.call('zipalign -f -p 4 repacked.apk repacked_aligned.apk', shell=True)
        print_info('Signing APK ...')
        sign_apk("repacked_aligned.apk", "repacked_signed.apk")
        os.rename("repacked_signed.apk", args["out"])
    else:
        os.rename("repacked.apk", args["out"])

    print_info('Cleaning stuff .. ')
    if not args['debug']:
        # if debugging do not remove temp/ and unpacked. oldo ye
        clean_directory()

    devnull.close()
    print_ok("Done")
