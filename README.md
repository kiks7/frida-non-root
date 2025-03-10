# frida-non-root
## Whait is it
Just automate the process of injecting the frida-gadgets library into APKs to use Frida with non-rooted Android Devices.
(you can also do it manually following this precious guide https://koz.io/using-frida-on-android-without-root/).

Frida-gadgets are called at the startup of the app and will listen on port 27042. After patched and installed the APK, you can use frida -U Gadget (over USB) to instrument your application.

## What it does:
- Decode the APK and locate the Main Activity reading the AndroidManifest.xml
- Add frida-gadgets-[arch].so into libs folder
- Inject smali code into the Main Activity
- Rebuild APK, zipalign and sign.

## Reqs:
- python
- apktool
- keytool
- zipalign & apksigner (part of the Android SDK)
- \*nix (Native commands like ['mv','rm'] are used, sorry for Windows users [just fire up a VM || docker || what else]) :}}}

## Install/Usage:

```bash
git clone https://github.com/kiks7/frida-non-root.git
chmod +x main.py
./main.py --help
./main.py -i <input APK> -o <output NAME>
```
