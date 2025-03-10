#!/bin/sh
if [ "$#" -ne 2 ]; then
	echo "Fast build an APK"
	echo
	echo "Usage: $0 <decodedFolder> <outputAPK>"
else
	echo '[*] Cleaning stuff'
	rm ssl.key
	echo '[*] Building '$1
	apktool b -o $2 $1
	echo '[*] Generating certiciate'

	keytool -genkey -keystore ssl.key -keyalg RSA -keysize 2048 -validity 10000 -alias sslpin -dname "cn=Unknown, ou=Unknown, o=Unknown, c=Unknown" -storepass test12 -keypass test12
	echo '[*] Signing .. '

	jarsigner -sigalg SHA1withRSA -digestalg SHA1 -keystore ssl.key -storepass test12 $2 sslpin

	jarsigner --verify $2
	rm ssl.key
	echo '[+] Done'
fi
