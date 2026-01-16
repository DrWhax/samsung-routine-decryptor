# samsung-routine-decryptor
Decrypt Samsung Routines and Actions 

An Samsung Routine and Actions file has .rtn as ending, it's basically a zip.

In the zip an routine_0 file can be found, it consists of two pieces of json and a mysterious body. that's aes-gcm encrypted.

When an Samsung routine's (v2) is shared, part of it is encrypted with the APK's certificate key. It's derived as follows:

```
keytool -printcert -jarfile "com.samsung.android.app.routines_4.8.07.1-480701000_minAPI34(arm64-v8a,armeabi-v7a)(nodpi)_apkmirror.com.apk" -rfc \
| python3 -c "import sys,base64,re; d=sys.stdin.read(); m=re.search('-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----', d, re.S); b=base64.b64decode(''.join(m.group(1).split())); print(b.hex()[:32])"
The certificate uses the SHA1withRSA signature algorithm which is considered a security risk.
308204d4308203bca003020102020900
```

In order to decrypt:

```
python3 -m venv venv
source venv/bin/activate
pip install pycryptodome (or cryptography)

decode_routine0.py routine_0 --key 308204d4308203bca003020102020900 --print

{"version":"1.0.0","name":"In the dark","icon":23,"icon_color":-9581698,"is_recovery_off":false,"conditions":[{"package":"com.samsung.android.app.routines","tag":"time_v3","label":"Time period","instance_extra":""}],"actions":[{"package":"com.samsung.android.app.routines","tag":"dark_mode_v3","label":"Dark mode","intent_param":[{"KEY":"enable_dark_mode","TYPE":"STRING","VALUE":"2"}],"instance_extra":"ORDERING_INDEX&0"},{"package":"com.android.settings","tag":"sec_eye_comfort_shield_routine","label":"Eye comfort shield","intent_param":[{"KEY":"blue_light_filter_switch","TYPE":"NUMBER","VALUE":"1.0"},{"KEY":"blue_light_filter_scheduled","TYPE":"NUMBER","VALUE":"0.0"},{"KEY":"blue_light_filter_opacity","TYPE":"NUMBER","VALUE":"5.0"},{"KEY":"blue_light_filter_type","TYPE":"NUMBER","VALUE":"0.0"},{"KEY":"blue_light_filter_adaptive_mode","TYPE":"NUMBER","VALUE":"1.0"}],"instance_extra":"ORDERING_INDEX&0"},{"package":"com.android.settings","tag":"accessibility_extra_dim","label":"Extra dim","intent_param":[{"KEY":"intensity","TYPE":"NUMBER","VALUE":"80.0"},{"KEY":"switch","TYPE":"BOOLEAN","VALUE":"true"}],"instance_extra":"ORDERING_INDEX&0"}],"attributes":{},"tag":"preset_in_the_dark"}
```

## FAQ

Yes, this was vibe-coded.
