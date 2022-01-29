# Introduction

This repository contains the scripts used to break https://decryption.ch.

The main scripts to use are:

* `recover.py`: recover the keystream of an alphatav container
* `decr_with_ft.py`: decrypt an alphatav container with a given keystream (generally recovered with recover.py)

We demonstrate the usage of these scripts below with the files of the challenge.

## Breaking the challenge

Note: we call in the scripts "factor table" what I called in my explanations
"keystream". This is because the first version I reversed used directly the
output of the factor table, and this stayed in the scripts.

Warning: the various scripts can take some GB of memory, because we didn't take
time to write a "streamable" decryption interface for the files. So, at some
point, decrypted+decompressed files end up in memory.

We assume that the files of the challenge are in the `chall` directory

```
$ ll chall
'Bounty_Challenge-Encryptef_Files_(Vid-Wallet)-Stage_1.atd'
'Bounty_Challenge-Encryptef_Files_(Vid-Wallet)-Stage_1.atk1'
'Bounty_Challenge-Encryptef_Files_(Vid-Wallet)-Stage_1.atk2'
'Bounty_Challenge-Encryptef_Files_(Vid-Wallet)-Stage_1.atk3'
```

Starting with a python3 environment, let's install the requirements:

```
$ pip3 install -r requirements.txt
```

Now, let's recover the keystream for the container of the challenge:

```
$ python3 ./recover.py chall/Bounty_Challenge-Encryptef_Files_\(Vid-Wallet\)-Stage_1.atd chall/ks.bin
[+] Get settings from chall/Bounty_Challenge-Encryptef_Files_(Vid-Wallet)-Stage_1.atk3...
[+] Encryption algorithm for ATD: RC2
[+] Encryption algorithm for K1: 3DES
[+] Encryption algorithm for K2: 3DES
[+] Decrypt and decompress ATD...
[+] GZip header:
00000000: 1F 8B 08 00 66 59 59 3A  00 FF 00 07 40 F8 BF EE  ....fYY:....@...
00000010: 65 4A DF 79 E0 3E 63 C6  5F 47 3B 18 70 DE E2 66  eJ.y.>c._G;.p..f
[+] Decrypt and decompress K1...
[+] GZip header:
00000000: 1F 8B 08 00 F7 59 59 3A  00 FF 00 09 40 F6 BF 1C  .....YY:....@...
00000010: 9F 69 31 DD 5F 30 94 2F  A0 62 DA E3 7E D4 E8 03  .i1._0./.b..~...
[+] Decrypt and decompress K2...
[+] GZip header:
00000000: 1F 8B 08 00 6D 59 59 3A  00 FF 34 9D 8B 61 24 B9  ....mYY:..4..a$.
00000010: AE 64 EF A8 64 40 57 92  06 28 49 1A 50 FC 18 A0  .d..d@W..(I.P...
[+] Trying with L=12300
[/] First round...
[/] Factor table recovered: 12300 bits, 12.5000 %
[/] Factor table recovered: 12764 bits, 12.9715 %
[/] Recover zeros and FF...
[/] Factor table recovered: 98400 bits, 100.0000 %
[+] Found a valid password length: 12300!
[+] Factor table recovered: 98400 bits, 100.0000 %
[+] Got full factor table!! Save it to chall/ks.bin!
```

Now that the keystream has been recovered and saved in "chall/ks.bin", let's
decrypt and extract the container:

```
$ python3 ./decr_with_ks.py chall/Bounty_Challenge-Encryptef_Files_\(Vid-Wallet\)-Stage_1.atd chall/ks.bin
[+] Get settings from 'chall/Bounty_Challenge-Encryptef_Files_(Vid-Wallet)-Stage_1.atk3'...
[+] Decrypting and decompressing streams...
[+] GZip header:
00000000: 1F 8B 08 00 4F B9 7E 5D  00 FF 34 9D 8B 61 24 B9  ....O.~]..4..a$.
00000010: AE 64 EF A8 64 40 57 92  06 28 49 1A 50 FC 18 A0  .d..d@W..(I.P...
[+] GZip header:
00000000: 1F 8B 08 00 44 B9 7E 5D  00 FF 00 07 40 F8 BF EE  ....D.~]....@...
00000010: 65 4A DF 79 E0 3E 63 C6  5F 47 3B 18 70 DE E2 66  eJ.y.>c._G;.p..f
[+] GZip header:
00000000: 1F 8B 08 00 D5 B9 7E 5D  00 FF 00 09 40 F6 BF 1C  ......~]....@...
00000010: 9F 69 31 DD 5F 30 94 2F  A0 62 DA E3 7E D4 E8 03  .i1._0./.b..~...
[+] Zip password is '1334055052224403135[...]'
[+] Writing decrypted zip in 'chall/decr.zip'...
[+] Done! Extracing zip...
[+] Zip contains: 'Alph@TaV Vault - Bounty Challenge - Encrypted BTC Wallet Files.zip'
[+] Zip contains: 'Alph@TaV Vault - Bounty Challenge - Encrypted Files - Video Instructions - PRIVATE.mp4'
[+] Zip contains: 'More Video/'
[+] Zip contains: 'More Video/Alph@TaV Vault - Bounty Challenge - BTC Wallet - First Time Load + 1 BTC Balance Verification.mp4'
[+] Zip contains: 'More Video/Alph@TaV Vault - Bounty Challenge - Encrypted Files - Video Instructions - PUBLIC.mp4'
[+] Zip contains: 'More Video/Alph@TaV Vault - Bounty Challenge - Video Final Story.mp4'
[+] Zip contains: 'More Video/Alph@TaV Vault - Bounty Challenge - Video Teaser.mp4'
[+] Zip contains: 'More Video/Alph@TaV Vault - Software PRO License Activation.mp4'
[+] Extracted with success!
```

All the files are now extracted in chall:

```
$ tree chall
chall
├── Alph@TaV Vault - Bounty Challenge - Encrypted BTC Wallet Files.zip
├── Alph@TaV Vault - Bounty Challenge - Encrypted Files - Video Instructions - PRIVATE.mp4
├── More Video
│   ├── Alph@TaV Vault - Bounty Challenge - BTC Wallet - First Time Load + 1 BTC Balance Verification.mp4
│   ├── Alph@TaV Vault - Bounty Challenge - Encrypted Files - Video Instructions - PUBLIC.mp4
│   ├── Alph@TaV Vault - Bounty Challenge - Video Final Story.mp4
│   ├── Alph@TaV Vault - Bounty Challenge - Video Teaser.mp4
│   └── Alph@TaV Vault - Software PRO License Activation.mp4
[...]
```


## Bonus: decrypt the container with the electrum wallet.

First, extract the zip file containing the aformentioned container.

```
$ mkdir chall2 && cd chall2 && unzip '../chall/Alph@TaV Vault - Bounty Challenge - Encrypted BTC Wallet Files.zip' && cd ..
```

Then, recover the keystream. Here, we are in a "complex" case where ATD and AK1
are encrypted with AES. As we can see from the output, using a partial
decompression of the gzip stream is sufficient to completely retreive the
keystream:

```
$ python3 ./recover.py chall2/Bounty\ Challenge\ BTC\ Wallet.atd chall2/ks.bin
[+] Get settings from chall2/Bounty Challenge BTC Wallet.atk3...
[+] Decrypt and decompress ATD...
[/] Stream encrypted with AES. Postponing its decryption.
[+] Decrypt and decompress K1...
[/] Stream encrypted with AES. Postponing its decryption.
[+] Decrypt and decompress K2...
[+] GZip header:
00000000: 1F 8B 08 00 B2 44 49 C1  00 FF 64 9D 0B 96 24 2D  .....DI...d...$-
00000010: 8E AC BB 32 72 01 15 0E  0B 48 07 16 10 3C 16 90  ...2r....H...<..
[+] Trying with L=1024
[-] Stream: unable to decrypt. Trying to bruteforce remaining bits...
[-] Unable to recover deflate stream!
[-] Didn't work. Decompressing what we can!
[/] Trying to decompress at index 1024...
[/] Trying to decompress at index 2048...
[...]
[/] Trying to decompress at index 131072...
[+] Partial decompressed stream can be recovered! Recovering...
[+] Recovered 36734559 bytes over 36750956 (99.9554 %)
[/] First round...
[/] unable to recover: setting a value different from what was previously known
[+] Trying with L=1100
[-] Stream: unable to decrypt. Trying to bruteforce remaining bits...
[-] Unable to recover deflate stream!
[-] Didn't work. Decompressing what we can!
[/] First round...
[/] unable to recover: setting a value different from what was previously known
[...] # Checking various password length
[+] Trying with L=13900
[-] Stream: unable to decrypt. Trying to bruteforce remaining bits...
[-] Unable to recover deflate stream!
[-] Didn't work. Decompressing what we can!
[/] First round...
[/] unable to recover: setting a value different from what was previously known
[+] Trying with L=14000
[-] Stream: unable to decrypt. Trying to bruteforce remaining bits...
[-] Unable to recover deflate stream!
[-] Didn't work. Decompressing what we can!
[/] First round...
[/] First round finished, FT not full. Status: 12.7625 %
[/] Attempt to decrypt K1...
[-] Stream: unable to decrypt. Trying to bruteforce remaining bits...
[-] Unable to recover deflate stream!
[-] Didn't work. Decompressing what we can!
[/] Trying to decompress at index 1024...
[/] Trying to decompress at index 2048...
[...]
[/] Trying to decompress at index 130048...
[/] Trying to decompress at index 131072...
[+] Partial decompressed stream can be recovered! Recovering...
[+] Recovered 4577474 bytes over 4593870 (99.6431 %)
[+] New stream decrypted!
[/] Going for another round!
[/] Recover zeros and FF...
112000 100.0
[+] Found a valid password length: 14000!
[+] Factor table recovered: 112000 bytes, 100.0000 %
[+] Got full factor table!! Save it to chall2/ks.bin!
```

Same as above, now that we have the full keystream, let's decrypt and decompress this container:

```
$ python3 ./decr_with_ft.py chall2/Bounty\ Challenge\ BTC\ Wallet.atd chall2/ks.bin
[+] Get settings from 'chall2/Bounty Challenge BTC Wallet.atk3'...
[+] Decrypting and decompressing streams...
[+] GZip header:
00000000: 1F 8B 08 00 39 0D 7B 5D  00 FF 64 9D 0B 96 24 2D  ....9.{]..d...$-
00000010: 8E AC BB 32 72 01 15 0E  0B 48 07 16 10 3C 16 90  ...2r....H...<..
[+] GZip header:
00000000: 1F 8B 08 00 34 0D 7B 5D  00 FF 00 0D 40 F2 BF 9D  ....4.{]....@...
00000010: A6 F6 28 D0 49 32 98 DD  05 97 B8 08 73 1F DA A9  ..(.I2......s...
[+] GZip header:
00000000: 1F 8B 08 00 57 0D 7B 5D  00 FF 00 0C 40 F3 BF 6D  ....W.{]....@..m
00000010: CC D5 C6 71 C9 32 B4 F7  73 DE CC B7 9D E0 75 43  ...q.2..s.....uC
[+] Zip password is '1330236147731631503[...]'
[+] Writing decrypted zip in 'chall2/decr.zip'...
[+] Done! Extracing zip...
[+] Zip contains: 'AppData/'
[+] Zip contains: 'AppData/Roaming/'
[+] Zip contains: 'AppData/Roaming/Electrum/'
[+] Zip contains: 'AppData/Roaming/Electrum/wallets/'
[+] Zip contains: 'AppData/Roaming/Electrum/wallets/alphatav_vault_bounty_challenge_btc_wallet'
[+] Zip contains: 'electrum-3.3.8.exe'
[+] Extracted with success!
```

And here are the files:

```
$ tree chall2
chall2
├── AppData
│   └── Roaming
│       └── Electrum
│           └── wallets
│               └── alphatav_vault_bounty_challenge_btc_wallet
├── electrum-3.3.8.exe
[...]
```
