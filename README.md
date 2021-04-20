# IDA Key Checker
IDA Pro (6.x-7.x) key checker tool

## Usage

A list of available utilities can be retrieved using:

```shell
ida_key_checker --help
```

### Arguments:

| Option        | Default   | Description                                 |
| ------------- | --------- | ------------------------------------------- |
| `-i/--help`   |           | A list of available command options         |
| `-i/--input`  | `ida.key` | Input file                                  |
| `-o/--output` | `unused`  | Output (encrypted signature block) filename |
| `-t/--type`   | `key`     | Type of file (`key`, `bin` or `idb`)        |

### Sample

Sample with public leaked key

```bash
ida_key_checker -i "ida.key" -o sign

Key file: "ida.key"
Pirated Key:    0
MD5 is valid:   1

Key:
HexRays License 6.8

User            Giancarlo Russo, HT Srl
Email           g.russo@hackingteam.com
Issued On       2015-05-25 18:07:13
MD5             1A 7C 54 CF 96 02 83 23 F7 07 4C 05 5B B3 B5 05

Products
      LICENSE ID   #    SUPPORT    EXPIRES NAME
 48-3255-7514-28   1 2016-04-08      Never IDA Professional Named License (Windows)
 48-B055-7514-8E   1 2016-04-08      Never IDA Professional Named License (Mac)
 56-BC5F-5554-94   1 2016-04-08      Never ARM Decompiler (Mac)
 56-3E5F-5554-3E   1 2016-04-08      Never ARM Decompiler (Windows)
 55-BECD-8F84-AA   1 2016-04-08      Never x64 Decompiler (Mac)
 55-3CC9-8FA4-6E   1 2016-04-08      Never x64 Decompiler (Windows)
 57-3817-7E44-17   1 2016-04-08      Never x86 Decompiler (Mac)
 57-B813-7E44-DB   1 2016-04-08      Never x86 Decompiler (Windows)

Signature:
Key Number:     25143
Key Version:    680
License Type:   Named
User Number:    0
Reserved0:      -1
Reserved1:      -1
Started:        2015-05-25 19:07:13
Expires:        Never
Support Exp:    Never
License ID:     48-3255-7514-28
Username:       Giancarlo Russo, HT Srl
Version Flag:   0x07
MD5:            1A 7C 54 CF 96 02 83 23 F7 07 4C 05 5B B3 B5 05

Save signature to: "sign.bin"
Signature saved

Save decrypted signature to: "sign.decrypted"
Decrypted signature saved
```

## Libs

[bigint](https://sourceforge.net/projects/axtls/)

[md5](https://openwall.info/wiki/people/solar/software/public-domain-source-code/md5)

[cpp-base64](https://github.com/ReneNyffenegger/cpp-base64)

