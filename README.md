# ps5-payload-ftpsrv
This is a simple FTP server that can be executed on a Playstation 5 that has
been jailbroken via the [BD-J][bdj] or the [webkit][webkit] entry points.

## Quick-start
To deploy ps5-payload-ftpsrv, first make sure [ps5-payload-elfldr][elfldr] is
running, then load the payload as follows:

```console
john@localhost:~$ export PS5_HOST=ps5
john@localhost:~$ wget -q -O - https://github.com/ps5-payload-dev/ftpsrv/releases/download/v0.11/Payload.zip | gunzip -c -d | nc -q0 $PS5_HOST 9021
```

## Features
Client software that has been testing include gFTP, Filezilla, curl, and Thunar.
Furthermore, the payload supports a couple of custom SITE commands specifically
for the PS5 (executed without prepending SITE). In particular:
 - KILL - kill the FTP server.
 - MTRW - remount /system and /system_ex with write permissions.

## Building
Assuming you have the [ps5-payload-sdk][sdk] installed on a POSIX machine,
the FTP server can be compiled using the following two commands:
```console
john@localhost:ps5-payload-dev/ftpsrv$ export PS5_PAYLOAD_SDK=/opt/ps5-payload-sdk
john@localhost:ps5-payload-dev/ftpsrv$ make
```

## Reporting Bugs
If you encounter problems with ps5-payload-ftpsrv, please [file a github issue][issues].
If you plan on sending pull requests which affect more than a few lines of code,
please file an issue before you start to work on you changes. This will allow us
to discuss the solution properly before you commit time and effort.

## License
ps5-payload-ftpsrv is licensed under the GPLv3+.

[bdj]: https://github.com/john-tornblom/bdj-sdk
[sdk]: https://github.com/ps5-payload-dev/sdk
[webkit]: https://github.com/Cryptogenic/PS5-IPV6-Kernel-Exploit
[elfldr]: https://github.com/ps5-payload-dev/elfldr
[issues]: https://github.com/ps5-payload-dev/ftpsrv/issues/new
