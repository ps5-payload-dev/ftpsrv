# ftpsrv
This is a simple FTP server that can be executed on a Playstation 4 or
Playstation 5 that has been jailbroken and is running an ELF loader.

## Features
Client software that has been testing include gFTP, Filezilla, curl, and Thunar.
The payload supports a couple of custom SITE commands specifically for the
PS4 and PS5 (executed without prepending SITE). In particular:
 - KILL - kill the FTP server.
 - MTRW - remount /system and /system_ex with write permissions.

## Building for the PS4
Assuming you have the [ps4-payload-sdk][sdk-ps4] installed on a POSIX machine,
the FTP server can be compiled using the following two commands:
```console
john@localhost:ftpsrv$ export PS4_PAYLOAD_SDK=/opt/ps4-payload-sdk
john@localhost:ftpsrv$ make
```

## Building for the PS5
Assuming you have the [ps5-payload-sdk][sdk-ps5] installed on a POSIX machine,
the FTP server can be compiled using the following two commands:
```console
john@localhost:ftpsrv$ export PS5_PAYLOAD_SDK=/opt/ps5-payload-sdk
john@localhost:ftpsrv$ make
```

## Reporting Bugs
If you encounter problems with ftpsrv, please [file a github issue][issues].
If you plan on sending pull requests which affect more than a few lines of code,
please file an issue before you start to work on you changes. This will allow us
to discuss the solution properly before you commit time and effort.

## License
ftpsrv is licensed under the GPLv3+.

[sdk-ps4]: https://github.com/ps4-payload-dev/sdk
[sdk-ps5]: https://github.com/ps5-payload-dev/sdk
[issues]: https://github.com/ps5-payload-dev/ftpsrv/issues/new
