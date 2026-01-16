# ftpsrv
This is a simple FTP server that can be executed on a Playstation 4 or
Playstation 5 that has been jailbroken and is running an ELF loader.
The FTP server accepts connection on port 2121.

## Features
Client software that has been tested include gFTP, Filezilla, curl, and Thunar.
The payload supports a couple of custom SITE commands specifically for the
PS4 and PS5 (executed without prepending SITE). In particular:
 - KILL - kill the FTP server.
 - MTRW - remount /system and /system_ex with write permissions.
 - SELF - toggle on-the-fly SELF to ELF decryption (enabled by default).
 - SCHK - toggle SELF digest verification.

Note: the SELF command operates on induvidual connections so use e.g.,
```console
john@localhost:ftpsrv$ curl -o libkernel.sprx -Q SELF ftp://ps5:2121/system/common/lib/libkernel.sprx
```

## Additional commands
These commands are implemented but were not previously documented here:
 - DSIZ <path> - report recursive directory size (errors if path is a file).
 - RMDA <dir> - delete a directory tree (alias: SITE RMDIR).
 - AVBL <path> - available space in bytes for the given path.
 - XQUOTA - report file count/limits and disk usage/limits.
 - SITE CHMOD <mode> <path> - change permissions.
 - SITE UMASK [mode] - get/set file creation mask.
 - SITE SYMLINK <target> <link> - create a symlink.
 - SITE CPFR <from> / SITE CPTO <to> - server-side copy (asynchronous).
 - SITE COPY <from> <to> - server-side copy (asynchronous).

Note: the copy commands return immediately with "250 Copy started in background";
errors during the background copy are not reported to the client.

Some clients (e.g. WinSCP) can be configured to use these extra commands
for file management operations.

## Building for the PS4
Assuming you have the [ps4-payload-sdk][sdk-ps4] installed on a POSIX machine,
the FTP server can be compiled using the following two commands:
```console
john@localhost:ftpsrv$ export PS4_PAYLOAD_SDK=/opt/ps4-payload-sdk
john@localhost:ftpsrv$ make -f Makefile.ps4
```

## Building for the PS5
Assuming you have the [ps5-payload-sdk][sdk-ps5] installed on a POSIX machine,
the FTP server can be compiled using the following two commands:
```console
john@localhost:ftpsrv$ export PS5_PAYLOAD_SDK=/opt/ps5-payload-sdk
john@localhost:ftpsrv$ make -f Makefile.ps5
```

## Building for GNU/Linux systems
Assuming you have a compiler toolchain installed on your GNU/Linux system,
the FTP server can be compiled using the following command:
```console
john@localhost:ftpsrv$ make -f Makefile.posix
```

## Known issues
Some PS5 firmwares below vesion 4 contains a kernel bug where reading from some SELF
files causes the read syscall to stall.

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
