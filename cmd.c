/* Copyright (C) 2023 John Törnblom

This program is free software; you can redistribute it and/or modify it
under the terms of the GNU General Public License as published by the
Free Software Foundation; either version 3, or (at your option) any
later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; see the file COPYING. If not, see
<http://www.gnu.org/licenses/>.  */

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <netinet/in.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#ifdef __FreeBSD__
#include <sys/_iovec.h>
#include <sys/mount.h>
#endif

#include "cmd.h"


/**
 * Create a string representation of a file mode.
 **/
static void
ftp_mode_string(mode_t mode, char *buf) {
  char c, d;
  int i, bit;

  buf[10] = 0;
  for(i=0; i<9; i++) {
    bit = mode & (1<<i);
    c = i%3;
    if(!c && (mode & (1<<((d=i/3)+9)))) {
      c = "tss"[(int)d];
      if (!bit) c &= ~0x20;
    } else c = bit ? "xwr"[(int)c] : '-';
    buf[9-i] = c;
  }

  if (S_ISDIR(mode)) c = 'd';
  else if (S_ISBLK(mode)) c = 'b';
  else if (S_ISCHR(mode)) c = 'c';
  else if (S_ISLNK(mode)) c = 'l';
  else if (S_ISFIFO(mode)) c = 'p';
  else if (S_ISSOCK(mode)) c = 's';
  else c = '-';
  *buf = c;
}


/**
 * Open a new PASSV FTP data connection.
 **/
static int
ftp_data_open(ftp_env_t *env) {
  struct sockaddr_in data_addr;
  socklen_t addr_len;

  if((env->data_fd=accept(env->passive_fd, (struct sockaddr*)&data_addr,
			  &addr_len)) < 0) {
    return -1;
  }

  return 0;
}


/**
 * Transmit a formatted string via an existing data connection.
 **/
static int
ftp_data_printf(ftp_env_t *env, const char *fmt, ...) {
  char buf[0x1000];
  size_t len = 0;
  va_list args;

  va_start(args, fmt);
  vsnprintf(buf, sizeof(buf), fmt, args);
  va_end(args);

  len = strlen(buf);
  if(write(env->data_fd, buf, len) != len) {
    return -1;
  }

  return 0;
}


/**
 * Read data from an existing data connection.
 **/
static int
ftp_data_read(ftp_env_t *env, void *buf, size_t count) {
  return recv(env->data_fd, buf, count, 0);
}


/**
 * Transmit data on an existing data connection.
 **/
static int
ftp_data_send(ftp_env_t *env, void *buf, size_t count) {
  return send(env->data_fd, buf, count, 0);
}


/**
 * Close an existing data connection.
 **/
static int
ftp_data_close(ftp_env_t *env) {
  if(!close(env->data_fd) && !close(env->passive_fd)) {
    return 0;
  }
  return -1;
}


/**
 * Transmit a formatted string via an active connection.
 **/
static int
ftp_active_printf(ftp_env_t *env, const char *fmt, ...) {
  char buf[0x1000];
  size_t len = 0;
  va_list args;

  va_start(args, fmt);
  vsnprintf(buf, sizeof(buf), fmt, args);
  va_end(args);

  len = strlen(buf);

  if(write(env->active_fd, buf, len) != len) {
    return -1;
  }

  return 0;
}


/**
 * Transmit an errno string via an active connection.
 **/
static int
ftp_perror(ftp_env_t *env) {
  char buf[255];

  if(strerror_r(errno, buf, sizeof(buf))) {
    strncpy(buf, "Unknown error", sizeof(buf));
  }

  return ftp_active_printf(env, "550 %s\r\n", buf);
}


/**
 *
 **/
static void
ftp_abspath(ftp_env_t *env, char *abspath, const char *path) {
  char buf[PATH_MAX+1];

  if(path[0] != '/') {
    snprintf(buf, sizeof(buf), "%s/%s", env->cwd, path);
    strncpy(abspath, buf, PATH_MAX);
  } else {
    strncpy(abspath, path, PATH_MAX);
  }
}


/**
 *
 **/
int
ftp_cmd_CWD(ftp_env_t *env, const char* arg) {
  char pathbuf[PATH_MAX];
  struct stat st;

  if(!arg[0]) {
    return ftp_active_printf(env, "501 Usage: CWD <PATH>\r\n");
  }

  ftp_abspath(env, pathbuf, arg);
  if(stat(pathbuf, &st)) {
    return ftp_perror(env);
  }

  if(!S_ISDIR(st.st_mode)) {
    return ftp_active_printf(env, "550 No such directory\r\n");
  }

  snprintf(env->cwd, sizeof(env->cwd), "%s", pathbuf);

  return ftp_active_printf(env, "250 OK\r\n");
}


/**
 *
 **/
int
ftp_cmd_LIST(ftp_env_t *env, const char* arg) {
  char pathbuf[PATH_MAX+256+2];
  struct dirent *ent;
  const char *p = env->cwd;
  struct stat statbuf;
  char timebuf[20];
  char modebuf[20];
  struct tm * tm;
  DIR *dir;

  if(arg[0] && arg[0] != '-') {
    p = arg;
  }

  if(!(dir=opendir(p))) {
    return ftp_perror(env);
  }

  if(ftp_data_open(env)) {
    return ftp_perror(env);
  }

  ftp_active_printf(env, "150 Opening data transfer\r\n");

  while((ent=readdir(dir))) {
    if(p[0] == '/') {
      snprintf(pathbuf, sizeof(pathbuf), "%s/%s", p, ent->d_name);
    } else {
      snprintf(pathbuf, sizeof(pathbuf), "/%s/%s/%s", env->cwd, p,
	       ent->d_name);
    }

    if(stat(pathbuf, &statbuf) != 0) {
      continue;
    }

    ftp_mode_string(statbuf.st_mode, modebuf);
    tm = localtime((const time_t *)&(statbuf.st_ctim)); // TODO: not threadsafe
    strftime(timebuf, sizeof(timebuf), "%b %d %H:%M", tm);

    ftp_data_printf(env, "%s %lu %lu %lu %llu %s %s\r\n", modebuf,
		    statbuf.st_nlink, statbuf.st_uid, statbuf.st_gid,
		    statbuf.st_size, timebuf, ent->d_name);
  }

  if(ftp_data_close(env)) {
    int ret = ftp_perror(env);
    closedir(dir);
    return ret;
  }

  if(closedir(dir)) {
    return ftp_perror(env);
  }

  return ftp_active_printf(env, "226 Transfer complete\r\n");
}


/**
 * Enter passive mode.
 **/
int
ftp_cmd_PASV(ftp_env_t *env, const char* arg) {
  socklen_t sockaddr_len = sizeof(struct sockaddr_in);
  struct sockaddr_in sockaddr;
  uint32_t addr = 0;
  uint16_t port = 0;

  if(getsockname(env->active_fd, (struct sockaddr*)&sockaddr, &sockaddr_len)) {
    return ftp_perror(env);
  }
  addr = sockaddr.sin_addr.s_addr;

  if(env->passive_fd > 0) {
    close(env->passive_fd);
  }

  if((env->passive_fd=socket(AF_INET, SOCK_STREAM, 0)) < 0) {
    return ftp_perror(env);
  }

  memset(&sockaddr, 0, sockaddr_len);
  sockaddr.sin_family = AF_INET;
  sockaddr.sin_addr.s_addr = htonl(INADDR_ANY);
  sockaddr.sin_port = htons(0);

  if(bind(env->passive_fd, (struct sockaddr*)&sockaddr, sockaddr_len) != 0) {
    int ret = ftp_perror(env);
    close(env->passive_fd);
    return ret;
  }

  if(listen(env->passive_fd, 5) != 0) {
    int ret = ftp_perror(env);
    close(env->passive_fd);
    return ret;
  }

  if(getsockname(env->passive_fd, (struct sockaddr*)&sockaddr, &sockaddr_len)) {
    int ret = ftp_perror(env);
    close(env->passive_fd);
    return ret;
  }
  port = sockaddr.sin_port;

  return ftp_active_printf(env, "227 Entering Passive Mode (%hhu,%hhu,%hhu,%hhu,%hhu,%hhu).\r\n",
			   (addr >> 0) & 0xFF,
			   (addr >> 8) & 0xFF,
			   (addr >> 16) & 0xFF,
			   (addr >> 24) & 0xFF,
			   (port >> 0) & 0xFF,
			   (port >> 8) & 0xFF);
}


/**
 * Retreive data from a given file.
 **/
int
ftp_cmd_RETR(ftp_env_t *env, const char* arg) {
  char pathbuf[PATH_MAX];
  char buf[0x4000];
  struct stat st;
  size_t len;
  int fd;

  if(!arg[0]) {
    return ftp_active_printf(env, "501 Usage: RETR <PATH>\r\n");
  }

  ftp_abspath(env, pathbuf, arg);
  if(stat(pathbuf, &st)) {
    return ftp_perror(env);
  }

  if(!S_ISREG(st.st_mode)) {
    return ftp_active_printf(env, "550 Not a regular file\r\n");
  }

  if((fd=open(pathbuf, O_RDONLY, 0)) < 0) {
    return ftp_active_printf(env, "550 %s\r\n", strerror(errno));
  }

  if(ftp_active_printf(env, "150 Opening data transfer\r\n")) {
    return ftp_perror(env);
  }

  if(ftp_data_open(env)) {
    return ftp_perror(env);
  }

  if(lseek(fd, env->data_offset, SEEK_SET) == -1) {
    int ret = ftp_perror(env);
    close(fd);
    return ret;
  }

  while((len=read(fd, buf, sizeof(buf)))) {
    if(ftp_data_send(env, buf, len) != len) {
      int ret = ftp_perror(env);
      close(fd);
      return ret;
    }
  }

  close(fd);

  if(ftp_data_close(env)) {
    return ftp_perror(env);
  }

  return ftp_active_printf(env, "226 Transfer completed\r\n");
}



/**
 * Obtain the size of a given file.
 **/
int
ftp_cmd_SIZE(ftp_env_t *env, const char* arg) {
  struct stat st;

  if(!arg[0]) {
    return ftp_active_printf(env, "501 Usage: SIZE <FILENAME>\r\n");
  }

  if(stat(arg, &st)) {
    return ftp_perror(env);
  }

  return ftp_active_printf(env, "213 %"  PRIu64 "\r\n", st.st_size);
}


/**
 * Store recieved data in a given file.
 **/
int
ftp_cmd_STOR(ftp_env_t *env, const char* arg) {
  uint8_t readbuf[0x4000];
  char pathbuf[PATH_MAX];
  size_t len;
  int fd;

  if(!arg[0]) {
    return ftp_active_printf(env, "501 Usage: STOR <FILENAME>\r\n");
  }

  ftp_abspath(env, pathbuf, arg);
  if((fd=open(pathbuf, O_CREAT | O_WRONLY | O_TRUNC, 0777)) < 0) {
    return ftp_perror(env);
  }

  if(ftp_active_printf(env, "150 Opening data transfer\r\n")) {
    close(fd);
    return -1;
  }

  if(ftp_data_open(env)) {
    int ret = ftp_perror(env);
    close(fd);
    return ret;
  }

  while((len=ftp_data_read(env, readbuf, sizeof(readbuf)))) {
    if(write(fd, readbuf, len) != len) {
      int ret = ftp_perror(env);
      ftp_data_close(env);
      close(fd);
      return ret;
    }
  }

  close(fd);

  if(ftp_data_close(env)) {
    return ftp_perror(env);
  }

  return ftp_active_printf(env, "226 Data transfer complete\r\n");
}


/**
 * Print working directory.
 **/
int
ftp_cmd_PWD(ftp_env_t *env, const char* arg) {
  return ftp_active_printf(env, "257 \"%s\"\r\n", env->cwd);
}


/**
 * Disconnect user.
 **/
int
ftp_cmd_QUIT(ftp_env_t *env, const char* arg) {
  ftp_active_printf(env, "221 Goodbye\r\n");
  return -1;
}


/**
 * Return system type.
 **/
int
ftp_cmd_SYST(ftp_env_t *env, const char* arg) {
  return ftp_active_printf(env, "215 UNIX Type: L8\r\n");
}


/**
 * Sets the transfer mode (ASCII or Binary).
 **/
int
ftp_cmd_TYPE(ftp_env_t *env, const char* arg) {
  switch(arg[0]) {
  case 'A':
  case 'I':
    env->type = arg[0];
    return ftp_active_printf(env, "200 Type set to %c\r\n", env->type);
  }

  return ftp_active_printf(env, "501 Invalid argument to TYPE\r\n");
}


/**
 * Authenticate user.
 **/
int
ftp_cmd_USER(ftp_env_t *env, const char* arg) {
  return ftp_active_printf(env, "230 User logged in\r\n");
}


/**
 * Unsupported command.
 **/
int
ftp_cmd_NA(ftp_env_t *env, const char* arg) {
  return ftp_active_printf(env, "502 Command not implemented\r\n");
}


/**
 * No operation.
 **/
int
ftp_cmd_NOOP(ftp_env_t *env, const char* arg) {
  return ftp_active_printf(env, "200 NOOP OK\r\n");
}


/**
 *
 **/
int
ftp_cmd_REST(ftp_env_t *env, const char* arg) {
  if(!arg[0]) {
    return ftp_active_printf(env, "501 Usage: REST <OFFSET>\r\n");
  }
  
  env->data_offset = atol(arg);

  return ftp_active_printf(env, "200 REST OK\r\n");
}


/**
 *
 **/
int
ftp_cmd_DELE(ftp_env_t *env, const char* arg) {
  char pathbuf[PATH_MAX];

  if(!arg[0]) {
    return ftp_active_printf(env, "501 Usage: DELE <FILENAME>\r\n");
  }

  ftp_abspath(env, pathbuf, arg);
  if(remove(pathbuf)) {
    return ftp_perror(env);
  }

  return ftp_active_printf(env, "226 File deleted\r\n");
}


/**
 *
 **/
int
ftp_cmd_MKD(ftp_env_t *env, const char* arg) {
  char pathbuf[PATH_MAX];

  if(!arg[0]) {
    return ftp_active_printf(env, "501 Usage: MKD <DIRNAME>\r\n");
  }

  ftp_abspath(env, pathbuf, arg);
  if(mkdir(pathbuf, 0777)) {
    return ftp_perror(env);
  }

  return ftp_active_printf(env, "226 Directory created\r\n");
}


/**
 *
 **/
int
ftp_cmd_CDUP(ftp_env_t *env, const char* arg) {
  int pos = -1;

  for(size_t i=0; i<sizeof(env->cwd); i++) {
    if(!env->cwd[i]) {
      break;
    } else if(env->cwd[i] == '/') {
      pos = i;
    }
  }

  if(pos > 0) {
    env->cwd[pos] = '\0';
  }

  return ftp_active_printf(env, "250 OK\r\n");
}


/**
 *
 **/
int
ftp_cmd_RMD(ftp_env_t *env, const char* arg) {
  char pathbuf[PATH_MAX];

  if(!arg[0]) {
    return ftp_active_printf(env, "501 Usage: RMD <DIRNAME>\r\n");
  }

  ftp_abspath(env, pathbuf, arg);
  if(rmdir(pathbuf)) {
    return ftp_perror(env);
  }

  return ftp_active_printf(env, "226 Directory deleted\r\n");
}


/**
 *
 **/
int
ftp_cmd_RNFR(ftp_env_t *env, const char* arg) {
  struct stat st;

  if(!arg[0]) {
    return ftp_active_printf(env, "501 Usage: RNFR <PATH>\r\n");
  }

  ftp_abspath(env, env->rename_path, arg);
  if(stat(env->rename_path, &st)) {
    return ftp_perror(env);
  }

  return ftp_active_printf(env, "350 Awaiting new name\r\n");
}


/**
 *
 **/
int
ftp_cmd_RNTO(ftp_env_t *env, const char* arg) {
  char pathbuf[PATH_MAX];
  struct stat st;

  if(!arg[0]) {
    return ftp_active_printf(env, "501 Usage: RNTO <PATH>\r\n");
  }

  if(stat(env->rename_path, &st)) {
    return ftp_perror(env);
  }

  ftp_abspath(env, pathbuf, arg);
  if(rename(env->rename_path, pathbuf)) {
    return ftp_perror(env);
  }

  return ftp_active_printf(env, "226 Path renamed\r\n");
}


#ifdef MTRW_COMMAND
/**
 * Build an iovec structure for nmount().
 **/
static void
freebsd_build_iovec(struct iovec **iov, int *iovlen, const char *name, const char *v) {
  int i;

  if(*iovlen < 0) {
    return;
  }

  i = *iovlen;
  *iov = realloc(*iov, sizeof(**iov) * (i + 2));
  if(*iov == 0) {
    *iovlen = -1;
    return;
  }

  (*iov)[i].iov_base = strdup(name);
  (*iov)[i].iov_len = strlen(name) + 1;
  i++;

  (*iov)[i].iov_base = v ? strdup(v) : 0;
  (*iov)[i].iov_len = v ? strlen(v) + 1 : 0;
  i++;

  *iovlen = i;
}


/**
 * Remount a given path with write permissions.
 * 
 * TODO: is there a memory leak to plug?
 **/
static int
sce_remount(const char *dev, const char *path) {
  struct iovec* iov = 0;
  int iovlen = 0;

  freebsd_build_iovec(&iov, &iovlen, "fstype", "exfatfs");
  freebsd_build_iovec(&iov, &iovlen, "fspath", path);
  freebsd_build_iovec(&iov, &iovlen, "from", dev);
  freebsd_build_iovec(&iov, &iovlen, "large", "yes");
  freebsd_build_iovec(&iov, &iovlen, "timezone", "static");
  freebsd_build_iovec(&iov, &iovlen, "async", 0);
  freebsd_build_iovec(&iov, &iovlen, "ignoreacl", 0);

  return nmount(iov, iovlen, MNT_UPDATE);
}
#endif // MTRW_COMMAND


/**
 * Remount read-only mount points with write permissions.
 **/
int
ftp_cmd_MTRW(ftp_env_t *env, const char* arg) {
#ifdef MTRW_COMMAND
  if(sce_remount("/dev/ssd0.system", "/system")) {
    return ftp_perror(env);
  }
  if(sce_remount("/dev/ssd0.system_ex", "/system_ex")) {
    return ftp_perror(env);
  }
  return ftp_active_printf(env, "226 /system and /system_ex remounted\r\n");
#else
  return ftp_cmd_NA(env, arg);
#endif
}

