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
#include <netinet/tcp.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#include "cmd.h"
#include "io.h"
#include "log.h"
#include "self.h"


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
 * Open the data connection.
 */
int
ftp_data_open(ftp_env_t *env) {
  struct sockaddr_in data_addr;
  socklen_t addr_len;
  int opt;

  if(env->data_fd != -1) {
    close(env->data_fd);
  }

  if(env->data_addr.sin_port) {
    if(connect(env->data_fd, (struct sockaddr*)&env->data_addr,
	       sizeof(env->data_addr))) {
      return -1;
    }
  } else {
    if((env->data_fd=accept(env->passive_fd, (struct sockaddr*)&data_addr,
			    &addr_len)) < 0) {
      return -1;
    }
  }

  opt = 0x100000;
  if(setsockopt(env->data_fd, SOL_SOCKET, SO_SNDBUF, &opt, sizeof(opt)) < 0) {
    return -1;
  }
  if(setsockopt(env->data_fd, SOL_SOCKET, SO_RCVBUF, &opt, sizeof(opt)) < 0) {
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
  len = vsnprintf(buf, sizeof(buf), fmt, args);
  va_end(args);

  if(io_nwrite(env->data_fd, buf, len)) {
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
 * Close the data connection.
 **/
int
ftp_data_close(ftp_env_t *env) {
  if(close(env->data_fd)) {
    return -1;
  }

  env->data_fd = -1;

  return 0;
}


/**
 * Write a string to the active connection with printf semantics.
 **/
int
ftp_active_printf(ftp_env_t *env, const char *fmt, ...) {
  char buf[0x1000];
  size_t len = 0;
  va_list args;

  va_start(args, fmt);
  len = vsnprintf(buf, sizeof(buf), fmt, args);
  va_end(args);

  if(io_nwrite(env->active_fd, buf, len)) {
    return -1;
  }

  return 0;
}


/**
 * Write a string to the active connection with perror semantics.
 **/
int
ftp_perror(ftp_env_t *env) {
  char buf[255];

  if(strerror_r(errno, buf, sizeof(buf))) {
    strncpy(buf, "Unknown error", sizeof(buf));
  }

  return ftp_active_printf(env, "550 %s\r\n", buf);
}


/**
 * Create an absolute path from the current working directory.
 **/
void
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
 * Enter passive mode.
 **/
int
ftp_cmd_PASV(ftp_env_t *env, const char* arg) {
  socklen_t sockaddr_len = sizeof(struct sockaddr_in);
  struct sockaddr_in sockaddr;
  uint32_t addr = 0;
  uint16_t port = 0;
  int ret = 0;

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
    ret = ftp_perror(env);
    close(env->passive_fd);
    return ret;
  }

  if(listen(env->passive_fd, SOMAXCONN) != 0) {
    ret = ftp_perror(env);
    close(env->passive_fd);
    return ret;
  }

  if(getsockname(env->passive_fd, (struct sockaddr*)&sockaddr, &sockaddr_len)) {
    ret = ftp_perror(env);
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
 * Change the working directory to its parent.
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

  if(pos <= 0) {
    env->cwd[0] = '/';
    env->cwd[1] = '\0';
  } else if(pos > 0) {
    env->cwd[pos] = '\0';
  }

  return ftp_active_printf(env, "250 OK\r\n");
}


/**
 * Change the permission mode bits of a path.
 **/
int
ftp_cmd_CHMOD(ftp_env_t *env, const char* arg) {
  char pathbuf[PATH_MAX];
  mode_t mode = 0;
  char* ptr;

  if(!arg[0] || !(ptr=strstr(arg, " "))) {
    return ftp_active_printf(env, "501 Usage: CHMOD <MODE> <PATH>\r\n");
  }

  mode = strtol(arg, 0, 8);
  ftp_abspath(env, pathbuf, ptr+1);

  if(chmod(pathbuf, mode)) {
    return ftp_perror(env);
  }

  return ftp_active_printf(env, "200 OK\r\n");
}


/**
 * Change the working directory.
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
 * Delete a given file.
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
 * Trasfer a list of files and folder.
 **/
int
ftp_cmd_LIST(ftp_env_t *env, const char* arg) {
  const char *p = env->cwd;
  char pathbuf[PATH_MAX*3];
  struct dirent *ent;
  struct stat statbuf;
  char timebuf[20];
  char modebuf[20];
  struct tm tm;
  DIR *dir;
  int err;

  if(arg[0] && arg[0] != '-') {
    p = arg;
  }

  if(!(dir=opendir(p))) {
    return ftp_perror(env);
  }

  if(ftp_data_open(env)) {
    err = ftp_perror(env);
    closedir(dir);
    return err;
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

    if(env->self2elf && self_is_valid(pathbuf) == 1) {
      statbuf.st_size = self_get_elfsize(pathbuf);
    }

    ftp_mode_string(statbuf.st_mode, modebuf);
    localtime_r((const time_t *)&(statbuf.st_ctim), &tm);
    strftime(timebuf, sizeof(timebuf), "%b %d %H:%M", &tm);
    ftp_data_printf(env, "%s %lu %lu %lu %llu %s %s\r\n", modebuf,
		    statbuf.st_nlink, statbuf.st_uid, statbuf.st_gid,
		    statbuf.st_size, timebuf, ent->d_name);
  }

  if(ftp_data_close(env)) {
    err = ftp_perror(env);
    closedir(dir);
    return err;
  }

  if(closedir(dir)) {
    return ftp_perror(env);
  }

  return ftp_active_printf(env, "226 Transfer complete\r\n");
}


/**
 * Create a new directory at a given path.
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
 * No operation.
 **/
int
ftp_cmd_NOOP(ftp_env_t *env, const char* arg) {
  return ftp_active_printf(env, "200 NOOP OK\r\n");
}


/**
 * Establish a data connection with client.
 **/
int
ftp_cmd_PORT(ftp_env_t *env, const char* arg) {
  uint8_t addr[6];
  uint64_t s_addr;
  uint16_t port;

  if(sscanf(arg, "%hhu,%hhu,%hhu,%hhu,%hhu,%hhu",
	    addr, addr+1, addr+2, addr+3, addr+4, addr+5) != 6) {
    return ftp_active_printf(env, "501 Usage: PORT <addr>\r\n");
  }

  if(env->data_fd != -1) {
    close(env->data_fd);
  }
  if((env->data_fd=socket(AF_INET, SOCK_STREAM, 0)) < 0) {
    return ftp_perror(env);
  }

  s_addr = (addr[3] << 24) | (addr[2] << 16) | (addr[1] << 8) | addr[0];
  port = (addr[5] << 8) | addr[4];

  env->data_addr.sin_family = AF_INET;
  env->data_addr.sin_addr.s_addr = s_addr;
  env->data_addr.sin_port = port;

  return ftp_active_printf(env, "200 PORT command successful.\r\n");
}


/**
 * Print working directory.
 **/
int
ftp_cmd_PWD(ftp_env_t *env, const char* arg) {
  return ftp_active_printf(env, "257 \"%s\"\r\n", env->cwd);
}


/**
 * Disconnect client.
 **/
int
ftp_cmd_QUIT(ftp_env_t *env, const char* arg) {
  ftp_active_printf(env, "221 Goodbye\r\n");
  return -1;
}


/**
 * Mark the offset to start from in a future file transer.
 **/
int
ftp_cmd_REST(ftp_env_t *env, const char* arg) {
  if(!arg[0]) {
    return ftp_active_printf(env, "501 Usage: REST <OFFSET>\r\n");
  }

  env->data_offset = atol(arg);

  return ftp_active_printf(env, "350 REST OK\r\n");
}


/**
 * Retreive data from a given file.
 **/
static int
ftp_cmd_RETR_fd(ftp_env_t *env, int fd) {
  off_t off = env->data_offset;
  struct stat st;
  int err = 0;

  if(fstat(fd, &st)) {
    return ftp_perror(env);
  }
  if(lseek(fd, off, SEEK_SET) < 0) {
    return ftp_perror(env);
  }

  if(ftp_active_printf(env, "150 Starting data transfer\r\n")) {
    return -1;
  }

  if(ftp_data_open(env)) {
    return ftp_perror(env);
  }

  if(io_ncopy(fd, env->data_fd, st.st_size - off)) {
    err = ftp_perror(env);
    ftp_data_close(env);
    return err;
  }

  if(ftp_data_close(env)) {
    return ftp_perror(env);
  }

  env->data_offset = 0;

  return ftp_active_printf(env, "226 Transfer completed\r\n");
}


/**
 * Retreive an ELF file embedded within a SELF file.
 **/
static int
ftp_cmd_RETR_self2elf(ftp_env_t *env, int fd) {
  FILE* tmpf;
  int err;

  if(!(tmpf=tmpfile())) {
    return ftp_perror(env);
  }

  if(ftp_active_printf(env, "150-Extracting ELF...\r\n")) {
    fclose(tmpf);
    return -1;
  }
  if(self_extract_elf(fd, fileno(tmpf))) {
    if(errno != EBADMSG) {
      err = ftp_perror(env);
      fclose(tmpf);
      return err;
    }
    if(ftp_active_printf(env, "150-Warning: ELF digest mismatch\r\n")) {
      fclose(tmpf);
      return -1;
    }
  }

  rewind(tmpf);
  err = ftp_cmd_RETR_fd(env, fileno(tmpf));
  fclose(tmpf);

  return err;
}


/**
 * Retreive data from a given file.
 **/
int
ftp_cmd_RETR(ftp_env_t *env, const char* arg) {
  char path[PATH_MAX];
  int err;
  int fd;

  if(!arg[0]) {
    return ftp_active_printf(env, "501 Usage: RETR <PATH>\r\n");
  }

  ftp_abspath(env, path, arg);
  if((fd=open(path, O_RDONLY, 0)) < 0) {
    return ftp_perror(env);
  }

  if(env->self2elf && self_is_valid(path) == 1) {
    err = ftp_cmd_RETR_self2elf(env, fd);
  } else {
    err = ftp_cmd_RETR_fd(env, fd);
  }

  close(fd);
  return err;
}


/**
 * Remove a directory.
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
 * Specify a path that will later be renamed by the RNTO command.
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
 * Rename a path previously specified by the RNFR command.
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


/**
 * Obtain the size of a given file.
 **/
int
ftp_cmd_SIZE(ftp_env_t *env, const char* arg) {
  char pathbuf[PATH_MAX];
  struct stat st = {0};

  if(!arg[0]) {
    return ftp_active_printf(env, "501 Usage: SIZE <FILENAME>\r\n");
  }

  ftp_abspath(env, pathbuf, arg);

  if(env->self2elf) {
    st.st_size = self_get_elfsize(pathbuf);
  }

  if(!st.st_size) {
    if(stat(pathbuf, &st)) {
      return ftp_perror(env);
    }
  }

  return ftp_active_printf(env, "213 %"  PRIu64 "\r\n", st.st_size);
}


/**
 * Store recieved data in a given file.
 **/
int
ftp_cmd_STOR(ftp_env_t *env, const char* arg) {
  off_t off = env->data_offset;
  char pathbuf[PATH_MAX];
  int err = 0;
  size_t len;
  int fd;

  env->data_offset = 0;

  if(!arg[0]) {
    return ftp_active_printf(env, "501 Usage: STOR <FILENAME>\r\n");
  }

  if(env->type == 'A') {
    return ftp_active_printf(env, "504 STOR in ASCII mode is not supported\r\n");
  }

  ftp_abspath(env, pathbuf, arg);
  if((fd=open(pathbuf, O_CREAT | O_WRONLY, 0777)) < 0) {
    return ftp_perror(env);
  }

  if(lseek(fd, off, SEEK_CUR) < 0) {
    err = ftp_perror(env);
    close(fd);
    return err;
  }

  if(ftp_active_printf(env, "150 Opening data transfer\r\n")) {
    close(fd);
    return -1;
  }

  if(ftp_data_open(env)) {
    err = ftp_perror(env);
    close(fd);
    return err;
  }

  while((len=ftp_data_read(env, env->readbuf, env->readbuf_size)) > 0) {
    if(io_nwrite(fd, env->readbuf, len)) {
      err = ftp_perror(env);
      ftp_data_close(env);
      close(fd);
      return err;
    }
    off += len;
  }

  if(ftruncate(fd, off)) {
    err = ftp_perror(env);
    ftp_data_close(env);
    close(fd);
    return err;
  }

  close(fd);
  if(ftp_data_close(env)) {
    return ftp_perror(env);
  }

  return ftp_active_printf(env, "226 Data transfer complete\r\n");
}


/**
 * Append to an existing file.
 **/
int
ftp_cmd_APPE(ftp_env_t *env, const char* arg) {
  char pathbuf[PATH_MAX];
  struct stat statbuf;

  if(!arg[0]) {
    return ftp_active_printf(env, "501 Usage: APPE <FILENAME>\r\n");
  }

  if(!env->data_offset) {
    ftp_abspath(env, pathbuf, arg);
    if(stat(pathbuf, &statbuf)) {
      return ftp_perror(env);
    }
    env->data_offset = statbuf.st_size;
  }

  return ftp_cmd_STOR(env, arg);
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
  env->type = arg[0];

  switch(arg[0]) {
  case 'A':
  case 'I':
    return ftp_active_printf(env, "200 Type set to %c\r\n", env->type);
  default:
    return ftp_active_printf(env, "501 Invalid argument to TYPE\r\n");
  }
}


/**
 * Authenticate user.
 **/
int
ftp_cmd_USER(ftp_env_t *env, const char* arg) {
  return ftp_active_printf(env, "230 User logged in\r\n");
}


/**
 * Custom command that terminates the server.
 **/
int
ftp_cmd_KILL(ftp_env_t *env, const char* arg) {
  FTP_LOG_PUTS("Server killed");
  exit(EXIT_SUCCESS);
  return -1;
}



/**
 * Custom command to toggle SELF transfer mode.
 **/
int
ftp_cmd_SELF(ftp_env_t *env, const char* arg) {
  env->self2elf = !env->self2elf;

  if(env->self2elf) {
    return ftp_active_printf(env, "226 SELF transfer mode enabled\r\n");
  } else {
    return ftp_active_printf(env, "226 SELF transfer mode disabled\r\n");
  }
}


/**
 * Unsupported command.
 **/
int
ftp_cmd_unavailable(ftp_env_t *env, const char* arg) {
  return ftp_active_printf(env, "502 Command not implemented\r\n");
}


/**
 * Unknown command.
 **/
int
ftp_cmd_unknown(ftp_env_t *env, const char* arg) {
  return ftp_active_printf(env, "502 Command not recognized\r\n");
}


/*
  Local Variables:
  c-file-style: "gnu"
  End:
*/
