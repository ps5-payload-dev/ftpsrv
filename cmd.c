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
#include <strings.h>
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
 * Close the data connection after a failure, preserving errno.
 **/
static int
ftp_data_fail(ftp_env_t *env) {
  int err = errno;

  ftp_data_close(env);
  errno = err;

  return -1;
}


/**
 * Open the data connection.
 */
int
ftp_data_open(ftp_env_t *env) {
  socklen_t addr_len = sizeof(struct sockaddr_in);
  struct sockaddr_in data_addr;
  int opt;

  if(env->data_fd != -1) {
    ftp_data_close(env);
  }

  if(env->data_addr.sin_port) {
    if((env->data_fd=socket(AF_INET, SOCK_STREAM, 0)) < 0) {
      return -1;
    }
    if(connect(env->data_fd, (struct sockaddr*)&env->data_addr,
	       sizeof(env->data_addr))) {
      return ftp_data_fail(env);
    }
  } else {
    if((env->data_fd=accept(env->passive_fd, (struct sockaddr*)&data_addr,
			    &addr_len)) < 0) {
      return -1;
    }
  }

  opt = 0x100000;
  if(setsockopt(env->data_fd, SOL_SOCKET, SO_SNDBUF, &opt, sizeof(opt)) < 0) {
    return ftp_data_fail(env);
  }
  if(setsockopt(env->data_fd, SOL_SOCKET, SO_RCVBUF, &opt, sizeof(opt)) < 0) {
    return ftp_data_fail(env);
  }

  // the connection stays open between transfers in block mode, so send the
  // last block of each transfer right away instead of waiting until the peer
  // acknowledges the previous data
  if(env->mode == 'B') {
    opt = 1;
    if(setsockopt(env->data_fd, IPPROTO_TCP, TCP_NODELAY, &opt,
		  sizeof(opt)) < 0) {
      FTP_LOG_PERROR("setsockopt");
    }
  }

  env->data_pending = 0;

  return 0;
}


/**
 * Transmit data via an existing data connection, as data blocks in block mode.
 **/
static int
ftp_data_write(ftp_env_t *env, const void *buf, size_t len) {
  if(env->mode == 'B') {
    return io_block_write(&env->data_writer, buf, len);
  }

  return io_nwrite(env->data_fd, buf, len);
}


/**
 * Format and transmit a complete string via a control or data connection.
 **/
static int
ftp_vprintf(ftp_env_t *env, int data, const char *fmt, va_list args) {
  char buf[0x1000];
  char *out = buf;
  va_list copy;
  int len, err;

  va_copy(copy, args);
  len = vsnprintf(buf, sizeof(buf), fmt, copy);
  va_end(copy);
  if(len < 0) {
    return -1;
  }

  if((size_t)len >= sizeof(buf)) {
    if(!(out=malloc((size_t)len + 1))) {
      return -1;
    }
    va_copy(copy, args);
    err = vsnprintf(out, (size_t)len + 1, fmt, copy);
    va_end(copy);
    if(err != len) {
      free(out);
      errno = EIO;
      return -1;
    }
  }

  err = data ? ftp_data_write(env, out, len) :
    io_nwrite(env->active_fd, out, len);
  if(out != buf) {
    free(out);
  }

  return err;
}


/**
 * Transmit a formatted string via an existing data connection.
 **/
static int
ftp_data_printf(ftp_env_t *env, const char *fmt, ...) {
  va_list args;
  int err;

  va_start(args, fmt);
  err = ftp_vprintf(env, 1, fmt, args);
  va_end(args);

  return err;
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
  int fd = env->data_fd;

  env->data_fd = -1;
  if(close(fd)) {
    return -1;
  }

  return 0;
}


/**
 * Check if a transfer in block mode has a data connection to use: a new one
 * requested by PASV or PORT, or the one kept open by the previous transfer.
 **/
static int
ftp_block_ready(ftp_env_t *env) {
  return env->data_pending || env->data_fd != -1;
}


/**
 * Start a transfer in block mode: open the data connection requested by PASV
 * or PORT and send the given 150 reply, or reuse the connection kept open by
 * the previous transfer and reply 125. Returns 0 when the transfer can start;
 * otherwise an error reply was sent, and the result is 1 (-1 if the control
 * connection failed).
 **/
static int
ftp_block_begin(ftp_env_t *env, const char *msg) {
  if(!env->data_pending) {
    msg = "125 Data connection already open; transfer starting.\r\n";
  } else if(ftp_data_open(env)) {
    return ftp_active_printf(env, "425 Can't open data connection.\r\n") ?
      -1 : 1;
  }

  io_block_writer_init(&env->data_writer, env->data_fd, env->blockbuf);

  return ftp_active_printf(env, "%s", msg);
}


/**
 * Abort a transfer in block mode after a failure of the data connection, or
 * of the data it carries.
 **/
static int
ftp_block_abort(ftp_env_t *env) {
  ftp_data_close(env);

  return ftp_active_printf(env, "426 Connection closed; transfer aborted.\r\n");
}


/**
 * End a transfer in block mode that sends data with an EOF block, keeping the
 * data connection open for the next transfer.
 **/
static int
ftp_block_end(ftp_env_t *env) {
  if(io_block_write_eof(&env->data_writer)) {
    return ftp_block_abort(env);
  }

  return ftp_active_printf(env, "250 Transfer complete.\r\n");
}


/**
 * Write a string to the active connection with printf semantics.
 **/
int
ftp_active_printf(ftp_env_t *env, const char *fmt, ...) {
  va_list args;
  int err;

  va_start(args, fmt);
  err = ftp_vprintf(env, 0, fmt, args);
  va_end(args);

  return err;
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
int
ftp_abspath(ftp_env_t *env, char *abspath, const char *path) {
  int len;

  if(path[0] != '/') {
    len = snprintf(abspath, PATH_MAX, "%s/%s", env->cwd, path);
  } else {
    len = snprintf(abspath, PATH_MAX, "%s", path);
  }

  if(len < 0 || len >= PATH_MAX) {
    abspath[0] = '\0';
    if(len >= PATH_MAX) {
      errno = ENAMETOOLONG;
    }
    return -1;
  }

  return 0;
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

  // a new data connection replaces the one kept open in block mode
  if(env->data_fd != -1) {
    ftp_data_close(env);
  }
  env->data_pending = 0;

  if(getsockname(env->active_fd, (struct sockaddr*)&sockaddr, &sockaddr_len)) {
    return ftp_perror(env);
  }
  addr = sockaddr.sin_addr.s_addr;

  // forget the address given by a previous PORT command
  memset(&env->data_addr, 0, sizeof(env->data_addr));

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
    env->passive_fd = -1;
    return ret;
  }

  if(listen(env->passive_fd, 1) != 0) {
    ret = ftp_perror(env);
    close(env->passive_fd);
    env->passive_fd = -1;
    return ret;
  }

  if(getsockname(env->passive_fd, (struct sockaddr*)&sockaddr, &sockaddr_len)) {
    ret = ftp_perror(env);
    close(env->passive_fd);
    env->passive_fd = -1;
    return ret;
  }
  port = sockaddr.sin_port;
  env->data_pending = 1;

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
  const char* ptr;

  if(!arg[0] || !(ptr=strstr(arg, " "))) {
    return ftp_active_printf(env, "501 Usage: CHMOD <MODE> <PATH>\r\n");
  }

  mode = strtol(arg, 0, 8);
  if(ftp_abspath(env, pathbuf, ptr+1)) {
    return ftp_perror(env);
  }

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

  if(ftp_abspath(env, pathbuf, arg)) {
    return ftp_perror(env);
  }
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

  if(ftp_abspath(env, pathbuf, arg)) {
    return ftp_perror(env);
  }
  if(remove(pathbuf)) {
    return ftp_perror(env);
  }

  return ftp_active_printf(env, "226 File deleted\r\n");
}


/**
 * List supported FTP protocol extensions.
 **/
int
ftp_cmd_FEAT(ftp_env_t *env, const char *arg) {
  return ftp_active_printf(env,
                           "211-Features:\r\n"
                           " MLSD\r\n"
                           " KILL\r\n"
                           " MTRW\r\n"
                           " SELF\r\n"
                           "211 End\r\n");
}


/**
 * Trasfer a list of files and folder.
 **/
int
ftp_cmd_LIST(ftp_env_t *env, const char* arg) {
  const char *p = env->cwd;
  char pathbuf[PATH_MAX*3];
  char dirbuf[PATH_MAX];
  struct dirent *ent;
  struct stat statbuf;
  char timebuf[20];
  char modebuf[20];
  struct tm tm;
  DIR *dir;
  int err;

  if(env->mode == 'B' && !ftp_block_ready(env)) {
    return ftp_active_printf(env, "425 Use PORT or PASV first.\r\n");
  }

  if(arg[0] && arg[0] != '-') {
    if(ftp_abspath(env, dirbuf, arg)) {
      return ftp_perror(env);
    }
    p = dirbuf;
  }

  if(!(dir=opendir(p))) {
    return ftp_perror(env);
  }

  if(env->mode == 'B') {
    if((err=ftp_block_begin(env, "150 Opening data transfer\r\n"))) {
      closedir(dir);
      return err > 0 ? 0 : err;
    }
  } else {
    if(ftp_data_open(env)) {
      err = ftp_perror(env);
      closedir(dir);
      return err;
    }

    ftp_active_printf(env, "150 Opening data transfer\r\n");
  }

  while((ent=readdir(dir))) {
    snprintf(pathbuf, sizeof(pathbuf), "%s/%s", p, ent->d_name);

    if(stat(pathbuf, &statbuf) != 0) {
      continue;
    }

    if(env->self2elf && self_is_valid(pathbuf) == 1) {
      statbuf.st_size = self_get_elfsize(pathbuf);
    }

    ftp_mode_string(statbuf.st_mode, modebuf);
    gmtime_r(&statbuf.st_ctim.tv_sec, &tm);
    strftime(timebuf, sizeof(timebuf), "%b %d %H:%M", &tm);
    if(ftp_data_printf(env, "%s %lu %lu %lu %llu %s %s\r\n", modebuf,
		       statbuf.st_nlink, statbuf.st_uid, statbuf.st_gid,
		       statbuf.st_size, timebuf, ent->d_name) &&
       env->mode == 'B') {
      closedir(dir);
      return ftp_block_abort(env);
    }
  }

  if(env->mode == 'B') {
    closedir(dir);
    return ftp_block_end(env);
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

  if(ftp_abspath(env, pathbuf, arg)) {
    return ftp_perror(env);
  }
  if(mkdir(pathbuf, 0777)) {
    return ftp_perror(env);
  }

  return ftp_active_printf(env, "226 Directory created\r\n");
}


/**
 * Transfer a machine-readable directory listing.
 **/
int
ftp_cmd_MLSD(ftp_env_t *env, const char *arg) {
  char pathbuf[PATH_MAX*3];
  struct stat statbuf;
  struct dirent *ent;
  char timebuf[20];
  struct tm tm;
  DIR *dir;
  int err;

  if(env->mode == 'B' && !ftp_block_ready(env)) {
    return ftp_active_printf(env, "425 Use PORT or PASV first.\r\n");
  }

  if(!(dir=opendir(env->cwd))) {
    return ftp_perror(env);
  }

  if(env->mode == 'B') {
    if((err=ftp_block_begin(env, "150 Opening data transfer\r\n"))) {
      closedir(dir);
      return err > 0 ? 0 : err;
    }
  } else {
    if(ftp_data_open(env)) {
      err = ftp_perror(env);
      closedir(dir);
      return err;
    }

    ftp_active_printf(env, "150 Opening data transfer\r\n");
  }

  while((ent=readdir(dir))) {
    snprintf(pathbuf, sizeof(pathbuf), "/%s/%s", env->cwd, ent->d_name);
    if(stat(pathbuf, &statbuf) != 0) {
      continue;
    }

    if(env->self2elf && self_is_valid(pathbuf) == 1) {
      statbuf.st_size = self_get_elfsize(pathbuf);
    }

    gmtime_r(&statbuf.st_ctim.tv_sec, &tm);
    strftime(timebuf, sizeof(timebuf), "%Y%m%d%H%M%S", &tm);

    if(ftp_data_printf(env, "type=%s;size=%llu;modify=%s; %s\r\n",
		       S_ISDIR(statbuf.st_mode) ? "dir" : "file",
		       statbuf.st_size, timebuf, ent->d_name) &&
       env->mode == 'B') {
      closedir(dir);
      return ftp_block_abort(env);
    }
  }

  if(env->mode == 'B') {
    closedir(dir);
    return ftp_block_end(env);
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
 * Set the transfer mode: stream (S), or block (B) where the data connection
 * stays open between transfers.
 **/
int
ftp_cmd_MODE(ftp_env_t *env, const char* arg) {
  if(!arg[0]) {
    return ftp_active_printf(env, "501 Usage: MODE <S|B>\r\n");
  }

  if(!strcasecmp(arg, "S")) {
    // in stream mode, closing the data connection ends each transfer
    if(env->data_fd != -1) {
      ftp_data_close(env);
    }
    env->mode = 'S';

  } else if(!strcasecmp(arg, "B")) {
    env->mode = 'B';

  } else {
    return ftp_active_printf(env, "504 Unsupported transfer mode.\r\n");
  }

  return ftp_active_printf(env, "200 Mode set to %c.\r\n", env->mode);
}


/**
 * Transfer a list of names: the entries of a directory, or the given path when
 * it names a file.
 **/
int
ftp_cmd_NLST(ftp_env_t *env, const char* arg) {
  char pathbuf[PATH_MAX];
  struct dirent *ent;
  const char *p = arg;
  struct stat st;
  DIR *dir = 0;
  int err = 0;

  if(env->mode == 'B' && !ftp_block_ready(env)) {
    return ftp_active_printf(env, "425 Use PORT or PASV first.\r\n");
  }

  // skip ls-style options such as -a (names starting with a dot are always
  // listed)
  while(p[0] == '-') {
    if(!(p=strchr(p, ' '))) {
      p = "";
      break;
    }
    while(p[0] == ' ') {
      p++;
    }
  }

  if(p[0]) {
    if(ftp_abspath(env, pathbuf, p)) {
      return ftp_perror(env);
    }
  } else {
    snprintf(pathbuf, sizeof(pathbuf), "%s", env->cwd);
  }

  if(stat(pathbuf, &st)) {
    return ftp_perror(env);
  }
  if(S_ISDIR(st.st_mode) && !(dir=opendir(pathbuf))) {
    return ftp_perror(env);
  }

  if(env->mode == 'B') {
    if((err=ftp_block_begin(env, "150 Opening data transfer\r\n"))) {
      if(dir) {
	closedir(dir);
      }
      return err > 0 ? 0 : err;
    }
  } else {
    if(ftp_data_open(env)) {
      err = ftp_perror(env);
      if(dir) {
	closedir(dir);
      }
      return err;
    }

    ftp_active_printf(env, "150 Opening data transfer\r\n");
  }

  if(!dir) {
    err = ftp_data_printf(env, "%s\r\n", p);
  } else {
    while(!err && (ent=readdir(dir))) {
      if(strcmp(ent->d_name, ".") && strcmp(ent->d_name, "..")) {
	err = ftp_data_printf(env, "%s\r\n", ent->d_name);
      }
    }
    closedir(dir);
  }

  if(env->mode == 'B') {
    if(err) {
      return ftp_block_abort(env);
    }
    return ftp_block_end(env);
  }

  if(err) {
    ftp_data_close(env);
    return ftp_active_printf(env, "426 Connection closed; transfer aborted.\r\n");
  }

  if(ftp_data_close(env)) {
    return ftp_perror(env);
  }

  return ftp_active_printf(env, "226 Transfer complete\r\n");
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

  // a new data connection replaces the one kept open in block mode
  if(env->data_fd != -1) {
    ftp_data_close(env);
  }

  // stop listening for a connection requested by a previous PASV command
  if(env->passive_fd > 0) {
    close(env->passive_fd);
    env->passive_fd = -1;
  }

  s_addr = (addr[3] << 24) | (addr[2] << 16) | (addr[1] << 8) | addr[0];
  port = (addr[5] << 8) | addr[4];

  env->data_addr.sin_family = AF_INET;
  env->data_addr.sin_addr.s_addr = s_addr;
  env->data_addr.sin_port = port;
  env->data_pending = 1;

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
  intmax_t off;
  char *end;

  if(!arg[0]) {
    return ftp_active_printf(env, "501 Usage: REST <OFFSET>\r\n");
  }

  errno = 0;
  off = strtoimax(arg, &end, 10);
  if(arg[0] < '0' || arg[0] > '9' || *end || errno || off < 0 ||
     (intmax_t)(off_t)off != off) {
    return ftp_active_printf(env, "501 Invalid restart offset\r\n");
  }

  env->data_offset = (off_t)off;

  return ftp_active_printf(env, "350 REST OK\r\n");
}


/**
 * Transfer N bytes from a given file in block mode.
 **/
static int
ftp_cmd_RETR_block(ftp_env_t *env, int fd, size_t size) {
  size_t len;
  int err;

  if((err=ftp_block_begin(env, "150 Starting data transfer\r\n"))) {
    return err > 0 ? 0 : err;
  }

  while(size) {
    len = size;
    if(len > env->readbuf_size) {
      len = env->readbuf_size;
    }

    if(io_nread(fd, env->readbuf, len)) {
      ftp_data_fail(env);
      return ftp_perror(env);
    }
    if(io_block_write(&env->data_writer, env->readbuf, len)) {
      return ftp_block_abort(env);
    }

    size -= len;
  }

  return ftp_block_end(env);
}


/**
 * Retreive data from a given file.
 **/
static int
ftp_cmd_RETR_fd(ftp_env_t *env, int fd, off_t off) {
  struct stat st;
  int err = 0;

  if(fstat(fd, &st)) {
    return ftp_perror(env);
  }
  if(off < 0 || off > st.st_size) {
    errno = EINVAL;
    return ftp_perror(env);
  }
  if(lseek(fd, off, SEEK_SET) < 0) {
    return ftp_perror(env);
  }

  if(env->mode == 'B') {
    return ftp_cmd_RETR_block(env, fd, st.st_size - off);
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

  return ftp_active_printf(env, "226 Transfer completed\r\n");
}


/**
 * Retreive an ELF file embedded within a SELF file.
 **/
static int
ftp_cmd_RETR_self2elf(ftp_env_t *env, int fd, off_t off) {
  int code = 150;
  FILE* tmpf;
  int err;

  // the preliminary reply ends with 125 when block mode reuses the data
  // connection, and its first lines must have the same code
  if(env->mode == 'B' && !env->data_pending) {
    code = 125;
  }

  if(!(tmpf=tmpfile())) {
    return ftp_perror(env);
  }

  if(ftp_active_printf(env, "%d-Extracting ELF...\r\n", code)) {
    fclose(tmpf);
    return -1;
  }
  if(self_extract_elf(fd, fileno(tmpf))) {
    if(errno != EBADMSG) {
      err = ftp_perror(env);
      fclose(tmpf);
      return err;
    }
    if(ftp_active_printf(env, "%d-Warning: ELF digest mismatch\r\n", code)) {
      fclose(tmpf);
      return -1;
    }
  }

  rewind(tmpf);
  err = ftp_cmd_RETR_fd(env, fileno(tmpf), off);
  fclose(tmpf);

  return err;
}


/**
 * Retreive data from a given file.
 **/
int
ftp_cmd_RETR(ftp_env_t *env, const char* arg) {
  off_t off = env->data_offset;
  char path[PATH_MAX];
  int err;
  int fd;

  env->data_offset = 0;

  if(!arg[0]) {
    return ftp_active_printf(env, "501 Usage: RETR <PATH>\r\n");
  }

  if(env->mode == 'B' && !ftp_block_ready(env)) {
    return ftp_active_printf(env, "425 Use PORT or PASV first.\r\n");
  }

  if(ftp_abspath(env, path, arg)) {
    return ftp_perror(env);
  }
  if((fd=open(path, O_RDONLY, 0)) < 0) {
    return ftp_perror(env);
  }

  if(env->self2elf && self_is_valid(path) == 1) {
    err = ftp_cmd_RETR_self2elf(env, fd, off);
  } else {
    err = ftp_cmd_RETR_fd(env, fd, off);
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

  if(ftp_abspath(env, pathbuf, arg)) {
    return ftp_perror(env);
  }
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

  if(ftp_abspath(env, env->rename_path, arg)) {
    return ftp_perror(env);
  }
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

  if(ftp_abspath(env, pathbuf, arg)) {
    return ftp_perror(env);
  }
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
  size_t size;

  if(!arg[0]) {
    return ftp_active_printf(env, "501 Usage: SIZE <FILENAME>\r\n");
  }

  if(ftp_abspath(env, pathbuf, arg)) {
    return ftp_perror(env);
  }
  if(stat(pathbuf, &st)) {
    return ftp_active_printf(env, "550 No such file or directory\r\n");
  }

  if(env->self2elf) {
    if((size=self_get_elfsize(pathbuf))) {
      st.st_size = size;
    }
  }

  return ftp_active_printf(env, "213 %"  PRIu64 "\r\n", st.st_size);
}


/**
 * Store data received in block mode in a given file, starting at a given
 * offset.
 **/
static int
ftp_cmd_STOR_block(ftp_env_t *env, int fd, off_t off) {
  io_block_reader_t reader;
  size_t size = 0;
  ssize_t len;
  int err;

  if((err=ftp_block_begin(env, "150 Opening data transfer\r\n"))) {
    return err > 0 ? 0 : err;
  }

  io_block_reader_init(&reader, env->data_fd);
  while(1) {
    // gather data from several blocks before writing it to the file
    len = io_block_read(&reader, (char*)env->readbuf + size,
			env->readbuf_size - size);
    if(len > 0) {
      size += len;
      if(size < env->readbuf_size) {
	continue;
      }
    }

    if(size) {
      if(io_nwrite(fd, env->readbuf, size)) {
	ftp_data_fail(env);
	return ftp_perror(env);
      }
      off += size;
      size = 0;
    }

    if(len < 0) {
      // keep the data received before the failure, but nothing past it
      if(ftruncate(fd, off)) {
	FTP_LOG_PERROR("ftruncate");
      }
      return ftp_block_abort(env);
    }

    if(!len) {
      break;
    }
  }

  if(ftruncate(fd, off)) {
    ftp_data_fail(env);
    return ftp_perror(env);
  }

  return ftp_active_printf(env, "250 Transfer complete.\r\n");
}


/**
 * Store recieved data in a given file.
 **/
int
ftp_cmd_STOR(ftp_env_t *env, const char* arg) {
  off_t off = env->data_offset;
  char pathbuf[PATH_MAX];
  int err = 0;
  ssize_t len;
  int fd;

  env->data_offset = 0;

  if(!arg[0]) {
    return ftp_active_printf(env, "501 Usage: STOR <FILENAME>\r\n");
  }

  if(env->type == 'A') {
    return ftp_active_printf(env, "504 STOR in ASCII mode is not supported\r\n");
  }

  if(env->mode == 'B' && !ftp_block_ready(env)) {
    return ftp_active_printf(env, "425 Use PORT or PASV first.\r\n");
  }

  if(ftp_abspath(env, pathbuf, arg)) {
    return ftp_perror(env);
  }
  if((fd=open(pathbuf, O_CREAT | O_WRONLY, 0777)) < 0) {
    return ftp_perror(env);
  }

  if(lseek(fd, off, SEEK_CUR) < 0) {
    err = ftp_perror(env);
    close(fd);
    return err;
  }

  if(env->mode == 'B') {
    err = ftp_cmd_STOR_block(env, fd, off);
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

  if(len < 0) {
    err = ftp_perror(env);
    ftp_data_close(env);
    close(fd);
    return err;
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
    if(ftp_abspath(env, pathbuf, arg)) {
      return ftp_perror(env);
    }
    if(stat(pathbuf, &statbuf)) {
      // a file that does not exist is created, starting at offset 0
      if(errno != ENOENT) {
	return ftp_perror(env);
      }
      statbuf.st_size = 0;
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
