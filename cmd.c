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

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "cmd.h"
#include "io.h"
#include "log.h"
#include "self.h"

#ifndef FTP_LIST_OUTBUF_SIZE
#define FTP_LIST_OUTBUF_SIZE (256 * 1024)
#endif

#define DISABLE_ASCII_MODE

// #define IO_USE_SENDFILE  // Disabled. Speed x2 down ?!


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

static int
ftp_normpath(const char *path, char *out, size_t out_size) {
  size_t stack[PATH_MAX / 2 + 2];
  size_t sp = 0;
  size_t len = 1;
  const char *p = path;

  if(!path || !out || out_size < 2) {
    errno = EINVAL;
    return -1;
  }

  out[0] = '/';
  out[1] = '\0';

  while(*p == '/') {
    p++;
  }

  while(*p) {
    const char *start = p;
    size_t comp_len = 0;

    while(*p && *p != '/') {
      p++;
      comp_len++;
    }
    while(*p == '/') {
      p++;
    }

    if(!comp_len || (comp_len == 1 && start[0] == '.')) {
      continue;
    }

    if(comp_len == 2 && start[0] == '.' && start[1] == '.') {
      if(sp > 0) {
        len = stack[--sp];
        out[len] = '\0';
      } else {
        len = 1;
        out[1] = '\0';
      }
      continue;
    }

    size_t prelen = len;
    if(len > 1) {
      if(len + 1 >= out_size) {
        errno = ENAMETOOLONG;
        return -1;
      }
      out[len++] = '/';
    }

    if(len + comp_len >= out_size) {
      errno = ENAMETOOLONG;
      return -1;
    }

    memcpy(out + len, start, comp_len);
    len += comp_len;
    out[len] = '\0';

    if(sp < (sizeof(stack) / sizeof(stack[0]))) {
      stack[sp++] = prelen;
    }
  }
  return 0;
}


/**
 * Open the data connection.
 */
int
ftp_data_open(ftp_env_t *env) {
  struct sockaddr_in data_addr;
  struct sockaddr_in ctrl_addr;
  socklen_t addr_len;
  socklen_t ctrl_len;

  if(env->data_addr.sin_port) {
    if(env->data_fd < 0) {
      env->data_fd = socket(AF_INET, SOCK_STREAM, 0);
      if(env->data_fd < 0) {
        return -1;
      }
    }
    if(connect(env->data_fd, (struct sockaddr*)&env->data_addr,
               sizeof(env->data_addr))) {
      close(env->data_fd);
      env->data_fd = -1;
      return -1;
    }
  } else {
    if(env->passive_fd < 0) {
      errno = ENOTCONN;
      return -1;
    }
    addr_len = sizeof(data_addr);
    if((env->data_fd=accept(env->passive_fd, (struct sockaddr*)&data_addr,
                              &addr_len)) < 0) {
      return -1;
    }

    close(env->passive_fd);
    env->passive_fd = -1;

    memset(&ctrl_addr, 0, sizeof(ctrl_addr));
    ctrl_len = sizeof(ctrl_addr);
    if(getpeername(env->active_fd, (struct sockaddr *)&ctrl_addr, &ctrl_len) !=
       0) {
      close(env->data_fd);
      env->data_fd = -1;
      errno = EACCES;
      return -1;
    }
    if(ctrl_addr.sin_family != AF_INET ||
       ctrl_addr.sin_addr.s_addr != data_addr.sin_addr.s_addr) {
      close(env->data_fd);
      env->data_fd = -1;
      errno = EACCES;
      return -1;
    }
  }

  io_set_socket_opts(env->data_fd, 1);

  return 0;
}


/**
 * Read data from an existing data connection.
 **/
static ssize_t
ftp_data_read(ftp_env_t *env, void *buf, size_t count) {
  for(;;) {
    ssize_t r = recv(env->data_fd, buf, count, 0);
    if(r < 0 && errno == EINTR) {
      continue;
    }
    return r;
  }
}

static int
ftp_copy_ascii_out(ftp_env_t *env, int fd_in) {
  char *inbuf = env->xfer_buf;
  size_t bufsize = env->xfer_buf_size;
  char *outbuf = NULL;
  size_t outcap = 0;
  int free_in = 0;
  int prev_cr = 0;

  if(!inbuf || !bufsize) {
    inbuf = malloc(IO_COPY_BUFSIZE);
    bufsize = IO_COPY_BUFSIZE;
    free_in = 1;
    if(!inbuf) {
      return -1;
    }
  }

  outcap = bufsize * 2 + 2;
  outbuf = malloc(outcap);
  if(!outbuf) {
    if(free_in) {
      free(inbuf);
    }
    return -1;
  }

  for(;;) {
    ssize_t r = read(fd_in, inbuf, bufsize);
    size_t out_len = 0;

    if(r < 0) {
      if(errno == EINTR) {
        continue;
      }
      goto error;
    }
    if(r == 0) {
      break;
    }

    for(ssize_t i = 0; i < r; i++) {
      unsigned char c = (unsigned char)inbuf[i];

      if(prev_cr) {
        if(c == '\n') {
          outbuf[out_len++] = '\r';
          outbuf[out_len++] = '\n';
          prev_cr = 0;
          continue;
        }
        outbuf[out_len++] = '\r';
        prev_cr = 0;
      }

      if(c == '\r') {
        prev_cr = 1;
        continue;
      }
      if(c == '\n') {
        outbuf[out_len++] = '\r';
        outbuf[out_len++] = '\n';
        continue;
      }
      outbuf[out_len++] = (char)c;
    }

    if(out_len && io_nwrite(env->data_fd, outbuf, out_len)) {
      goto error;
    }
  }

  if(prev_cr) {
    outbuf[0] = '\r';
    if(io_nwrite(env->data_fd, outbuf, 1)) {
      goto error;
    }
  }

  free(outbuf);
  if(free_in) {
    free(inbuf);
  }
  return 0;

error:
  free(outbuf);
  if(free_in) {
    free(inbuf);
  }
  return -1;
}

static int
ftp_copy_ascii_in(ftp_env_t *env, int fd_out, off_t *out_off) {
  char *inbuf = env->xfer_buf;
  size_t bufsize = env->xfer_buf_size;
  char *outbuf = NULL;
  size_t outcap = 0;
  int free_in = 0;
  int prev_cr = 0;

  if(!out_off) {
    errno = EINVAL;
    return -1;
  }

  if(!inbuf || !bufsize) {
    inbuf = malloc(IO_COPY_BUFSIZE);
    bufsize = IO_COPY_BUFSIZE;
    free_in = 1;
    if(!inbuf) {
      return -1;
    }
  }

  outcap = bufsize + 1;
  outbuf = malloc(outcap);
  if(!outbuf) {
    if(free_in) {
      free(inbuf);
    }
    return -1;
  }

  for(;;) {
    ssize_t r = recv(env->data_fd, inbuf, bufsize, 0);
    size_t out_len = 0;

    if(r < 0) {
      if(errno == EINTR) {
        continue;
      }
      goto error;
    }
    if(r == 0) {
      break;
    }

    for(ssize_t i = 0; i < r; i++) {
      unsigned char c = (unsigned char)inbuf[i];

      if(prev_cr) {
        if(c == '\n') {
          outbuf[out_len++] = '\n'; // \r\n -> \n
          prev_cr = 0;
          continue;
        }
        // Emit the swallowed \r
        if(out_len < outcap) {
          outbuf[out_len++] = '\r'; 
        }
        prev_cr = 0;
      }

      if(c == '\r') {
        prev_cr = 1;
        continue; // Swallow \r
      }
      if(out_len < outcap) outbuf[out_len++] = (char)c;
    }

    if(out_len && io_nwrite(fd_out, outbuf, out_len)) {
      goto error;
    }
    *out_off += (off_t)out_len;
  }

  if(prev_cr) {
    outbuf[0] = '\r';
    if(io_nwrite(fd_out, outbuf, 1)) {
      goto error;
    }
    *out_off += 1;
  }

  free(outbuf);
  if(free_in) {
    free(inbuf);
  }
  return 0;

error:
  free(outbuf);
  if(free_in) {
    free(inbuf);
  }
  return -1;
}


/**
 * Close the data connection.
 **/
int
ftp_data_close(ftp_env_t *env) {
  if(env->data_fd < 0) {
    return 0;
  }

  if(!close(env->data_fd)) {
    env->data_fd = -1;
    return 0;
  }
  env->data_fd = -1; // Force reset even on error to prevent double close
  return -1;
}


/**
 * Write a string to the active connection with printf semantics.
 **/
int
ftp_active_printf(ftp_env_t *env, const char *fmt, ...) {
  char buf[0x1000];
  va_list args;

  va_start(args, fmt);
  int n = vsnprintf(buf, sizeof(buf), fmt, args);
  va_end(args);

  if(n < 0) {
    return -1;
  }

  size_t len = (size_t)n;
  if(len >= sizeof(buf)) {
    len = sizeof(buf) - 1;
  }

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

static int
ftp_errno_is_timeout(int e) {
  if(e == EAGAIN
#ifdef EWOULDBLOCK
     || e == EWOULDBLOCK
#endif
#ifdef ETIMEDOUT
     || e == ETIMEDOUT
#endif
  ) {
    return 1;
  }
  return 0;
}

static int
ftp_data_xfer_error_reply(ftp_env_t *env) {
  int e = errno;
  if(ftp_errno_is_timeout(e)) {
    return ftp_active_printf(env, "426 Data connection timed out\r\n");
  }
  errno = e;
  return ftp_perror(env);
}

static int
ftp_data_open_error_reply(ftp_env_t *env) {
  int e = errno;
  if(e == EACCES) {
    return ftp_active_printf(env, "425 Can't open data connection\r\n");
  }
  errno = e;
  return ftp_perror(env);
}


/**
 * Create an absolute path from the current working directory.
 * Returns 0 on success, -1 on error (errno set).
 **/
int
ftp_abspath(ftp_env_t *env, char *abspath, size_t abspath_size,
            const char *path) {
  char buf[PATH_MAX + 1];
  int n;

  if(!env || !abspath || !path || abspath_size < 2) {
    errno = EINVAL;
    return -1;
  }

  if(path[0] != '/') {
    n = snprintf(buf, sizeof(buf), "%s/%s", env->cwd, path);
  } else {
    n = snprintf(buf, sizeof(buf), "%s", path);
  }
  if(n < 0 || (size_t)n >= sizeof(buf)) {
    errno = ENAMETOOLONG;
    return -1;
  }

  if(ftp_normpath(buf, abspath, abspath_size)) {
    return -1;
  }
  return 0;
}

static const char *
ftp_list_path_arg(const char *arg, char *buf, size_t bufsize) {
  const char *p = arg;
  const char *path = NULL;
  size_t path_len = 0;
  int next_is_path = 0;

  while(*p == ' ') {
    p++;
  }

  while(*p) {
    const char *start = p;
    size_t len = 0;

    while(*p && *p != ' ') {
      p++;
      len++;
    }
    while(*p == ' ') {
      p++;
    }

    if(!len) {
      continue;
    }

    if(next_is_path) {
      path = start;
      path_len = len;
      break;
    }

    if(len == 2 && start[0] == '-' && start[1] == '-') {
      next_is_path = 1;
      continue;
    }

    if(start[0] != '-') {
      path = start;
      path_len = len;
    }
  }

  if(!path || !buf || bufsize < 2) {
    return NULL;
  }

  if(path_len >= bufsize) {
    path_len = bufsize - 1;
  }
  memcpy(buf, path, path_len);
  buf[path_len] = '\0';

  return buf;
}


/**
 * Compare two strings case-insensitively.
 **/
int
ftp_strieq(const char *a, const char *b) {
  while(*a && *b) {
    if(tolower((unsigned char)*a) != tolower((unsigned char)*b)) {
      return 0;
    }
    a++;
    b++;
  }
  return *a == '\0' && *b == '\0';
}

static int
ftp_format_mdtm(time_t t, char *buf, size_t bufsize) {
  struct tm tm;

  if(!buf || bufsize < 15) {
    return -1;
  }

  if(!gmtime_r(&t, &tm)) {
    return -1;
  }

  if(snprintf(buf, bufsize, "%04d%02d%02d%02d%02d%02d", tm.tm_year + 1900,
              tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min,
              tm.tm_sec) >= (int)bufsize) {
    return -1;
  }

  return 0;
}

static int
ftp_format_list_time(time_t t, char *buf, size_t bufsize) {
  struct tm tm;
  time_t now;

  // LIST output is typically server-local time (unlike MLSD's UTC "modify"). 
  static const char *mon[] = {"Jan","Feb","Mar","Apr","May","Jun",
                              "Jul","Aug","Sep","Oct","Nov","Dec"};

  if(!buf || bufsize < 14) {
    return -1;
  }

  if(!localtime_r(&t, &tm)) {
    // Fallback to a fixed epoch-ish timestamp rather than garbage. 
    (void)snprintf(buf, bufsize, "Jan  1  1970");
    return 0;
  }

  now = time(NULL);
  long long diff = (long long)now - (long long)t;
  const long long six_months = 180LL * 24LL * 60LL * 60LL;
  const char *mname = mon[(tm.tm_mon >= 0 && tm.tm_mon < 12) ? tm.tm_mon : 0];

  if(diff < 0 || diff > six_months) {
    // Older timestamps: show year like "ls -l".
    (void)snprintf(buf, bufsize, "%s %2d  %4d", mname, tm.tm_mday, tm.tm_year + 1900);
  } else {
    // Recent timestamps: show time.
    (void)snprintf(buf, bufsize, "%s %2d %02d:%02d", mname, tm.tm_mday, tm.tm_hour, tm.tm_min);
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

  env->data_addr.sin_port = 0;
  env->data_addr.sin_addr.s_addr = 0;
  if(env->data_fd >= 0) {
    close(env->data_fd);
    env->data_fd = -1;
  }

  if(getsockname(env->active_fd, (struct sockaddr*)&sockaddr, &sockaddr_len)) {
    return ftp_perror(env);
  }
  addr = sockaddr.sin_addr.s_addr;

  if(env->passive_fd >= 0) {
    close(env->passive_fd);
    env->passive_fd = -1;
  }

  if((env->passive_fd=socket(AF_INET, SOCK_STREAM, 0)) < 0) {
    return ftp_perror(env);
  }

  if(setsockopt(env->passive_fd, SOL_SOCKET, SO_REUSEADDR, &(int){1},
                sizeof(int)) < 0) {
    int ret = ftp_perror(env);
    close(env->passive_fd);
    env->passive_fd = -1;
    return ret;
  }

  memset(&sockaddr, 0, sockaddr_len);
  sockaddr.sin_family = AF_INET;
  sockaddr.sin_addr.s_addr = htonl(INADDR_ANY);
  sockaddr.sin_port = htons(0);

  if(bind(env->passive_fd, (struct sockaddr*)&sockaddr, sockaddr_len) != 0) {
    int ret = ftp_perror(env);
    close(env->passive_fd);
    env->passive_fd = -1;
    return ret;
  }

  if(listen(env->passive_fd, FTP_LISTEN_BACKLOG) != 0) {
    int ret = ftp_perror(env);
    close(env->passive_fd);
    env->passive_fd = -1;
    return ret;
  }

  if(getsockname(env->passive_fd, (struct sockaddr*)&sockaddr, &sockaddr_len)) {
    int ret = ftp_perror(env);
    close(env->passive_fd);
    env->passive_fd = -1;
    return ret;
  }
  port = sockaddr.sin_port;
  uint32_t ip = ntohl(addr);
  uint16_t p  = ntohs(port);

  return ftp_active_printf(env, "227 Entering Passive Mode (%hhu,%hhu,%hhu,%hhu,%hhu,%hhu).\r\n",
    (ip >> 24) & 0xFF, (ip >> 16) & 0xFF, (ip >> 8) & 0xFF, (ip >> 0) & 0xFF,
    (p >> 8) & 0xFF, (p >> 0) & 0xFF);
}


/**
 * Enter extended passive mode.
 **/
int
ftp_cmd_EPSV(ftp_env_t *env, const char *arg) {
  socklen_t sockaddr_len = sizeof(struct sockaddr_in);
  struct sockaddr_in sockaddr;
  uint16_t port = 0;

  env->data_addr.sin_port = 0;
  env->data_addr.sin_addr.s_addr = 0;
  if(env->data_fd >= 0) {
    close(env->data_fd);
    env->data_fd = -1;
  }

  if(env->passive_fd >= 0) {
    close(env->passive_fd);
    env->passive_fd = -1;
  }

  if((env->passive_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
    return ftp_perror(env);
  }

  if(setsockopt(env->passive_fd, SOL_SOCKET, SO_REUSEADDR, &(int){1},
                sizeof(int)) < 0) {
    int ret = ftp_perror(env);
    close(env->passive_fd);
    env->passive_fd = -1;
    return ret;
  }

  memset(&sockaddr, 0, sockaddr_len);
  sockaddr.sin_family = AF_INET;
  sockaddr.sin_addr.s_addr = htonl(INADDR_ANY);
  sockaddr.sin_port = htons(0);

  if(bind(env->passive_fd, (struct sockaddr *)&sockaddr, sockaddr_len) != 0) {
    int ret = ftp_perror(env);
    close(env->passive_fd);
    env->passive_fd = -1;
    return ret;
  }

  if(listen(env->passive_fd, FTP_LISTEN_BACKLOG) != 0) {
    int ret = ftp_perror(env);
    close(env->passive_fd);
    env->passive_fd = -1;
    return ret;
  }

  if(getsockname(env->passive_fd, (struct sockaddr *)&sockaddr,
                 &sockaddr_len)) {
    int ret = ftp_perror(env);
    close(env->passive_fd);
    env->passive_fd = -1;
    return ret;
  }
  port = sockaddr.sin_port;

  return ftp_active_printf(env,
                           "229 Entering Extended Passive Mode (|||%hu|)\r\n",
                           ntohs(port));
}


/**
 * Change the working directory to its parent.
 **/
int
ftp_cmd_CDUP(ftp_env_t *env, const char* arg) {
  char pathbuf[PATH_MAX];

  if(ftp_abspath(env, pathbuf, sizeof(pathbuf), "..")) {
    return ftp_perror(env);
  }
  snprintf(env->cwd, sizeof(env->cwd), "%s", pathbuf);

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
  if(ftp_abspath(env, pathbuf, sizeof(pathbuf), ptr+1)) {
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

  if(ftp_abspath(env, pathbuf, sizeof(pathbuf), arg)) {
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

  if(ftp_abspath(env, pathbuf, sizeof(pathbuf), arg)) {
    return ftp_perror(env);
  }
  if(remove(pathbuf)) {
    return ftp_perror(env);
  }

  return ftp_active_printf(env, "250 File deleted\r\n");
}



/**
 * Buffered data-transfer helpers for directory listings.
 *
 * These reduce copy/paste between LIST/NLST/MLSD and centralize flush/error handling.
 **/
typedef struct ftp_xfer_buf {
  ftp_env_t *env;
  char *buf;
  size_t cap;
  size_t len;
  int free_buf;
  int failed;
} ftp_xfer_buf_t;

static void
ftp_xfer_buf_release(ftp_xfer_buf_t *x) {
  if(x->free_buf && x->buf) {
    free(x->buf);
  }
  x->buf = NULL;
  x->cap = 0;
  x->len = 0;
  x->free_buf = 0;
}

static int
ftp_xfer_write_raw(ftp_xfer_buf_t *x, const void *data, size_t len) {
  if(x->failed) {
    return -1;
  }
  if(io_nwrite(x->env->data_fd, data, len)) {
    (void)ftp_data_xfer_error_reply(x->env);
    x->failed = 1;
    return -1;
  }
  return 0;
}

static int
ftp_xfer_flush(ftp_xfer_buf_t *x) {
  if(x->failed) {
    return -1;
  }
  if(x->len) {
    if(ftp_xfer_write_raw(x, x->buf, x->len)) {
      return -1;
    }
    x->len = 0;
  }
  return 0;
}

static int
ftp_xfer_vprintf(ftp_xfer_buf_t *x, const char *fmt, va_list ap) {
  for(;;) {
    size_t rem;

    if(x->failed) {
      return -1;
    }

    rem = x->cap - x->len;

    va_list aq;
    va_copy(aq, ap);
    int n = vsnprintf(x->buf + x->len, rem, fmt, aq);
    va_end(aq);

    if(n < 0) {
      // Formatting error; let caller decide whether to skip entry.
      return -1;
    }

    if((size_t)n < rem) {
      x->len += (size_t)n;
      return 0;
    }

    // Not enough space -> flush and try again. 
    if(ftp_xfer_flush(x)) {
      return -1;
    }

    // If a single line is larger than the buffer, format into a temp string and write directly. 
    if((size_t)n >= x->cap) {
      size_t need = (size_t)n + 1;
      char *tmp = malloc(need);
      if(!tmp) {
        x->failed = 1;
        return -1;
      }

      va_list ar;
      va_copy(ar, ap);
      int m = vsnprintf(tmp, need, fmt, ar);
      va_end(ar);

      if(m < 0) {
        free(tmp);
        return -1;
      }

      int wr = ftp_xfer_write_raw(x, tmp, (size_t)m);
      free(tmp);
      return wr;
    }

    // else: retry with empty buffer 
  }
}

static int
ftp_xfer_printf(ftp_xfer_buf_t *x, const char *fmt, ...) {
  int rc;
  va_list ap;
  va_start(ap, fmt);
  rc = ftp_xfer_vprintf(x, fmt, ap);
  va_end(ap);
  return rc;
}


/**
* Shared prologue/epilogue for LIST/NLST/MLSD 
**/
static int
ftp_list_xfer_start(ftp_env_t *env, DIR *dir, ftp_xfer_buf_t *x) {
  memset(x, 0, sizeof(*x));
  x->env = env;
  x->buf = env->xfer_buf;
  x->cap = env->xfer_buf_size;
  if(!x->buf || !x->cap) {
    x->cap = FTP_LIST_OUTBUF_SIZE;
    x->buf = malloc(x->cap);
    x->free_buf = 1;
    if(!x->buf) {
      int err = ftp_perror(env);
      closedir(dir);
      return err;
    }
  }

  if(ftp_active_printf(env, "150 Opening data transfer\r\n")) {
    ftp_xfer_buf_release(x);
    closedir(dir);
    return -1;
  }
  if(ftp_data_open(env)) {
    int err = ftp_data_open_error_reply(env);
    ftp_xfer_buf_release(x);
    closedir(dir);
    return err;
  }

  return 0;
}

static int
ftp_list_xfer_finish(ftp_env_t *env, DIR *dir, ftp_xfer_buf_t *x) {
  if(!x->failed) {
    (void)ftp_xfer_flush(x);
  }

  if(ftp_data_close(env)) {
    (void)ftp_perror(env);
    x->failed = 1;
  }

  if(closedir(dir)) {
    (void)ftp_perror(env);
    x->failed = 1;
  }

  ftp_xfer_buf_release(x);

  if(x->failed) {
    return 0;
  }
  return ftp_active_printf(env, "226 Transfer complete\r\n");
}


static int
ftp_join_path(char *dst, size_t dst_sz, const char *dir_path, const char *name) {
  int n;

  if(!dst || dst_sz < 2) {
    errno = ENAMETOOLONG;
    return -1;
  }

  if(dir_path[1] == '\0') {
    n = snprintf(dst, dst_sz, "/%s", name);
  } else {
    n = snprintf(dst, dst_sz, "%s/%s", dir_path, name);
  }

  if(n < 0 || (size_t)n >= dst_sz) {
    errno = ENAMETOOLONG;
    return -1;
  }

  return 0;
}

/**
 * Trasfer a list of files and folder.
 **/
int
ftp_cmd_LIST(ftp_env_t *env, const char *arg) {
  const char *dir_path = NULL;  
  struct dirent *ent;
  struct stat statbuf;
  char timebuf[32];
  char modebuf[20];
  DIR *dir;
  ftp_xfer_buf_t x;

  // Allocate large buffers on Heap to avoid SceLibcInternalHeap error due to stack overflow
  char *argbuf = malloc(PATH_MAX + 1);
  char *list_path = malloc(PATH_MAX + 1);
  char *pathbuf = malloc(PATH_MAX * 3);

   if(!argbuf || !list_path || !pathbuf) {
    if(argbuf)
      free(argbuf);
    if(list_path)
      free(list_path);
    if(pathbuf)
      free(pathbuf);
    return ftp_perror(env);
  }


  dir_path = ftp_list_path_arg(arg, argbuf, PATH_MAX + 1);
  if(dir_path) {
    if(ftp_abspath(env, list_path, PATH_MAX + 1, dir_path)) {
      free(argbuf);
      free(list_path);
      free(pathbuf);
      return ftp_perror(env);
    }
  } else {
    if(ftp_normpath(env->cwd, list_path, PATH_MAX + 1)) {
      free(argbuf);
      free(list_path);
      free(pathbuf);
      return ftp_perror(env);
    }
  }
  dir_path = list_path;

  if(!(dir = opendir(dir_path))) {
    free(argbuf);
    free(list_path);
    free(pathbuf);
    return ftp_perror(env);
  }

  int err = ftp_list_xfer_start(env, dir, &x);
  if(err) {
    free(argbuf);
    free(list_path);
    free(pathbuf);
    return err; // start() already replied and closed DIR on error
  }

#if defined(AT_SYMLINK_NOFOLLOW) && !defined(__ORBIS__)
  int dir_fd = dirfd(dir);
#endif

  int readdir_errno = 0;

  for(;;) {
    int have_path = 0;
    int stat_rc  = -1;

    errno = 0;
    ent = readdir(dir);
    if(!ent) {
      readdir_errno = errno;
      break;
    }


#if defined(AT_SYMLINK_NOFOLLOW) && !defined(__ORBIS__)
    if(dir_fd >= 0) {
      stat_rc = fstatat(dir_fd, ent->d_name, &statbuf, AT_SYMLINK_NOFOLLOW);
    } 
#endif

    if(stat_rc != 0) {
      if(ftp_join_path(pathbuf, PATH_MAX * 3, dir_path, ent->d_name) != 0) {
        continue;
      }
      have_path = 1;
#ifdef AT_SYMLINK_NOFOLLOW
      if(lstat(pathbuf, &statbuf) != 0)
#else
      if(stat(pathbuf, &statbuf) != 0)
#endif
      {
        continue;
      }
    }

    if(env->self2elf && S_ISREG(statbuf.st_mode)) {
      if(!have_path) {
        if(ftp_join_path(pathbuf, PATH_MAX * 3, dir_path, ent->d_name) != 0) {
          continue;
        }
        have_path = 1;
      }
      size_t elf_size = self_is_valid(pathbuf);
      if(elf_size) {
        statbuf.st_size = elf_size;
      }
    }

    ftp_mode_string(statbuf.st_mode, modebuf);
    if(ftp_format_list_time(statbuf.st_mtime, timebuf, sizeof(timebuf))) {
      continue;
    }

    if(ftp_xfer_printf(&x,
                       "%s %" PRIuMAX " %" PRIuMAX " %" PRIuMAX
                       " %" PRIuMAX " %s %s\r\n",
                       modebuf, (uintmax_t)statbuf.st_nlink,
                       (uintmax_t)statbuf.st_uid,
                       (uintmax_t)statbuf.st_gid,
                       (uintmax_t)statbuf.st_size, timebuf, ent->d_name)) {
      if(x.failed) {
        break;
      }
      // formatting error -> skip entry
      continue;
    }

    if(x.failed) {
      break;
    }
  }

  if(readdir_errno && !x.failed) {
    errno = readdir_errno;
    (void)ftp_perror(env);
    x.failed = 1;
  }

  free(argbuf);
  free(list_path);
  free(pathbuf);
  return ftp_list_xfer_finish(env, dir, &x);
}


/**
 * Transfer a list of file names (no stat).
 **/
int
ftp_cmd_NLST(ftp_env_t *env, const char *arg) {
  const char *dir_path = NULL;
  struct dirent *ent;
  DIR *dir;
  ftp_xfer_buf_t x;
  char *argbuf = malloc(PATH_MAX + 1);
  char *list_path = malloc(PATH_MAX + 1);

   if(!argbuf || !list_path) {
    if(argbuf)
      free(argbuf);
    if(list_path)
      free(list_path);
    return ftp_perror(env);
  }

  dir_path = ftp_list_path_arg(arg, argbuf, PATH_MAX + 1);
  if(dir_path) {
    if(ftp_abspath(env, list_path, PATH_MAX + 1, dir_path)) {
      free(argbuf);
      free(list_path);
      return ftp_perror(env);
    }
  } else {
    if(ftp_normpath(env->cwd, list_path, PATH_MAX + 1)) {
      free(argbuf);
      free(list_path);
      return ftp_perror(env);
    }
  }
  dir_path = list_path;

  if(!(dir = opendir(dir_path))) {
    free(argbuf);
    free(list_path);
    return ftp_perror(env);
  }

  int err = ftp_list_xfer_start(env, dir, &x);
  if(err) {
    free(argbuf);
    free(list_path);
    return err; // start() already replied and closed DIR on error 
  }

  int readdir_errno = 0;

  for(;;) {
    errno = 0;
    ent = readdir(dir);
    if(!ent) {
      readdir_errno = errno;
      break;
    }

    if(ftp_xfer_printf(&x, "%s\r\n", ent->d_name)) {
      if(x.failed) {
        break;
      }
      // shouldn't happen; but if it does, skip entry 
      continue;
    }

    if(x.failed) {
      break;
    }
  }

  if(readdir_errno && !x.failed) {
    errno = readdir_errno;
    (void)ftp_perror(env);
    x.failed = 1;
  }
  
  free(argbuf);
  free(list_path);
  return ftp_list_xfer_finish(env, dir, &x);
}


/**
 * Transfer a machine-readable list.
 **/
int
ftp_cmd_MLSD(ftp_env_t *env, const char *arg) {
  const char *dir_path = NULL;
  struct dirent *ent;
  struct stat statbuf;
  DIR *dir;
  ftp_xfer_buf_t x;

  // Allocate large buffers on Heap to avoid SceLibcInternalHeap error due to stack overflow
  char *argbuf = malloc(PATH_MAX + 1);
  char *list_path = malloc(PATH_MAX + 1);
  char *pathbuf = malloc(PATH_MAX * 3);

   if(!argbuf || !list_path || !pathbuf) {
    if(argbuf)
      free(argbuf);
    if(list_path)
      free(list_path);
    if(pathbuf)
      free(pathbuf);
    return ftp_perror(env);
  }


  dir_path = ftp_list_path_arg(arg, argbuf, PATH_MAX + 1);
  if(dir_path) {
    if(ftp_abspath(env, list_path, PATH_MAX + 1, dir_path)) {
      free(argbuf);
      free(list_path);
      free(pathbuf);
      return ftp_perror(env);
    }
  } else {
    if(ftp_normpath(env->cwd, list_path, PATH_MAX + 1)) {
      free(argbuf);
      free(list_path);
      free(pathbuf);
      return ftp_perror(env);
    }
  }
  dir_path = list_path;

  if(!(dir = opendir(dir_path))) {
    free(argbuf);
    free(list_path);
    free(pathbuf);
    return ftp_perror(env);
  }

  int err = ftp_list_xfer_start(env, dir, &x);
  if(err) {
    free(argbuf);
    free(list_path);
    free(pathbuf);
    return err; // start() already replied and closed DIR on error
  }

#if defined(AT_SYMLINK_NOFOLLOW) && !defined(__ORBIS__)
  int dir_fd = dirfd(dir);
#endif

  int readdir_errno = 0;

  for(;;) {
    int have_path = 0;
    int stat_rc  = -1;
    const char *type;
    uintmax_t size;
    char timebuf[32];

    errno = 0;
    ent = readdir(dir);
    if(!ent) {
      readdir_errno = errno;
      break;
    }

#if defined(AT_SYMLINK_NOFOLLOW) && !defined(__ORBIS__)
    if(dir_fd >= 0) {
      stat_rc = fstatat(dir_fd, ent->d_name, &statbuf, AT_SYMLINK_NOFOLLOW);
    } 
#endif

    if(stat_rc != 0) {
      if(ftp_join_path(pathbuf, PATH_MAX * 3, dir_path, ent->d_name) != 0) {
        continue;
      }
      have_path = 1;
#ifdef AT_SYMLINK_NOFOLLOW
      if(lstat(pathbuf, &statbuf) != 0)
#else
      if(stat(pathbuf, &statbuf) != 0)
#endif
      {
        continue;
      }
    }

    if(ent->d_name[0] == '.' && ent->d_name[1] == '\0') {
      type = "type=cdir;";
    } else if(ent->d_name[0] == '.' && ent->d_name[1] == '.' &&
              ent->d_name[2] == '\0') {
      type = "type=pdir;";
    } else if(S_ISDIR(statbuf.st_mode)) {
      type = "type=dir;";
    } else if(S_ISREG(statbuf.st_mode)) {
      type = "type=file;";
    } else if(S_ISLNK(statbuf.st_mode)) {
      type = "type=OS.unix=symlink;";
    } else if(S_ISCHR(statbuf.st_mode)) {
      type = "type=OS.unix=chardev;";
    } else if(S_ISBLK(statbuf.st_mode)) {
      type = "type=OS.unix=blockdev;";
    } else if(S_ISFIFO(statbuf.st_mode)) {
      type = "type=OS.unix=fifo;";
    } else if(S_ISSOCK(statbuf.st_mode)) {
      type = "type=OS.unix=sock;";
    } else {
      type = "type=unknown;";
    }

    size = (uintmax_t)statbuf.st_size;
    if(env->self2elf && S_ISREG(statbuf.st_mode)) {
      if(!have_path) {
        if(ftp_join_path(pathbuf,  PATH_MAX * 3, dir_path, ent->d_name) != 0) {
          continue;
        }
        have_path = 1;
      }
      size_t elf_size = self_is_valid(pathbuf);
      if(elf_size) {
        size = (uintmax_t)elf_size;
      }
    }

    if(ftp_format_mdtm(statbuf.st_mtime, timebuf, sizeof(timebuf))) {
      continue;
    }

    if(ftp_xfer_printf(&x,
                       "%ssize=%" PRIuMAX ";modify=%s; %s\r\n",
                       type, size, timebuf, ent->d_name)) {
      if(x.failed) {
        break;
      }
      continue;
    }

    if(x.failed) {
      break;
    }
  }

  if(readdir_errno && !x.failed) {
    errno = readdir_errno;
    (void)ftp_perror(env);
    x.failed = 1;
  }
  
  free(argbuf);
  free(list_path);
  free(pathbuf);
  return ftp_list_xfer_finish(env, dir, &x);
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

  if(ftp_abspath(env, pathbuf, sizeof(pathbuf), arg)) {
    return ftp_perror(env);
  }
  if(mkdir(pathbuf, 0777)) {
    return ftp_perror(env);
  }

  return ftp_active_printf(env, "257 Directory created\r\n");
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
  struct in_addr in_addr;
  struct sockaddr_in ctrl_addr;
  socklen_t ctrl_len;
  uint32_t s_addr_host;
  uint16_t port_host;

  if(sscanf(arg, "%hhu,%hhu,%hhu,%hhu,%hhu,%hhu",
	    addr, addr+1, addr+2, addr+3, addr+4, addr+5) != 6) {
    return ftp_active_printf(env, "501 Usage: PORT <addr>\r\n");
  }

  s_addr_host = ((uint32_t)addr[0] << 24) | ((uint32_t)addr[1] << 16) |
                ((uint32_t)addr[2] << 8) | (uint32_t)addr[3];
  in_addr.s_addr = htonl(s_addr_host);
  port_host = (uint16_t)(((uint16_t)addr[4] << 8) | (uint16_t)addr[5]);

  memset(&ctrl_addr, 0, sizeof(ctrl_addr));
  ctrl_len = sizeof(ctrl_addr);
  if(getpeername(env->active_fd, (struct sockaddr *)&ctrl_addr, &ctrl_len) !=
     0) {
    return ftp_active_printf(env, "500 Illegal PORT command\r\n");
  }
  if(ctrl_addr.sin_family != AF_INET ||
     ctrl_addr.sin_addr.s_addr != in_addr.s_addr) {
    return ftp_active_printf(env, "500 Illegal PORT command\r\n");
  }

  if(env->passive_fd >= 0) {
    close(env->passive_fd);
    env->passive_fd = -1;
  }

  if(env->data_fd >= 0) {
    close(env->data_fd);
    env->data_fd = -1;
  }

  if((env->data_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
    return ftp_perror(env);
  }

  env->data_addr.sin_family = AF_INET;
  env->data_addr.sin_addr = in_addr;
  env->data_addr.sin_port = htons(port_host);

  return ftp_active_printf(env, "200 PORT command successful.\r\n");
}

/**
 * Establish a data connection with client (extended).
 **/
int
ftp_cmd_EPRT(ftp_env_t *env, const char *arg) {
  char addrbuf[INET_ADDRSTRLEN] = {0};
  char portbuf[16] = {0};
  char proto[8] = {0};
  struct sockaddr_in ctrl_addr;
  socklen_t ctrl_len;
  char delim;
  char *p1;
  char *p2;
  char *p3;
  unsigned long port_ul;
  struct in_addr in_addr;

  if(!arg[0]) {
    return ftp_active_printf(
      env, "501 Usage: EPRT <d><af><d><addr><d><port><d>\r\n");
  }

  delim = arg[0];
  p1 = strchr(arg + 1, delim);
  if(!p1) {
    return ftp_active_printf(
      env, "501 Usage: EPRT <d><af><d><addr><d><port><d>\r\n");
  }
  p2 = strchr(p1 + 1, delim);
  if(!p2) {
    return ftp_active_printf(
      env, "501 Usage: EPRT <d><af><d><addr><d><port><d>\r\n");
  }
  p3 = strchr(p2 + 1, delim);
  if(!p3) {
    return ftp_active_printf(
      env, "501 Usage: EPRT <d><af><d><addr><d><port><d>\r\n");
  }

  snprintf(proto, sizeof(proto), "%.*s", (int)(p1 - (arg + 1)), arg + 1);
  snprintf(addrbuf, sizeof(addrbuf), "%.*s", (int)(p2 - (p1 + 1)), p1 + 1);
  snprintf(portbuf, sizeof(portbuf), "%.*s", (int)(p3 - (p2 + 1)), p2 + 1);

  if(strcmp(proto, "1")) {
    return ftp_active_printf(env, "522 Network protocol not supported\r\n");
  }

  if(inet_pton(AF_INET, addrbuf, &in_addr) != 1) {
    return ftp_active_printf(
      env, "501 Usage: EPRT <d><af><d><addr><d><port><d>\r\n");
  }

  memset(&ctrl_addr, 0, sizeof(ctrl_addr));
  ctrl_len = sizeof(ctrl_addr);
  if(getpeername(env->active_fd, (struct sockaddr *)&ctrl_addr, &ctrl_len) !=
     0 || ctrl_addr.sin_family != AF_INET ||
     ctrl_addr.sin_addr.s_addr != in_addr.s_addr) {
    return ftp_active_printf(env, "500 Illegal EPRT command\r\n");
  }
  
  port_ul = strtoul(portbuf, NULL, 10);
  if(!port_ul || port_ul > 65535) {
    return ftp_active_printf(
      env, "501 Usage: EPRT <d><af><d><addr><d><port><d>\r\n");
  }

  if(env->passive_fd >= 0) {
    close(env->passive_fd);
    env->passive_fd = -1;
  }
  if(env->data_fd >= 0) {
    close(env->data_fd);
    env->data_fd = -1;
  }

  if((env->data_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
    return ftp_perror(env);
  }

  env->data_addr.sin_family = AF_INET;
  env->data_addr.sin_addr = in_addr;
  env->data_addr.sin_port = htons((uint16_t)port_ul);

  return ftp_active_printf(env, "200 EPRT command successful.\r\n");
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
  char *end = NULL;
  long long off = 0;

  if(env->type == 'A') {
    env->data_offset = 0;
    env->data_offset_is_rest = 0;
    return ftp_active_printf(env, "504 REST not supported in ASCII mode\r\n");
  }

  if(!arg[0]) {
    return ftp_active_printf(env, "501 Usage: REST <OFFSET>\r\n");
  }

  errno = 0;
  off = strtoll(arg, &end, 10);
  if(errno || end == arg) {
    return ftp_active_printf(env, "501 Usage: REST <OFFSET>\r\n");
  }
  if(*end || off < 0 || (off_t)off != off) {
    return ftp_active_printf(env, "501 Usage: REST <OFFSET>\r\n");
  }

  env->data_offset = (off_t)off;

    env->data_offset_is_rest = 1;
  return ftp_active_printf(env, "350 REST OK\r\n");
}


/**
 * Retreive data from a given file.
 **/
static int
ftp_cmd_RETR_fd(ftp_env_t *env, int fd) {
  off_t off = env->data_offset;
  int is_rest = env->data_offset_is_rest;
  env->data_offset = 0;
  env->data_offset_is_rest = 0;
  struct stat st;
  size_t remaining;
  int err = 0;

  if(env->type == 'A' && off != 0 && is_rest) {
    return ftp_active_printf(env, "504 REST not supported in ASCII mode\r\n");
  }

  if(fstat(fd, &st)) {
    return ftp_perror(env);
  }
  if(lseek(fd, off, SEEK_SET) < 0) {
    return ftp_perror(env);
  }

  if(off >= st.st_size) {
    remaining = 0;
  } else {
    remaining = (size_t)(st.st_size - off);
  }

  if(ftp_active_printf(env, "150 Starting data transfer\r\n")) {
    return -1;
  }

  if(ftp_data_open(env)) {
    return ftp_data_open_error_reply(env);
  }

  if(env->type == 'A') {
    if(ftp_copy_ascii_out(env, fd)) {
      err = ftp_data_xfer_error_reply(env);
      ftp_data_close(env);
      return err;
    }
  } else if(remaining) {
    int one = 1;
    if(remaining < 1460) {  // Typical MSS size
#ifdef TCP_NODELAY
      (void)setsockopt(env->data_fd, IPPROTO_TCP, TCP_NODELAY, &one,
                       sizeof(one));
#endif
    } else if(remaining >= 128*1024) {
#ifdef TCP_NOPUSH
      (void)setsockopt(env->data_fd, IPPROTO_TCP, TCP_NOPUSH, &one,
                       sizeof(one));
#endif
    }

#ifdef IO_USE_SENDFILE
    if(io_sendfile(fd, env->data_fd, off, remaining)) {
      err = ftp_data_xfer_error_reply(env);
      ftp_data_close(env);
      return err;
    }
#else

    if(env->xfer_buf && env->xfer_buf_size) {
      if(io_ncopy_buf(fd, env->data_fd, remaining, env->xfer_buf,
                      env->xfer_buf_size)) {
        err = ftp_data_xfer_error_reply(env);
        ftp_data_close(env);
        return err;
      }
    } else if(io_ncopy(fd, env->data_fd, remaining)) {
      err = ftp_data_xfer_error_reply(env);
      ftp_data_close(env);
      return err;
    }
#endif
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
  if(self_extract_elf_ex(fd, fileno(tmpf), env->self_verify)) {
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

  if(ftp_abspath(env, path, sizeof(path), arg)) {
    return ftp_perror(env);
  }
  if((fd=open(path, O_RDONLY, 0)) < 0) {
    return ftp_perror(env);
  }

  if(env->self2elf && self_is_valid(path)) {
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

  if(ftp_abspath(env, pathbuf, sizeof(pathbuf), arg)) {
    return ftp_perror(env);
  }
  if(rmdir(pathbuf)) {
    return ftp_perror(env);
  }

  return ftp_active_printf(env, "250 Directory deleted\r\n");
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

  if(ftp_abspath(env, env->rename_path, sizeof(env->rename_path), arg)) {
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

  if(ftp_abspath(env, pathbuf, sizeof(pathbuf), arg)) {
    return ftp_perror(env);
  }
  if(rename(env->rename_path, pathbuf)) {
    return ftp_perror(env);
  }

  return ftp_active_printf(env, "250 Path renamed\r\n");
}


/**
 * Obtain the size of a given file.
 **/
int
ftp_cmd_SIZE(ftp_env_t *env, const char* arg) {
  char pathbuf[PATH_MAX];
  struct stat st = {0};

  if(env->type == 'A') {
    return ftp_active_printf(env, "504 SIZE not supported in ASCII mode\r\n");
  }

  if(!arg[0]) {
    return ftp_active_printf(env, "501 Usage: SIZE <FILENAME>\r\n");
  }

  if(ftp_abspath(env, pathbuf, sizeof(pathbuf), arg)) {
    return ftp_perror(env);
  }

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
  int is_rest = env->data_offset_is_rest;
  char pathbuf[PATH_MAX];
  void *readbuf = env->xfer_buf;
  size_t bufsize = env->xfer_buf_size;
  int err = 0;
  int free_buf = 0;
  ssize_t len;
  struct stat st;
  int flags = O_WRONLY;
#ifdef O_CLOEXEC
  flags |= O_CLOEXEC;
#endif
#ifdef O_NOFOLLOW
  flags |= O_NOFOLLOW;
#endif
  int fd;

  env->data_offset = 0;
  env->data_offset_is_rest = 0;
  if(!arg[0]) {
    return ftp_active_printf(env, "501 Usage: STOR <FILENAME>\r\n");
  }

  if(env->type == 'A' && off != 0 && is_rest) {
    env->data_offset = 0;
    return ftp_active_printf(env, "504 REST not supported in ASCII mode\r\n");
  }

  if(ftp_abspath(env, pathbuf, sizeof(pathbuf), arg)) {
    return ftp_perror(env);
  }
  // Reject symlinks and non-regular files as upload targets.
  // (If you want to allow symlinks, remove the lstat() block below.)
#ifdef S_IFLNK
  {
    struct stat lst;
    if(lstat(pathbuf, &lst) == 0) {
      if(S_ISLNK(lst.st_mode)) {
        return ftp_active_printf(env, "550 Symlinks are not allowed\r\n");
      }
    } else if(errno != ENOENT) {
      return ftp_perror(env);
    }
  }
#endif
  if(stat(pathbuf, &st) == 0) {
    if(!S_ISREG(st.st_mode)) {
      return ftp_active_printf(env, "550 Not a regular file\r\n");
    }
  } else if(errno != ENOENT) {
    return ftp_perror(env);
  }

  if(off == 0) {
    flags |= O_CREAT | O_TRUNC;
  }

  if((fd = open(pathbuf, flags, 0777)) < 0) {
    return ftp_perror(env);
  }

  if(off > 0) {
    if(fstat(fd, &st)) {
      err = ftp_perror(env);
      close(fd);
      return err;
    }
    if(!S_ISREG(st.st_mode)) {
      close(fd);
      return ftp_active_printf(env, "550 Not a regular file\r\n");
    }
    if(off > st.st_size) {
      close(fd);
      return ftp_active_printf(env, "551 Restart point beyond EOF\r\n");
    }
  }

  if(lseek(fd, off, SEEK_SET) < 0) {
    err = ftp_perror(env);
    close(fd);
    return err;
  }

  if(ftp_active_printf(env, "150 Opening data transfer\r\n")) {
    close(fd);
    return -1;
  }

  if(ftp_data_open(env)) {
    err = ftp_data_open_error_reply(env);
    close(fd);
    return err;
  }

  if(!readbuf || !bufsize) {
    readbuf = malloc(IO_COPY_BUFSIZE);
    bufsize = IO_COPY_BUFSIZE;
    free_buf = 1;
    if(!readbuf) {
      err = ftp_perror(env);
      ftp_data_close(env);
      close(fd);
      return err;
    }
  }

  if(env->type == 'A') {
    if(ftp_copy_ascii_in(env, fd, &off)) {
      err = ftp_data_xfer_error_reply(env);
      ftp_data_close(env);
      if(free_buf) {
        free(readbuf);
      }
      close(fd);
      return err;
    }
  } else {
    while((len = ftp_data_read(env, readbuf, bufsize)) > 0) {
      if(io_nwrite(fd, readbuf, (size_t)len)) {
        err = ftp_perror(env);
        ftp_data_close(env);
        if(free_buf) {
          free(readbuf);
        }
        close(fd);
        return err;
      }
      off += len;
    }
  }

  if(env->type != 'A' && len < 0) {
    err = ftp_data_xfer_error_reply(env);
    ftp_data_close(env);
    if(free_buf) {
      free(readbuf);
    }
    close(fd);
    return err;
  }

  if(free_buf) {
    free(readbuf);
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

  env->data_offset = 0;
  env->data_offset_is_rest = 0;

  if(ftp_abspath(env, pathbuf, sizeof(pathbuf), arg)) {
    return ftp_perror(env);
  }

#ifdef S_IFLNK
  {
    struct stat lst;
    if(lstat(pathbuf, &lst) == 0) {
      if(S_ISLNK(lst.st_mode)) {
        return ftp_active_printf(env, "550 Symlinks are not allowed\r\n");
      }
    } else if(errno != ENOENT) {
      return ftp_perror(env);
    }
  }
#endif

  if(stat(pathbuf, &statbuf) == 0) {
    if(!S_ISREG(statbuf.st_mode)) {
      return ftp_active_printf(env, "550 Not a regular file\r\n");
    }
    env->data_offset = statbuf.st_size;
  } else {
    if(errno != ENOENT) {
      return ftp_perror(env);
    }
    env->data_offset = 0;
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
  switch(arg[0]) {
#ifdef DISABLE_ASCII_MODE
  case 'A':
  case 'I':
    env->type = 'I';
    return ftp_active_printf(env, "200 Type set to I\r\n");
#else
  case 'A':
    env->data_offset = 0;
    env->type = 'A';
    return ftp_active_printf(env, "200 Type set to %c\r\n", env->type);
  case 'I':
    env->type = 'I';
    return ftp_active_printf(env, "200 Type set to %c\r\n", env->type);
#endif
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
 * Specify user password.
 **/
int
ftp_cmd_PASS(ftp_env_t *env, const char *arg) {
  (void)arg;
  return ftp_active_printf(env, "230 User logged in\r\n");
}

/**
 * Feature list.
 **/
int
ftp_cmd_FEAT(ftp_env_t *env, const char *arg) {
  (void)arg;
  return ftp_active_printf(env,
                           "211-Features:\r\n"
                           " MLST type*;size*;modify*;\r\n"
                           " MLSD\r\n"
                           " UTF8\r\n"
                           " REST STREAM\r\n"
                           "211 End\r\n");
}

/**
 * Set options.
 **/
int
ftp_cmd_OPTS(ftp_env_t *env, const char *arg) {
  char opt[16];
  char val[16];
  size_t len = 0;

  if(!*arg) {
    return ftp_active_printf(env, "501 Usage: OPTS UTF8 ON\r\n");
  }

  while(*arg && *arg != ' ' && len + 1 < sizeof(opt)) {
    opt[len++] = *arg++;
  }
  opt[len] = '\0';

  while(*arg == ' ') {
    arg++;
  }

  len = 0;
  while(*arg && *arg != ' ' && len + 1 < sizeof(val)) {
    val[len++] = *arg++;
  }
  val[len] = '\0';

  if(ftp_strieq(opt, "UTF8")) {
    if(!val[0] || ftp_strieq(val, "ON")) {
      return ftp_active_printf(env, "200 UTF8 enabled\r\n");
    }
    if(ftp_strieq(val, "OFF")) {
      return ftp_active_printf(env, "200 UTF8 disabled\r\n");
    }
    return ftp_active_printf(env, "501 Usage: OPTS UTF8 ON\r\n");
  }

  return ftp_active_printf(env, "504 Option not supported\r\n");
}

/**
 * Return modification time.
 **/
int
ftp_cmd_MDTM(ftp_env_t *env, const char *arg) {
  char pathbuf[PATH_MAX];
  char timebuf[32];
  struct stat st;

  if(!arg[0]) {
    return ftp_active_printf(env, "501 Usage: MDTM <FILENAME>\r\n");
  }

  if(ftp_abspath(env, pathbuf, sizeof(pathbuf), arg)) {
    return ftp_perror(env);
  }
  if(stat(pathbuf, &st)) {
    return ftp_perror(env);
  }
  if(ftp_format_mdtm(st.st_mtime, timebuf, sizeof(timebuf))) {
    return ftp_active_printf(env, "550 MDTM failed\r\n");
  }

  return ftp_active_printf(env, "213 %s\r\n", timebuf);
}

/**
 * Return machine-readable info for one path.
 **/
int
ftp_cmd_MLST(ftp_env_t *env, const char *arg) {
  char pathbuf[PATH_MAX];
  char namebuf[PATH_MAX + 1];
  char timebuf[32];
  struct stat st;
  const char *name = NULL;
  const char *type = "type=unknown;";
  int is_cdir = 0;
  int is_pdir = 0;
  uintmax_t size = 0;
  const char *end;
  size_t name_len = 0;

  if(!*arg) {
    end = arg;
  } else {
    end = arg + strlen(arg);
  }
  while(end > arg && end[-1] == ' ') {
    end--;
  }
  name_len = (size_t)(end - arg);

  if(name_len) {
    if(name_len >= sizeof(namebuf)) {
      name_len = sizeof(namebuf) - 1;
    }
    memcpy(namebuf, arg, name_len);
    namebuf[name_len] = '\0';
    if(ftp_abspath(env, pathbuf, sizeof(pathbuf), namebuf)) {
      return ftp_perror(env);
    }
    name = namebuf;
  } else {
    if(ftp_normpath(env->cwd, pathbuf, sizeof(pathbuf))) {
      return ftp_perror(env);
    }
    name = pathbuf;
  }

  if(name && name[0] == '.' && name[1] == '\0') {
    is_cdir = 1;
  } else if(name && name[0] == '.' && name[1] == '.' && name[2] == '\0') {
    is_pdir = 1;
  }

  if(stat(pathbuf, &st)) {
    return ftp_perror(env);
  }

  if(is_cdir) {
    type = "type=cdir;";
  } else if(is_pdir) {
    type = "type=pdir;";
  } else if(S_ISDIR(st.st_mode)) {
    type = "type=dir;";
  } else if(S_ISREG(st.st_mode)) {
    type = "type=file;";
  } else if(S_ISLNK(st.st_mode)) {
    type = "type=link;";
  }

  if(env->self2elf && S_ISREG(st.st_mode)) {
    size_t elf_size = self_is_valid(pathbuf);
    size = elf_size ? (uintmax_t)elf_size : (uintmax_t)st.st_size;
  } else {
    size = (uintmax_t)st.st_size;
  }

  if(ftp_format_mdtm(st.st_mtime, timebuf, sizeof(timebuf))) {
    return ftp_active_printf(env, "550 MLST failed\r\n");
  }

  if(name[0] == '/' && name[1] == '\0') {
    name = "/";
  }

  if(ftp_active_printf(env, "250-Listing\r\n")) {
    return -1;
  }
  if(ftp_active_printf(env, " %ssize=%" PRIuMAX ";modify=%s; %s\r\n", type,
                       size, timebuf, name)) {
    return -1;
  }
  return ftp_active_printf(env, "250 End\r\n");
}

/**
 * Status info.
 **/
int
ftp_cmd_STAT(ftp_env_t *env, const char *arg) {
  (void)arg;
  if(ftp_active_printf(env, "211-FTP server status:\r\n")) {
    return -1;
  }
  if(ftp_active_printf(env, " CWD %s\r\n", env->cwd)) {
    return -1;
  }
  return ftp_active_printf(env, "211 End\r\n");
}

/**
 * Help.
 **/
int
ftp_cmd_HELP(ftp_env_t *env, const char *arg) {
  (void)arg;
  return ftp_active_printf(env,
                           "214-Commands:\r\n"
                           " USER PASS PWD CWD CDUP TYPE SIZE MDTM\r\n"
                           " LIST NLST MLSD MLST RETR STOR APPE\r\n"
                           " DELE RMD MKD RNFR RNTO REST\r\n"
                           " PASV PORT EPSV EPRT SYST NOOP QUIT\r\n"
                           "214 End\r\n");
}

/**
 * Transfer mode.
 **/
int
ftp_cmd_MODE(ftp_env_t *env, const char *arg) {
  (void)env;
  if(!arg[0]) {
    return ftp_active_printf(env, "501 Usage: MODE S\r\n");
  }
  if(arg[0] == 'S' || arg[0] == 's') {
    return ftp_active_printf(env, "200 Mode set to S\r\n");
  }
  return ftp_active_printf(env, "504 MODE not supported\r\n");
}

/**
 * File structure.
 **/
int
ftp_cmd_STRU(ftp_env_t *env, const char *arg) {
  (void)env;
  if(!arg[0]) {
    return ftp_active_printf(env, "501 Usage: STRU F\r\n");
  }
  if(arg[0] == 'F' || arg[0] == 'f') {
    return ftp_active_printf(env, "200 Structure set to F\r\n");
  }
  return ftp_active_printf(env, "504 STRU not supported\r\n");
}

/**
 * Allocate storage (no-op).
 **/
int
ftp_cmd_ALLO(ftp_env_t *env, const char *arg) {
  (void)arg;
  return ftp_active_printf(env, "200 ALLO OK\r\n");
}

/**
 * Abort transfer.
 **/
int
ftp_cmd_ABOR(ftp_env_t *env, const char *arg) {
  (void)arg;
  if(env->data_fd >= 0) {
    close(env->data_fd);
    env->data_fd = -1;
    env->data_offset = 0;
    if(ftp_active_printf(env,
                         "426 Data connection closed; transfer aborted\r\n")) {
      return -1;
    }
    return ftp_active_printf(env, "226 Abort successful\r\n");
  }

  env->data_offset = 0;
  return ftp_active_printf(env, "225 No transfer to abort\r\n");
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
    return ftp_active_printf(env, "200 SELF transfer mode enabled\r\n");
  } else {
    return ftp_active_printf(env, "200 SELF transfer mode disabled\r\n");
  }
}

/**
 * Toggle SELF digest verification.
 **/
int
ftp_cmd_SELFCHK(ftp_env_t *env, const char *arg) {
  if(arg[0]) {
    char *end = NULL;
    long val = strtol(arg, &end, 10);
    if(end == arg || (*end && *end != ' ')) {
      return ftp_active_printf(env, "501 Usage: SCHK <0|1>\r\n");
    }
    env->self_verify = val ? 1 : 0;
  } else {
    env->self_verify = !env->self_verify;
  }

  if(env->self_verify) {
    return ftp_active_printf(env, "200 SELF digest verification enabled\r\n");
  } else {
    return ftp_active_printf(env, "200 SELF digest verification disabled\r\n");
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
