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
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>

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
ftp_mode_string(mode_t mode, char *buf)
{
  char c, d;
  int i, bit;

  buf[10] = 0;
  for (i = 0; i < 9; i++)
  {
    bit = mode & (1 << i);
    c = i % 3;
    if (!c && (mode & (1 << ((d = i / 3) + 9))))
    {
      c = "tss"[(int)d];
      if (!bit)
        c &= ~0x20;
    }
    else
      c = bit ? "xwr"[(int)c] : '-';
    buf[9 - i] = c;
  }

  if (S_ISDIR(mode))
    c = 'd';
  else if (S_ISBLK(mode))
    c = 'b';
  else if (S_ISCHR(mode))
    c = 'c';
  else if (S_ISLNK(mode))
    c = 'l';
  else if (S_ISFIFO(mode))
    c = 'p';
  else if (S_ISSOCK(mode))
    c = 's';
  else
    c = '-';
  *buf = c;
}

static void
ftp_normpath(const char *path, char *out, size_t out_size)
{
  size_t stack[PATH_MAX / 2 + 2];
  size_t sp = 0;
  size_t len = 1;
  const char *p = path;

  if (!out_size)
  {
    return;
  }

  out[0] = '/';
  out[1] = '\0';
  if (out_size < 2)
  {
    return;
  }

  while (*p == '/')
  {
    p++;
  }

  while (*p)
  {
    const char *start = p;
    size_t comp_len = 0;

    while (*p && *p != '/')
    {
      p++;
      comp_len++;
    }
    while (*p == '/')
    {
      p++;
    }

    if (!comp_len || (comp_len == 1 && start[0] == '.'))
    {
      continue;
    }

    if (comp_len == 2 && start[0] == '.' && start[1] == '.')
    {
      if (sp > 0)
      {
        len = stack[--sp];
        out[len] = '\0';
      }
      else
      {
        len = 1;
        out[1] = '\0';
      }
      continue;
    }

    size_t prelen = len;
    if (len > 1)
    {
      if (len + 1 >= out_size)
      {
        break;
      }
      out[len++] = '/';
    }

    if (len + comp_len >= out_size)
    {
      comp_len = out_size - 1 - len;
    }
    if (!comp_len)
    {
      out[len] = '\0';
      break;
    }

    memcpy(out + len, start, comp_len);
    len += comp_len;
    out[len] = '\0';

    if (sp < (sizeof(stack) / sizeof(stack[0])))
    {
      stack[sp++] = prelen;
    }
  }
}

int ftp_data_open(ftp_env_t *env)
{
  struct sockaddr_in data_addr;
  struct sockaddr_in ctrl_addr;
  socklen_t addr_len;
  socklen_t ctrl_len;

  if (env->data_addr.sin_port)
  {
    if (env->data_fd < 0)
    {
      env->data_fd = socket(AF_INET, SOCK_STREAM, 0);
      if (env->data_fd < 0)
      {
        return -1;
      }
    }
    if (connect(env->data_fd, (struct sockaddr *)&env->data_addr,
                sizeof(env->data_addr)))
    {
      close(env->data_fd);
      env->data_fd = -1;
      return -1;
    }
  }
  else
  {
    if (env->passive_fd < 0)
    {
      errno = ENOTCONN;
      return -1;
    }
    addr_len = sizeof(data_addr);
    if ((env->data_fd = accept(env->passive_fd, (struct sockaddr *)&data_addr,
                               &addr_len)) < 0)
    {
      return -1;
    }

    close(env->passive_fd);
    env->passive_fd = -1;

    memset(&ctrl_addr, 0, sizeof(ctrl_addr));
    ctrl_len = sizeof(ctrl_addr);
    if (getpeername(env->active_fd, (struct sockaddr *)&ctrl_addr, &ctrl_len) !=
        0)
    {
      close(env->data_fd);
      env->data_fd = -1;
      errno = EACCES;
      return -1;
    }
    if (ctrl_addr.sin_family != AF_INET ||
        ctrl_addr.sin_addr.s_addr != data_addr.sin_addr.s_addr)
    {
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
ftp_data_read(ftp_env_t *env, void *buf, size_t count)
{
  for (;;)
  {
    ssize_t r = recv(env->data_fd, buf, count, 0);
    if (r < 0 && errno == EINTR)
    {
      continue;
    }
    return r;
  }
}

static int
ftp_copy_ascii_out(ftp_env_t *env, int fd_in)
{
  char *inbuf = env->xfer_buf;
  size_t bufsize = env->xfer_buf_size;
  char *outbuf = NULL;
  size_t outcap = 0;
  int free_in = 0;
  int prev_cr = 0;

  if (!inbuf || !bufsize)
  {
    inbuf = malloc(IO_COPY_BUFSIZE);
    bufsize = IO_COPY_BUFSIZE;
    free_in = 1;
    if (!inbuf)
    {
      return -1;
    }
  }

  outcap = bufsize * 2 + 2;
  outbuf = malloc(outcap);
  if (!outbuf)
  {
    if (free_in)
    {
      free(inbuf);
    }
    return -1;
  }

  for (;;)
  {
    ssize_t r = read(fd_in, inbuf, bufsize);
    size_t out_len = 0;

    if (r < 0)
    {
      if (errno == EINTR)
      {
        continue;
      }
      goto error;
    }
    if (r == 0)
    {
      break;
    }

    for (ssize_t i = 0; i < r; i++)
    {
      unsigned char c = (unsigned char)inbuf[i];

      if (prev_cr)
      {
        if (c == '\n')
        {
          outbuf[out_len++] = '\r';
          outbuf[out_len++] = '\n';
          prev_cr = 0;
          continue;
        }
        outbuf[out_len++] = '\r';
        outbuf[out_len++] = '\0';
        prev_cr = 0;
      }

      if (c == '\r')
      {
        prev_cr = 1;
        continue;
      }
      if (c == '\n')
      {
        outbuf[out_len++] = '\r';
        outbuf[out_len++] = '\n';
        continue;
      }
      outbuf[out_len++] = (char)c;
    }

    if (out_len && io_nwrite(env->data_fd, outbuf, out_len))
    {
      goto error;
    }
  }

  if (prev_cr)
  {
    outbuf[0] = '\r';
    outbuf[1] = '\0';
    if (io_nwrite(env->data_fd, outbuf, 2))
    {
      goto error;
    }
  }

  free(outbuf);
  if (free_in)
  {
    free(inbuf);
  }
  return 0;

error:
  free(outbuf);
  if (free_in)
  {
    free(inbuf);
  }
  return -1;
}

static int
ftp_copy_ascii_in(ftp_env_t *env, int fd_out, off_t *out_off)
{
  char *inbuf = env->xfer_buf;
  size_t bufsize = env->xfer_buf_size;
  char *outbuf = NULL;
  size_t outcap = 0;
  int free_in = 0;
  int prev_cr = 0;

  if (!out_off)
  {
    errno = EINVAL;
    return -1;
  }

  if (!inbuf || !bufsize)
  {
    inbuf = malloc(IO_COPY_BUFSIZE);
    bufsize = IO_COPY_BUFSIZE;
    free_in = 1;
    if (!inbuf)
    {
      return -1;
    }
  }

  outcap = bufsize + 1;
  outbuf = malloc(outcap);
  if (!outbuf)
  {
    if (free_in)
    {
      free(inbuf);
    }
    return -1;
  }

  for (;;)
  {
    ssize_t r = recv(env->data_fd, inbuf, bufsize, 0);
    size_t out_len = 0;

    if (r < 0)
    {
      if (errno == EINTR)
      {
        continue;
      }
      goto error;
    }
    if (r == 0)
    {
      break;
    }

    for (ssize_t i = 0; i < r; i++)
    {
      unsigned char c = (unsigned char)inbuf[i];

      if (prev_cr)
      {
        if (c == '\n')
        {
          outbuf[out_len++] = '\n';
          prev_cr = 0;
          continue;
        }
        if (c == '\0')
        {
          outbuf[out_len++] = '\r';
          prev_cr = 0;
          continue;
        }
        outbuf[out_len++] = '\r';
        prev_cr = 0;
      }

      if (c == '\r')
      {
        prev_cr = 1;
        continue;
      }
      outbuf[out_len++] = (char)c;
    }

    if (out_len && io_nwrite(fd_out, outbuf, out_len))
    {
      goto error;
    }
    *out_off += (off_t)out_len;
  }

  if (prev_cr)
  {
    outbuf[0] = '\r';
    if (io_nwrite(fd_out, outbuf, 1))
    {
      goto error;
    }
    *out_off += 1;
  }

  free(outbuf);
  if (free_in)
  {
    free(inbuf);
  }
  return 0;

error:
  free(outbuf);
  if (free_in)
  {
    free(inbuf);
  }
  return -1;
}

int ftp_data_close(ftp_env_t *env)
{
  if (env->data_fd < 0)
  {
    return 0;
  }

  if (!close(env->data_fd))
  {
    env->data_fd = -1;
    return 0;
  }
  return -1;
}

int ftp_active_printf(ftp_env_t *env, const char *fmt, ...)
{
  char buf[0x1000];
  size_t len = 0;
  va_list args;

  va_start(args, fmt);
  vsnprintf(buf, sizeof(buf), fmt, args);
  va_end(args);

  len = strlen(buf);

  if (io_nwrite(env->active_fd, buf, len))
  {
    return -1;
  }

  return 0;
}

int ftp_perror(ftp_env_t *env)
{
  char buf[255];

  if (strerror_r(errno, buf, sizeof(buf)))
  {
    strncpy(buf, "Unknown error", sizeof(buf));
  }

  return ftp_active_printf(env, "550 %s\r\n", buf);
}

static int
ftp_errno_is_timeout(int e)
{
  if (e == EAGAIN
#ifdef EWOULDBLOCK
      || e == EWOULDBLOCK
#endif
#ifdef ETIMEDOUT
      || e == ETIMEDOUT
#endif
  )
  {
    return 1;
  }
  return 0;
}

static int
ftp_data_xfer_error_reply(ftp_env_t *env)
{
  int e = errno;
  if (ftp_errno_is_timeout(e))
  {
    return ftp_active_printf(env, "426 Data connection timed out\r\n");
  }
  errno = e;
  return ftp_perror(env);
}

static int
ftp_data_open_error_reply(ftp_env_t *env)
{
  int e = errno;
  if (e == EACCES)
  {
    return ftp_active_printf(env, "425 Can't open data connection\r\n");
  }
  errno = e;
  return ftp_perror(env);
}

void ftp_abspath(ftp_env_t *env, char *abspath, const char *path)
{
  char buf[PATH_MAX + 1];

  if (path[0] != '/')
  {
    snprintf(buf, sizeof(buf), "%s/%s", env->cwd, path);
    ftp_normpath(buf, abspath, PATH_MAX + 1);
  }
  else
  {
    ftp_normpath(path, abspath, PATH_MAX + 1);
  }
}

static const char *
ftp_list_path_arg(const char *arg, char *buf, size_t bufsize)
{
  const char *p = arg;
  const char *path = NULL;
  size_t path_len = 0;
  int next_is_path = 0;

  while (*p == ' ')
  {
    p++;
  }

  while (*p)
  {
    const char *start = p;
    size_t len = 0;

    while (*p && *p != ' ')
    {
      p++;
      len++;
    }
    while (*p == ' ')
    {
      p++;
    }

    if (!len)
    {
      continue;
    }

    if (next_is_path)
    {
      path = start;
      path_len = len;
      break;
    }

    if (len == 2 && start[0] == '-' && start[1] == '-')
    {
      next_is_path = 1;
      continue;
    }

    if (start[0] != '-')
    {
      path = start;
      path_len = len;
    }
  }

  if (!path || !buf || bufsize < 2)
  {
    return NULL;
  }

  if (path_len >= bufsize)
  {
    path_len = bufsize - 1;
  }
  memcpy(buf, path, path_len);
  buf[path_len] = '\0';

  return buf;
}

static int
ftp_strieq(const char *a, const char *b)
{
  while (*a && *b)
  {
    if (tolower((unsigned char)*a) != tolower((unsigned char)*b))
    {
      return 0;
    }
    a++;
    b++;
  }
  return *a == '\0' && *b == '\0';
}

static int
ftp_format_mdtm(time_t t, char *buf, size_t bufsize)
{
  struct tm tm;

  if (!buf || bufsize < 15)
  {
    return -1;
  }

  if (!gmtime_r(&t, &tm))
  {
    return -1;
  }

  if (snprintf(buf, bufsize, "%04d%02d%02d%02d%02d%02d",
               tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
               tm.tm_hour, tm.tm_min, tm.tm_sec) >= (int)bufsize)
  {
    return -1;
  }

  return 0;
}

/**
 * Enter passive mode.
 **/
int ftp_cmd_PASV(ftp_env_t *env, const char *arg)
{
  socklen_t sockaddr_len = sizeof(struct sockaddr_in);
  struct sockaddr_in sockaddr;
  uint32_t addr = 0;
  uint16_t port = 0;

  env->data_addr.sin_port = 0;
  env->data_addr.sin_addr.s_addr = 0;
  if (env->data_fd >= 0)
  {
    close(env->data_fd);
    env->data_fd = -1;
  }

  if (getsockname(env->active_fd, (struct sockaddr *)&sockaddr, &sockaddr_len))
  {
    return ftp_perror(env);
  }
  addr = sockaddr.sin_addr.s_addr;

  if (env->passive_fd >= 0)
  {
    close(env->passive_fd);
    env->passive_fd = -1;
  }

  if ((env->passive_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
  {
    return ftp_perror(env);
  }

  if (setsockopt(env->passive_fd, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int)) < 0)
  {
    int ret = ftp_perror(env);
    close(env->passive_fd);
    env->passive_fd = -1;
    return ret;
  }

  memset(&sockaddr, 0, sockaddr_len);
  sockaddr.sin_family = AF_INET;
  sockaddr.sin_addr.s_addr = htonl(INADDR_ANY);
  sockaddr.sin_port = htons(0);

  if (bind(env->passive_fd, (struct sockaddr *)&sockaddr, sockaddr_len) != 0)
  {
    int ret = ftp_perror(env);
    close(env->passive_fd);
    env->passive_fd = -1;
    return ret;
  }

  if (listen(env->passive_fd, FTP_LISTEN_BACKLOG) != 0)
  {
    int ret = ftp_perror(env);
    close(env->passive_fd);
    env->passive_fd = -1;
    return ret;
  }

  if (getsockname(env->passive_fd, (struct sockaddr *)&sockaddr, &sockaddr_len))
  {
    int ret = ftp_perror(env);
    close(env->passive_fd);
    env->passive_fd = -1;
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
 * Enter extended passive mode.
 **/
int ftp_cmd_EPSV(ftp_env_t *env, const char *arg)
{
  socklen_t sockaddr_len = sizeof(struct sockaddr_in);
  struct sockaddr_in sockaddr;
  uint16_t port = 0;

  env->data_addr.sin_port = 0;
  env->data_addr.sin_addr.s_addr = 0;
  if (env->data_fd >= 0)
  {
    close(env->data_fd);
    env->data_fd = -1;
  }

  if (env->passive_fd >= 0)
  {
    close(env->passive_fd);
    env->passive_fd = -1;
  }

  if ((env->passive_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
  {
    return ftp_perror(env);
  }

  if (setsockopt(env->passive_fd, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int)) < 0)
  {
    int ret = ftp_perror(env);
    close(env->passive_fd);
    env->passive_fd = -1;
    return ret;
  }

  memset(&sockaddr, 0, sockaddr_len);
  sockaddr.sin_family = AF_INET;
  sockaddr.sin_addr.s_addr = htonl(INADDR_ANY);
  sockaddr.sin_port = htons(0);

  if (bind(env->passive_fd, (struct sockaddr *)&sockaddr, sockaddr_len) != 0)
  {
    int ret = ftp_perror(env);
    close(env->passive_fd);
    env->passive_fd = -1;
    return ret;
  }

  if (listen(env->passive_fd, FTP_LISTEN_BACKLOG) != 0)
  {
    int ret = ftp_perror(env);
    close(env->passive_fd);
    env->passive_fd = -1;
    return ret;
  }

  if (getsockname(env->passive_fd, (struct sockaddr *)&sockaddr, &sockaddr_len))
  {
    int ret = ftp_perror(env);
    close(env->passive_fd);
    env->passive_fd = -1;
    return ret;
  }
  port = sockaddr.sin_port;

  return ftp_active_printf(env, "229 Entering Extended Passive Mode (|||%hu|)\r\n",
                           ntohs(port));
}

/**
 * Change the working directory to its parent.
 **/
int ftp_cmd_CDUP(ftp_env_t *env, const char *arg)
{
  char pathbuf[PATH_MAX];

  ftp_abspath(env, pathbuf, "..");
  snprintf(env->cwd, sizeof(env->cwd), "%s", pathbuf);

  return ftp_active_printf(env, "250 OK\r\n");
}

/**
 *
 **/
int ftp_cmd_CHMOD(ftp_env_t *env, const char *arg)
{
  char pathbuf[PATH_MAX];
  mode_t mode = 0;
  char *ptr;

  if (!arg[0] || !(ptr = strstr(arg, " ")))
  {
    return ftp_active_printf(env, "501 Usage: CHMOD <MODE> <PATH>\r\n");
  }

  mode = strtol(arg, 0, 8);
  ftp_abspath(env, pathbuf, ptr + 1);

  if (chmod(pathbuf, mode))
  {
    return ftp_perror(env);
  }

  return ftp_active_printf(env, "200 OK\r\n");
}

/**
 * Change the working directory.
 **/
int ftp_cmd_CWD(ftp_env_t *env, const char *arg)
{
  char pathbuf[PATH_MAX];
  struct stat st;

  if (!arg[0])
  {
    return ftp_active_printf(env, "501 Usage: CWD <PATH>\r\n");
  }

  ftp_abspath(env, pathbuf, arg);
  if (stat(pathbuf, &st))
  {
    return ftp_perror(env);
  }

  if (!S_ISDIR(st.st_mode))
  {
    return ftp_active_printf(env, "550 No such directory\r\n");
  }

  snprintf(env->cwd, sizeof(env->cwd), "%s", pathbuf);

  return ftp_active_printf(env, "250 OK\r\n");
}

/**
 * Delete a given file.
 **/
int ftp_cmd_DELE(ftp_env_t *env, const char *arg)
{
  char pathbuf[PATH_MAX];

  if (!arg[0])
  {
    return ftp_active_printf(env, "501 Usage: DELE <FILENAME>\r\n");
  }

  ftp_abspath(env, pathbuf, arg);
  if (remove(pathbuf))
  {
    return ftp_perror(env);
  }

  return ftp_active_printf(env, "226 File deleted\r\n");
}

/**
 * Trasfer a list of files and folder.
 **/
int ftp_cmd_LIST(ftp_env_t *env, const char *arg)
{
  const char *dir_path = NULL;
  char argbuf[PATH_MAX + 1];
  char list_path[PATH_MAX + 1];
  char pathbuf[PATH_MAX * 3];
  char *outbuf = NULL;
  size_t outcap = 0;
  int free_outbuf = 0;
  char linebuf[1024];
  size_t out_len = 0;
  struct dirent *ent;
  struct stat statbuf;
  char timebuf[20];
  char modebuf[20];
  struct tm tm;
  DIR *dir;
  int xfer_failed = 0;

  dir_path = ftp_list_path_arg(arg, argbuf, sizeof(argbuf));
  if (dir_path)
  {
    ftp_abspath(env, list_path, dir_path);
  }
  else
  {
    ftp_normpath(env->cwd, list_path, sizeof(list_path));
  }
  dir_path = list_path;

  if (!(dir = opendir(dir_path)))
  {
    return ftp_perror(env);
  }

  outbuf = env->xfer_buf;
  outcap = env->xfer_buf_size;
  if (!outbuf || !outcap)
  {
    outcap = FTP_LIST_OUTBUF_SIZE;
    outbuf = malloc(outcap);
    free_outbuf = 1;
    if (!outbuf)
    {
      int err = ftp_perror(env);
      closedir(dir);
      return err;
    }
  }

  if (ftp_data_open(env))
  {
    int err = ftp_data_open_error_reply(env);
    if (free_outbuf)
    {
      free(outbuf);
    }
    closedir(dir);
    return err;
  }

  ftp_active_printf(env, "150 Opening data transfer\r\n");
#if defined(AT_SYMLINK_NOFOLLOW) && !defined(__ORBIS__)
  int dir_fd = dirfd(dir);
#endif

  while ((ent = readdir(dir)))
  {
    int have_path = 0;
    int stat_rc;

#if defined(AT_SYMLINK_NOFOLLOW) && !defined(__ORBIS__)
    if (dir_fd >= 0)
    {
      stat_rc = fstatat(dir_fd, ent->d_name, &statbuf, AT_SYMLINK_NOFOLLOW);
    }
    else
    {
      stat_rc = -1;
    }
#else
    stat_rc = -1;
#endif

    if (stat_rc != 0)
    {
      if (dir_path[1] == '\0')
      {
        snprintf(pathbuf, sizeof(pathbuf), "/%s", ent->d_name);
      }
      else
      {
        snprintf(pathbuf, sizeof(pathbuf), "%s/%s", dir_path, ent->d_name);
      }
      have_path = 1;
#ifdef AT_SYMLINK_NOFOLLOW
      if (lstat(pathbuf, &statbuf) != 0)
#else
      if (stat(pathbuf, &statbuf) != 0)
#endif
      {
        continue;
      }
    }

    if (env->self2elf && S_ISREG(statbuf.st_mode))
    {
      if (!have_path)
      {
        if (dir_path[1] == '\0')
        {
          snprintf(pathbuf, sizeof(pathbuf), "/%s", ent->d_name);
        }
        else
        {
          snprintf(pathbuf, sizeof(pathbuf), "%s/%s", dir_path, ent->d_name);
        }
        have_path = 1;
      }
      if (self_is_valid(pathbuf) == 1)
      {
        statbuf.st_size = self_get_elfsize(pathbuf);
      }
    }

    ftp_mode_string(statbuf.st_mode, modebuf);
    localtime_r((const time_t *)&(statbuf.st_mtime), &tm);
    strftime(timebuf, sizeof(timebuf), "%b %d %H:%M", &tm);
    int line_len = snprintf(linebuf, sizeof(linebuf),
                            "%s %" PRIuMAX " %" PRIuMAX " %" PRIuMAX
                            " %" PRIuMAX " %s %s\r\n",
                            modebuf, (uintmax_t)statbuf.st_nlink,
                            (uintmax_t)statbuf.st_uid,
                            (uintmax_t)statbuf.st_gid,
                            (uintmax_t)statbuf.st_size, timebuf,
                            ent->d_name);
    if (line_len < 0)
    {
      continue;
    }

    if ((size_t)line_len >= sizeof(linebuf))
    {
      line_len = (int)sizeof(linebuf) - 1;
    }

    if (out_len + (size_t)line_len > outcap)
    {
      if (out_len && io_nwrite(env->data_fd, outbuf, out_len))
      {
        (void)ftp_data_xfer_error_reply(env);
        xfer_failed = 1;
        break;
      }
      out_len = 0;
    }

    if ((size_t)line_len > outcap)
    {
      if (io_nwrite(env->data_fd, linebuf, (size_t)line_len))
      {
        (void)ftp_data_xfer_error_reply(env);
        xfer_failed = 1;
        break;
      }
    }
    else
    {
      memcpy(outbuf + out_len, linebuf, (size_t)line_len);
      out_len += (size_t)line_len;
    }
  }

  if (!xfer_failed && out_len)
  {
    if (io_nwrite(env->data_fd, outbuf, out_len))
    {
      (void)ftp_data_xfer_error_reply(env);
      xfer_failed = 1;
    }
  }

  if (ftp_data_close(env))
  {
    (void)ftp_perror(env);
    xfer_failed = 1;
  }

  if (closedir(dir))
  {
    (void)ftp_perror(env);
    xfer_failed = 1;
  }

  if (free_outbuf)
  {
    free(outbuf);
  }
  if (xfer_failed)
  {
    return 0;
  }
  return ftp_active_printf(env, "226 Transfer complete\r\n");
}

/**
 * Transfer a list of file names (no stat).
 **/
int ftp_cmd_NLST(ftp_env_t *env, const char *arg)
{
  const char *dir_path = NULL;
  char argbuf[PATH_MAX + 1];
  char list_path[PATH_MAX + 1];
  char *outbuf = NULL;
  size_t outcap = 0;
  int free_outbuf = 0;
  char linebuf[PATH_MAX + 4];
  size_t out_len = 0;
  struct dirent *ent;
  DIR *dir;
  int xfer_failed = 0;

  dir_path = ftp_list_path_arg(arg, argbuf, sizeof(argbuf));
  if (dir_path)
  {
    ftp_abspath(env, list_path, dir_path);
  }
  else
  {
    ftp_normpath(env->cwd, list_path, sizeof(list_path));
  }
  dir_path = list_path;

  if (!(dir = opendir(dir_path)))
  {
    return ftp_perror(env);
  }

  outbuf = env->xfer_buf;
  outcap = env->xfer_buf_size;
  if (!outbuf || !outcap)
  {
    outcap = FTP_LIST_OUTBUF_SIZE;
    outbuf = malloc(outcap);
    free_outbuf = 1;
    if (!outbuf)
    {
      int err = ftp_perror(env);
      closedir(dir);
      return err;
    }
  }

  if (ftp_data_open(env))
  {
    int err = ftp_data_open_error_reply(env);
    if (free_outbuf)
    {
      free(outbuf);
    }
    closedir(dir);
    return err;
  }

  ftp_active_printf(env, "150 Opening data transfer\r\n");

  while ((ent = readdir(dir)))
  {
    int line_len = snprintf(linebuf, sizeof(linebuf), "%s\r\n", ent->d_name);
    if (line_len < 0)
    {
      continue;
    }
    if ((size_t)line_len >= sizeof(linebuf))
    {
      line_len = (int)sizeof(linebuf) - 1;
    }

    if (out_len + (size_t)line_len > outcap)
    {
      if (out_len && io_nwrite(env->data_fd, outbuf, out_len))
      {
        (void)ftp_data_xfer_error_reply(env);
        xfer_failed = 1;
        break;
      }
      out_len = 0;
    }

    if ((size_t)line_len > outcap)
    {
      if (io_nwrite(env->data_fd, linebuf, (size_t)line_len))
      {
        (void)ftp_data_xfer_error_reply(env);
        xfer_failed = 1;
        break;
      }
    }
    else
    {
      memcpy(outbuf + out_len, linebuf, (size_t)line_len);
      out_len += (size_t)line_len;
    }
  }

  if (!xfer_failed && out_len)
  {
    if (io_nwrite(env->data_fd, outbuf, out_len))
    {
      (void)ftp_data_xfer_error_reply(env);
      xfer_failed = 1;
    }
  }

  if (ftp_data_close(env))
  {
    (void)ftp_perror(env);
    xfer_failed = 1;
  }

  if (closedir(dir))
  {
    (void)ftp_perror(env);
    xfer_failed = 1;
  }

  if (free_outbuf)
  {
    free(outbuf);
  }
  if (xfer_failed)
  {
    return 0;
  }
  return ftp_active_printf(env, "226 Transfer complete\r\n");
}

/**
 * Transfer a machine-readable list without stat/strftime.
 **/
int ftp_cmd_MLSD(ftp_env_t *env, const char *arg)
{
  const char *dir_path = NULL;
  char argbuf[PATH_MAX + 1];
  char list_path[PATH_MAX + 1];
  char pathbuf[PATH_MAX * 3];
  char *outbuf = NULL;
  size_t outcap = 0;
  int free_outbuf = 0;
  char linebuf[PATH_MAX + 64];
  size_t out_len = 0;
  struct dirent *ent;
  struct stat statbuf;
  DIR *dir;
  int xfer_failed = 0;

  dir_path = ftp_list_path_arg(arg, argbuf, sizeof(argbuf));
  if (dir_path)
  {
    ftp_abspath(env, list_path, dir_path);
  }
  else
  {
    ftp_normpath(env->cwd, list_path, sizeof(list_path));
  }
  dir_path = list_path;

  if (!(dir = opendir(dir_path)))
  {
    return ftp_perror(env);
  }

  outbuf = env->xfer_buf;
  outcap = env->xfer_buf_size;
  if (!outbuf || !outcap)
  {
    outcap = FTP_LIST_OUTBUF_SIZE;
    outbuf = malloc(outcap);
    free_outbuf = 1;
    if (!outbuf)
    {
      int err = ftp_perror(env);
      closedir(dir);
      return err;
    }
  }

  if (ftp_data_open(env))
  {
    int err = ftp_data_open_error_reply(env);
    if (free_outbuf)
    {
      free(outbuf);
    }
    closedir(dir);
    return err;
  }

  ftp_active_printf(env, "150 Opening data transfer\r\n");
#if defined(AT_SYMLINK_NOFOLLOW) && !defined(__ORBIS__)
  int dir_fd = dirfd(dir);
#endif

  while ((ent = readdir(dir)))
  {
    int have_path = 0;
    int stat_rc;
    const char *type = "type=unknown;";
    uintmax_t size = 0;
    char timebuf[32];

#if defined(AT_SYMLINK_NOFOLLOW) && !defined(__ORBIS__)
    if (dir_fd >= 0)
    {
      stat_rc = fstatat(dir_fd, ent->d_name, &statbuf, AT_SYMLINK_NOFOLLOW);
    }
    else
    {
      stat_rc = -1;
    }
#else
    stat_rc = -1;
#endif

    if (stat_rc != 0)
    {
      if (dir_path[1] == '\0')
      {
        snprintf(pathbuf, sizeof(pathbuf), "/%s", ent->d_name);
      }
      else
      {
        snprintf(pathbuf, sizeof(pathbuf), "%s/%s", dir_path, ent->d_name);
      }
      have_path = 1;
#ifdef AT_SYMLINK_NOFOLLOW
      if (lstat(pathbuf, &statbuf) != 0)
#else
      if (stat(pathbuf, &statbuf) != 0)
#endif
      {
        continue;
      }
    }

    if (ent->d_name[0] == '.' && ent->d_name[1] == '\0')
    {
      type = "type=cdir;";
    }
    else if (ent->d_name[0] == '.' && ent->d_name[1] == '.' && ent->d_name[2] == '\0')
    {
      type = "type=pdir;";
    }
    else if (S_ISDIR(statbuf.st_mode))
    {
      type = "type=dir;";
    }
    else if (S_ISREG(statbuf.st_mode))
    {
      type = "type=file;";
    }
    else if (S_ISLNK(statbuf.st_mode))
    {
      type = "type=link;";
    }

    size = (uintmax_t)statbuf.st_size;
    if (env->self2elf && S_ISREG(statbuf.st_mode))
    {
      if (!have_path)
      {
        if (dir_path[1] == '\0')
        {
          snprintf(pathbuf, sizeof(pathbuf), "/%s", ent->d_name);
        }
        else
        {
          snprintf(pathbuf, sizeof(pathbuf), "%s/%s", dir_path, ent->d_name);
        }
        have_path = 1;
      }
      if (self_is_valid(pathbuf) == 1)
      {
        size = (uintmax_t)self_get_elfsize(pathbuf);
      }
    }

    if (ftp_format_mdtm(statbuf.st_mtime, timebuf, sizeof(timebuf)))
    {
      continue;
    }

    int line_len = snprintf(linebuf, sizeof(linebuf),
                            "%ssize=%" PRIuMAX ";modify=%s; %s\r\n",
                            type, size, timebuf, ent->d_name);
    if (line_len < 0)
    {
      continue;
    }
    if ((size_t)line_len >= sizeof(linebuf))
    {
      line_len = (int)sizeof(linebuf) - 1;
    }

    if (out_len + (size_t)line_len > outcap)
    {
      if (out_len && io_nwrite(env->data_fd, outbuf, out_len))
      {
        (void)ftp_data_xfer_error_reply(env);
        xfer_failed = 1;
        break;
      }
      out_len = 0;
    }

    if ((size_t)line_len > outcap)
    {
      if (io_nwrite(env->data_fd, linebuf, (size_t)line_len))
      {
        (void)ftp_data_xfer_error_reply(env);
        xfer_failed = 1;
        break;
      }
    }
    else
    {
      memcpy(outbuf + out_len, linebuf, (size_t)line_len);
      out_len += (size_t)line_len;
    }
  }

  if (!xfer_failed && out_len)
  {
    if (io_nwrite(env->data_fd, outbuf, out_len))
    {
      (void)ftp_data_xfer_error_reply(env);
      xfer_failed = 1;
    }
  }

  if (ftp_data_close(env))
  {
    (void)ftp_perror(env);
    xfer_failed = 1;
  }

  if (closedir(dir))
  {
    (void)ftp_perror(env);
    xfer_failed = 1;
  }

  if (free_outbuf)
  {
    free(outbuf);
  }
  if (xfer_failed)
  {
    return 0;
  }
  return ftp_active_printf(env, "226 Transfer complete\r\n");
}

/**
 * Create a new directory at a given path.
 **/
int ftp_cmd_MKD(ftp_env_t *env, const char *arg)
{
  char pathbuf[PATH_MAX];

  if (!arg[0])
  {
    return ftp_active_printf(env, "501 Usage: MKD <DIRNAME>\r\n");
  }

  ftp_abspath(env, pathbuf, arg);
  if (mkdir(pathbuf, 0777))
  {
    return ftp_perror(env);
  }

  return ftp_active_printf(env, "226 Directory created\r\n");
}

/**
 * No operation.
 **/
int ftp_cmd_NOOP(ftp_env_t *env, const char *arg)
{
  return ftp_active_printf(env, "200 NOOP OK\r\n");
}

/**
 * Establish a data connection with client.
 **/
int ftp_cmd_PORT(ftp_env_t *env, const char *arg)
{
  uint8_t addr[6];
  struct in_addr in_addr;
  struct sockaddr_in ctrl_addr;
  socklen_t ctrl_len;
  uint32_t s_addr_host;
  uint16_t port_host;

  if (sscanf(arg, "%hhu,%hhu,%hhu,%hhu,%hhu,%hhu",
             addr, addr + 1, addr + 2, addr + 3, addr + 4, addr + 5) != 6)
  {
    return ftp_active_printf(env, "501 Usage: PORT <addr>\r\n");
  }

  s_addr_host = ((uint32_t)addr[0] << 24) | ((uint32_t)addr[1] << 16) |
                ((uint32_t)addr[2] << 8) | (uint32_t)addr[3];
  in_addr.s_addr = htonl(s_addr_host);
  port_host = (uint16_t)(((uint16_t)addr[4] << 8) | (uint16_t)addr[5]);

  memset(&ctrl_addr, 0, sizeof(ctrl_addr));
  ctrl_len = sizeof(ctrl_addr);
  if (getpeername(env->active_fd, (struct sockaddr *)&ctrl_addr, &ctrl_len) !=
      0)
  {
    return ftp_active_printf(env, "500 Illegal PORT command\r\n");
  }
  if (ctrl_addr.sin_family != AF_INET ||
      ctrl_addr.sin_addr.s_addr != in_addr.s_addr)
  {
    return ftp_active_printf(env, "500 Illegal PORT command\r\n");
  }

  if (env->passive_fd >= 0)
  {
    close(env->passive_fd);
    env->passive_fd = -1;
  }

  if (env->data_fd >= 0)
  {
    close(env->data_fd);
    env->data_fd = -1;
  }

  if ((env->data_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
  {
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
int ftp_cmd_EPRT(ftp_env_t *env, const char *arg)
{
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

  if (!arg[0])
  {
    return ftp_active_printf(env, "501 Usage: EPRT <d><af><d><addr><d><port><d>\r\n");
  }

  delim = arg[0];
  p1 = strchr(arg + 1, delim);
  if (!p1)
  {
    return ftp_active_printf(env, "501 Usage: EPRT <d><af><d><addr><d><port><d>\r\n");
  }
  p2 = strchr(p1 + 1, delim);
  if (!p2)
  {
    return ftp_active_printf(env, "501 Usage: EPRT <d><af><d><addr><d><port><d>\r\n");
  }
  p3 = strchr(p2 + 1, delim);
  if (!p3)
  {
    return ftp_active_printf(env, "501 Usage: EPRT <d><af><d><addr><d><port><d>\r\n");
  }

  snprintf(proto, sizeof(proto), "%.*s", (int)(p1 - (arg + 1)), arg + 1);
  snprintf(addrbuf, sizeof(addrbuf), "%.*s", (int)(p2 - (p1 + 1)), p1 + 1);
  snprintf(portbuf, sizeof(portbuf), "%.*s", (int)(p3 - (p2 + 1)), p2 + 1);

  if (strcmp(proto, "1"))
  {
    return ftp_active_printf(env, "522 Network protocol not supported\r\n");
  }

  if (inet_pton(AF_INET, addrbuf, &in_addr) != 1)
  {
    return ftp_active_printf(env, "501 Usage: EPRT <d><af><d><addr><d><port><d>\r\n");
  }

  memset(&ctrl_addr, 0, sizeof(ctrl_addr));
  ctrl_len = sizeof(ctrl_addr);
  if (getpeername(env->active_fd, (struct sockaddr *)&ctrl_addr, &ctrl_len) !=
      0)
  {
    return ftp_active_printf(env, "500 Illegal EPRT command\r\n");
  }
  if (ctrl_addr.sin_family != AF_INET ||
      ctrl_addr.sin_addr.s_addr != in_addr.s_addr)
  {
    return ftp_active_printf(env, "500 Illegal EPRT command\r\n");
  }

  port_ul = strtoul(portbuf, NULL, 10);
  if (!port_ul || port_ul > 65535)
  {
    return ftp_active_printf(env, "501 Usage: EPRT <d><af><d><addr><d><port><d>\r\n");
  }

  if (env->passive_fd >= 0)
  {
    close(env->passive_fd);
    env->passive_fd = -1;
  }
  if (env->data_fd >= 0)
  {
    close(env->data_fd);
    env->data_fd = -1;
  }

  if ((env->data_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
  {
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
int ftp_cmd_PWD(ftp_env_t *env, const char *arg)
{
  return ftp_active_printf(env, "257 \"%s\"\r\n", env->cwd);
}

/**
 * Disconnect client.
 **/
int ftp_cmd_QUIT(ftp_env_t *env, const char *arg)
{
  ftp_active_printf(env, "221 Goodbye\r\n");
  return -1;
}

/**
 * Mark the offset to start from in a future file transer.
 **/
int ftp_cmd_REST(ftp_env_t *env, const char *arg)
{
  const char *p = arg;
  char *end = NULL;
  long long off = 0;

  while (*p == ' ')
  {
    p++;
  }

  if (env->type == 'A')
  {
    env->data_offset = 0;
    return ftp_active_printf(env, "504 REST not supported in ASCII mode\r\n");
  }

  if (!p[0])
  {
    return ftp_active_printf(env, "501 Usage: REST <OFFSET>\r\n");
  }

  errno = 0;
  off = strtoll(p, &end, 10);
  if (errno || end == p)
  {
    return ftp_active_printf(env, "501 Usage: REST <OFFSET>\r\n");
  }
  while (*end == ' ')
  {
    end++;
  }
  if (*end || off < 0 || (off_t)off != off)
  {
    return ftp_active_printf(env, "501 Usage: REST <OFFSET>\r\n");
  }

  env->data_offset = (off_t)off;

  return ftp_active_printf(env, "350 REST OK\r\n");
}

/**
 * Retreive data from a given file.
 **/
static int
ftp_cmd_RETR_fd(ftp_env_t *env, int fd)
{
  off_t off = env->data_offset;
  env->data_offset = 0;
  struct stat st;
  size_t remaining;
  int err = 0;

  if (env->type == 'A' && off != 0)
  {
    return ftp_active_printf(env, "504 REST not supported in ASCII mode\r\n");
  }

  if (fstat(fd, &st))
  {
    return ftp_perror(env);
  }
  if (lseek(fd, off, SEEK_SET) < 0)
  {
    return ftp_perror(env);
  }

  if (off >= st.st_size)
  {
    remaining = 0;
  }
  else
  {
    remaining = (size_t)(st.st_size - off);
  }

  if (ftp_active_printf(env, "150 Starting data transfer\r\n"))
  {
    return -1;
  }

  if (ftp_data_open(env))
  {
    return ftp_data_open_error_reply(env);
  }

  #if defined(POSIX_FADV_SEQUENTIAL) && !defined(__ORBIS__)
    posix_fadvise(fd, off, 0, POSIX_FADV_SEQUENTIAL);
  #endif

  if (env->type == 'A')
  {
    if (ftp_copy_ascii_out(env, fd))
    {
      err = ftp_data_xfer_error_reply(env);
      ftp_data_close(env);
      return err;
    }
  }
  else if (remaining)
  {
    #ifdef IO_USE_SENDFILE
    if (io_sendfile(fd, env->data_fd, off, remaining))
    {
      err = ftp_data_xfer_error_reply(env);
      ftp_data_close(env);
      return err;
    }
    #else 
    if (env->xfer_buf && env->xfer_buf_size)
    {
      if (io_ncopy_buf(fd, env->data_fd, remaining, env->xfer_buf,
                       env->xfer_buf_size))
      {
        err = ftp_data_xfer_error_reply(env);
        ftp_data_close(env);
        return err;
      }
    }
    else if (io_ncopy(fd, env->data_fd, remaining))
    {
      err = ftp_data_xfer_error_reply(env);
      ftp_data_close(env);
      return err;
    }
    #endif

  }

  if (ftp_data_close(env))
  {
    return ftp_perror(env);
  }

  return ftp_active_printf(env, "226 Transfer completed\r\n");
}

/**
 * Retreive an ELF file embedded within a SELF file.
 **/
static int
ftp_cmd_RETR_self2elf(ftp_env_t *env, int fd)
{
  FILE *tmpf;
  int err;

  if (!(tmpf = tmpfile()))
  {
    return ftp_perror(env);
  }

  if (ftp_active_printf(env, "150-Extracting ELF...\r\n"))
  {
    fclose(tmpf);
    return -1;
  }
  if (self_extract_elf_ex(fd, fileno(tmpf), env->self_verify))
  {
    if (errno != EBADMSG)
    {
      err = ftp_perror(env);
      fclose(tmpf);
      return err;
    }
    if (ftp_active_printf(env, "150-Warning: ELF digest mismatch\r\n"))
    {
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
int ftp_cmd_RETR(ftp_env_t *env, const char *arg)
{
  char path[PATH_MAX];
  int err;
  int fd;

  if (!arg[0])
  {
    return ftp_active_printf(env, "501 Usage: RETR <PATH>\r\n");
  }

  ftp_abspath(env, path, arg);
  if ((fd = open(path, O_RDONLY, 0)) < 0)
  {
    return ftp_perror(env);
  }

  if (env->self2elf && self_is_valid(path) == 1)
  {
    err = ftp_cmd_RETR_self2elf(env, fd);
  }
  else
  {
    err = ftp_cmd_RETR_fd(env, fd);
  }

  close(fd);
  return err;
}

/**
 * Remove a directory.
 **/
int ftp_cmd_RMD(ftp_env_t *env, const char *arg)
{
  char pathbuf[PATH_MAX];

  if (!arg[0])
  {
    return ftp_active_printf(env, "501 Usage: RMD <DIRNAME>\r\n");
  }

  ftp_abspath(env, pathbuf, arg);
  if (rmdir(pathbuf))
  {
    return ftp_perror(env);
  }

  return ftp_active_printf(env, "226 Directory deleted\r\n");
}

/**
 * Specify a path that will later be renamed by the RNTO command.
 **/
int ftp_cmd_RNFR(ftp_env_t *env, const char *arg)
{
  struct stat st;

  if (!arg[0])
  {
    return ftp_active_printf(env, "501 Usage: RNFR <PATH>\r\n");
  }

  ftp_abspath(env, env->rename_path, arg);
  if (stat(env->rename_path, &st))
  {
    return ftp_perror(env);
  }

  return ftp_active_printf(env, "350 Awaiting new name\r\n");
}

/**
 * Rename a path previously specified by the RNFR command.
 **/
int ftp_cmd_RNTO(ftp_env_t *env, const char *arg)
{
  char pathbuf[PATH_MAX];
  struct stat st;

  if (!arg[0])
  {
    return ftp_active_printf(env, "501 Usage: RNTO <PATH>\r\n");
  }

  if (stat(env->rename_path, &st))
  {
    return ftp_perror(env);
  }

  ftp_abspath(env, pathbuf, arg);
  if (rename(env->rename_path, pathbuf))
  {
    return ftp_perror(env);
  }

  return ftp_active_printf(env, "226 Path renamed\r\n");
}

/**
 * Obtain the size of a given file.
 **/
int ftp_cmd_SIZE(ftp_env_t *env, const char *arg)
{
  char pathbuf[PATH_MAX];
  struct stat st = {0};

  if (env->type == 'A')
  {
    return ftp_active_printf(env, "504 SIZE not supported in ASCII mode\r\n");
  }

  if (!arg[0])
  {
    return ftp_active_printf(env, "501 Usage: SIZE <FILENAME>\r\n");
  }

  ftp_abspath(env, pathbuf, arg);

  if (env->self2elf)
  {
    st.st_size = self_get_elfsize(pathbuf);
  }

  if (!st.st_size)
  {
    if (stat(pathbuf, &st))
    {
      return ftp_perror(env);
    }
  }

  return ftp_active_printf(env, "213 %" PRIu64 "\r\n", st.st_size);
}

/**
 * Store recieved data in a given file.
 **/
int ftp_cmd_STOR(ftp_env_t *env, const char *arg)
{
  off_t off = env->data_offset;
  char pathbuf[PATH_MAX];
  void *readbuf = env->xfer_buf;
  size_t bufsize = env->xfer_buf_size;
  int err = 0;
  int free_buf = 0;
  ssize_t len;
  struct stat st;
  int flags = O_WRONLY;
  int fd;

  env->data_offset = 0;

  if (!arg[0])
  {
    return ftp_active_printf(env, "501 Usage: STOR <FILENAME>\r\n");
  }

  if (env->type == 'A' && off != 0)
  {
    env->data_offset = 0;
    return ftp_active_printf(env, "504 REST not supported in ASCII mode\r\n");
  }

  ftp_abspath(env, pathbuf, arg);
  if (off == 0)
  {
    flags |= O_CREAT | O_TRUNC;
  }

  if ((fd = open(pathbuf, flags, 0777)) < 0)
  {
    return ftp_perror(env);
  }

  if (off > 0)
  {
    if (fstat(fd, &st))
    {
      err = ftp_perror(env);
      close(fd);
      return err;
    }
    if (!S_ISREG(st.st_mode))
    {
      close(fd);
      return ftp_active_printf(env, "550 Not a regular file\r\n");
    }
    if (off > st.st_size)
    {
      close(fd);
      return ftp_active_printf(env, "551 Restart point beyond EOF\r\n");
    }
  }

  if (lseek(fd, off, SEEK_SET) < 0)
  {
    err = ftp_perror(env);
    close(fd);
    return err;
  }

  if (ftp_active_printf(env, "150 Opening data transfer\r\n"))
  {
    close(fd);
    return -1;
  }

  if (ftp_data_open(env))
  {
    err = ftp_data_open_error_reply(env);
    close(fd);
    return err;
  }

  if (!readbuf || !bufsize)
  {
    readbuf = malloc(IO_COPY_BUFSIZE);
    bufsize = IO_COPY_BUFSIZE;
    free_buf = 1;
    if (!readbuf)
    {
      err = ftp_perror(env);
      ftp_data_close(env);
      close(fd);
      return err;
    }
  }

  if (env->type == 'A')
  {
    if (ftp_copy_ascii_in(env, fd, &off))
    {
      err = ftp_data_xfer_error_reply(env);
      ftp_data_close(env);
      if (free_buf)
      {
        free(readbuf);
      }
      close(fd);
      return err;
    }
  }
  else
  {
    while ((len = ftp_data_read(env, readbuf, bufsize)) > 0)
    {
      if (io_nwrite(fd, readbuf, (size_t)len))
      {
        err = ftp_perror(env);
        ftp_data_close(env);
        if (free_buf)
        {
          free(readbuf);
        }
        close(fd);
        return err;
      }
      off += len;
    }
  }

  if (env->type != 'A' && len < 0)
  {
    err = ftp_data_xfer_error_reply(env);
    ftp_data_close(env);
    if (free_buf)
    {
      free(readbuf);
    }
    close(fd);
    return err;
  }

  if (free_buf)
  {
    free(readbuf);
  }

  if (ftruncate(fd, off))
  {
    err = ftp_perror(env);
    ftp_data_close(env);
    close(fd);
    return err;
  }

  close(fd);
  if (ftp_data_close(env))
  {
    return ftp_perror(env);
  }

  return ftp_active_printf(env, "226 Data transfer complete\r\n");
}

/**
 * Append to an existing file.
 **/
int ftp_cmd_APPE(ftp_env_t *env, const char *arg)
{
  char pathbuf[PATH_MAX];
  struct stat statbuf;

  if (!arg[0])
  {
    return ftp_active_printf(env, "501 Usage: APPE <FILENAME>\r\n");
  }

  if (!env->data_offset)
  {
    ftp_abspath(env, pathbuf, arg);
    if (stat(pathbuf, &statbuf))
    {
      return ftp_perror(env);
    }
    env->data_offset = statbuf.st_size;
  }

  return ftp_cmd_STOR(env, arg);
}

/**
 * Return system type.
 **/
int ftp_cmd_SYST(ftp_env_t *env, const char *arg)
{
  return ftp_active_printf(env, "215 UNIX Type: L8\r\n");
}

/**
 * Sets the transfer mode (ASCII or Binary).
 **/
int ftp_cmd_TYPE(ftp_env_t *env, const char *arg)
{
  switch (arg[0])
  {
#ifdef DISABLE_ASCII_MODE
  case 'A':
  case 'I':
    env->type = 'I';
    return ftp_active_printf(env, "200 Type set to %c\r\n", env->type);
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
int ftp_cmd_USER(ftp_env_t *env, const char *arg)
{
  return ftp_active_printf(env, "230 User logged in\r\n");
}

/**
 * Specify user password.
 **/
int ftp_cmd_PASS(ftp_env_t *env, const char *arg)
{
  (void)arg;
  return ftp_active_printf(env, "230 User logged in\r\n");
}

/**
 * Feature list.
 **/
int ftp_cmd_FEAT(ftp_env_t *env, const char *arg)
{
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
int ftp_cmd_OPTS(ftp_env_t *env, const char *arg)
{
  const char *p = arg;
  char opt[16];
  char val[16];
  size_t len = 0;

  while (*p == ' ')
  {
    p++;
  }
  if (!*p)
  {
    return ftp_active_printf(env, "501 Usage: OPTS UTF8 ON\r\n");
  }

  while (*p && *p != ' ' && len + 1 < sizeof(opt))
  {
    opt[len++] = *p++;
  }
  opt[len] = '\0';

  while (*p == ' ')
  {
    p++;
  }

  len = 0;
  while (*p && *p != ' ' && len + 1 < sizeof(val))
  {
    val[len++] = *p++;
  }
  val[len] = '\0';

  if (ftp_strieq(opt, "UTF8"))
  {
    if (!val[0] || ftp_strieq(val, "ON"))
    {
      return ftp_active_printf(env, "200 UTF8 enabled\r\n");
    }
    if (ftp_strieq(val, "OFF"))
    {
      return ftp_active_printf(env, "200 UTF8 disabled\r\n");
    }
    return ftp_active_printf(env, "501 Usage: OPTS UTF8 ON\r\n");
  }

  return ftp_active_printf(env, "504 Option not supported\r\n");
}

/**
 * Return modification time.
 **/
int ftp_cmd_MDTM(ftp_env_t *env, const char *arg)
{
  char pathbuf[PATH_MAX];
  char timebuf[32];
  struct stat st;

  if (!arg[0])
  {
    return ftp_active_printf(env, "501 Usage: MDTM <FILENAME>\r\n");
  }

  ftp_abspath(env, pathbuf, arg);
  if (stat(pathbuf, &st))
  {
    return ftp_perror(env);
  }
  if (ftp_format_mdtm(st.st_mtime, timebuf, sizeof(timebuf)))
  {
    return ftp_active_printf(env, "550 MDTM failed\r\n");
  }

  return ftp_active_printf(env, "213 %s\r\n", timebuf);
}

/**
 * Return machine-readable info for one path.
 **/
int ftp_cmd_MLST(ftp_env_t *env, const char *arg)
{
  char pathbuf[PATH_MAX];
  char namebuf[PATH_MAX + 1];
  char timebuf[32];
  struct stat st;
  const char *name = NULL;
  const char *type = "type=unknown;";
  int is_cdir = 0;
  int is_pdir = 0;
  uintmax_t size = 0;
  const char *p = arg;
  const char *end;
  size_t name_len = 0;

  while (*p == ' ')
  {
    p++;
  }
  end = p + strlen(p);
  while (end > p && end[-1] == ' ')
  {
    end--;
  }
  name_len = (size_t)(end - p);

  if (name_len)
  {
    if (name_len >= sizeof(namebuf))
    {
      name_len = sizeof(namebuf) - 1;
    }
    memcpy(namebuf, p, name_len);
    namebuf[name_len] = '\0';
    ftp_abspath(env, pathbuf, namebuf);
    name = namebuf;
  }
  else
  {
    ftp_normpath(env->cwd, pathbuf, sizeof(pathbuf));
    name = pathbuf;
  }

  if (name && name[0] == '.' && name[1] == '\0')
  {
    is_cdir = 1;
  }
  else if (name && name[0] == '.' && name[1] == '.' && name[2] == '\0')
  {
    is_pdir = 1;
  }

  if (stat(pathbuf, &st))
  {
    return ftp_perror(env);
  }

  if (is_cdir)
  {
    type = "type=cdir;";
  }
  else if (is_pdir)
  {
    type = "type=pdir;";
  }
  else if (S_ISDIR(st.st_mode))
  {
    type = "type=dir;";
  }
  else if (S_ISREG(st.st_mode))
  {
    type = "type=file;";
  }
  else if (S_ISLNK(st.st_mode))
  {
    type = "type=link;";
  }

  if (env->self2elf && S_ISREG(st.st_mode))
  {
    if (self_is_valid(pathbuf) == 1)
    {
      size = (uintmax_t)self_get_elfsize(pathbuf);
    }
    else
    {
      size = (uintmax_t)st.st_size;
    }
  }
  else
  {
    size = (uintmax_t)st.st_size;
  }

  if (ftp_format_mdtm(st.st_mtime, timebuf, sizeof(timebuf)))
  {
    return ftp_active_printf(env, "550 MLST failed\r\n");
  }

  if (name[0] == '/' && name[1] == '\0')
  {
    name = "/";
  }

  if (ftp_active_printf(env, "250-Listing\r\n"))
  {
    return -1;
  }
  if (ftp_active_printf(env, " %ssize=%" PRIuMAX ";modify=%s; %s\r\n",
                        type, size, timebuf, name))
  {
    return -1;
  }
  return ftp_active_printf(env, "250 End\r\n");
}

/**
 * Status info.
 **/
int ftp_cmd_STAT(ftp_env_t *env, const char *arg)
{
  (void)arg;
  if (ftp_active_printf(env, "211-FTP server status:\r\n"))
  {
    return -1;
  }
  if (ftp_active_printf(env, " CWD %s\r\n", env->cwd))
  {
    return -1;
  }
  return ftp_active_printf(env, "211 End\r\n");
}

/**
 * Help.
 **/
int ftp_cmd_HELP(ftp_env_t *env, const char *arg)
{
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
int ftp_cmd_MODE(ftp_env_t *env, const char *arg)
{
  (void)env;
  if (!arg[0])
  {
    return ftp_active_printf(env, "501 Usage: MODE S\r\n");
  }
  if (arg[0] == 'S' || arg[0] == 's')
  {
    return ftp_active_printf(env, "200 Mode set to S\r\n");
  }
  return ftp_active_printf(env, "504 MODE not supported\r\n");
}

/**
 * File structure.
 **/
int ftp_cmd_STRU(ftp_env_t *env, const char *arg)
{
  (void)env;
  if (!arg[0])
  {
    return ftp_active_printf(env, "501 Usage: STRU F\r\n");
  }
  if (arg[0] == 'F' || arg[0] == 'f')
  {
    return ftp_active_printf(env, "200 Structure set to F\r\n");
  }
  return ftp_active_printf(env, "504 STRU not supported\r\n");
}

/**
 * Allocate storage (no-op).
 **/
int ftp_cmd_ALLO(ftp_env_t *env, const char *arg)
{
  (void)arg;
  return ftp_active_printf(env, "200 ALLO OK\r\n");
}

/**
 * Abort transfer.
 **/
int ftp_cmd_ABOR(ftp_env_t *env, const char *arg)
{
  (void)arg;
  if (env->data_fd >= 0)
  {
    close(env->data_fd);
    env->data_fd = -1;
    env->data_offset = 0;
    if (ftp_active_printf(env, "426 Data connection closed; transfer aborted\r\n"))
    {
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
int ftp_cmd_KILL(ftp_env_t *env, const char *arg)
{
  FTP_LOG_PUTS("Server killed");
  exit(EXIT_SUCCESS);
  return -1;
}

/**
 * Custom command to toggle SELF transfer mode.
 **/
int ftp_cmd_SELF(ftp_env_t *env, const char *arg)
{
  env->self2elf = !env->self2elf;

  if (env->self2elf)
  {
    return ftp_active_printf(env, "226 SELF transfer mode enabled\r\n");
  }
  else
  {
    return ftp_active_printf(env, "226 SELF transfer mode disabled\r\n");
  }
}

/**
 * Toggle SELF digest verification.
 **/
int ftp_cmd_SELFCHK(ftp_env_t *env, const char *arg)
{
  if (arg[0])
  {
    char *end = NULL;
    long val = strtol(arg, &end, 10);
    if (end == arg || (*end && *end != ' '))
    {
      return ftp_active_printf(env, "501 Usage: SCHK <0|1>\r\n");
    }
    env->self_verify = val ? 1 : 0;
  }
  else
  {
    env->self_verify = !env->self_verify;
  }

  if (env->self_verify)
  {
    return ftp_active_printf(env, "226 SELF digest verification enabled\r\n");
  }
  else
  {
    return ftp_active_printf(env, "226 SELF digest verification disabled\r\n");
  }
}

/**
 * Unsupported command.
 **/
int ftp_cmd_unavailable(ftp_env_t *env, const char *arg)
{
  return ftp_active_printf(env, "502 Command not implemented\r\n");
}

/**
 * Unknown command.
 **/
int ftp_cmd_unknown(ftp_env_t *env, const char *arg)
{
  return ftp_active_printf(env, "502 Command not recognized\r\n");
}

/*
  Local Variables:
  c-file-style: "gnu"
  End:
*/
