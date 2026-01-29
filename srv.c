/* Copyright (C) 2025 John Törnblom

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

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/types.h>

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <ifaddrs.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include "cmd.h"
#include "io.h"
#include "log.h"
#include "notify.h"

#ifndef FTP_MAX_LINE
#define FTP_MAX_LINE 8192
#endif

/**
 * Map names of commands to function entry points.
 **/
typedef struct ftp_command {
  const char       *name;
  ftp_command_fn_t *func;
} ftp_command_t;

/**
 * Buffered reader state.
 **/
typedef struct ftp_reader {
  int fd;
  char buf[4096];
  size_t pos;
  size_t len;
  int line_too_long;
  int timed_out;
} ftp_reader_t;

/**
 * Lookup table for FTP commands.
 **/
static ftp_command_t commands[] = {
  {"APPE", ftp_cmd_APPE},
  {"CDUP", ftp_cmd_CDUP},
  {"CWD",  ftp_cmd_CWD},
  {"DELE", ftp_cmd_DELE},
  {"EPRT", ftp_cmd_EPRT},
  {"EPSV", ftp_cmd_EPSV},
  {"LIST", ftp_cmd_LIST},
  {"MKD",  ftp_cmd_MKD},
  {"MLSD", ftp_cmd_MLSD},
  {"MLST", ftp_cmd_MLST},
  {"NLST", ftp_cmd_NLST},
  {"NOOP", ftp_cmd_NOOP},
  {"PASS", ftp_cmd_PASS},
  {"PASV", ftp_cmd_PASV},
  {"PORT", ftp_cmd_PORT},
  {"PWD",  ftp_cmd_PWD},
  {"QUIT", ftp_cmd_QUIT},
  {"REST", ftp_cmd_REST},
  {"RETR", ftp_cmd_RETR},
  {"RMD",  ftp_cmd_RMD},
  {"RMDA", ftp_cmd_RMDA},
  {"RNFR", ftp_cmd_RNFR},
  {"RNTO", ftp_cmd_RNTO},
  {"SIZE", ftp_cmd_SIZE},
  {"DSIZ", ftp_cmd_DSIZ},
  {"STOR", ftp_cmd_STOR},
  {"SYST", ftp_cmd_SYST},
  {"TYPE", ftp_cmd_TYPE},
  {"USER", ftp_cmd_USER},
  {"ABOR", ftp_cmd_ABOR},
  {"ALLO", ftp_cmd_ALLO},
  {"AVBL", ftp_cmd_AVBL},
  {"FEAT", ftp_cmd_FEAT},
  {"HELP", ftp_cmd_HELP},
  {"MDTM", ftp_cmd_MDTM},
  {"MODE", ftp_cmd_MODE},
  {"OPTS", ftp_cmd_OPTS},
  {"STAT", ftp_cmd_STAT},
  {"STRU", ftp_cmd_STRU},

  // custom commands
  {"KILL", ftp_cmd_KILL},
  {"MTRW", ftp_cmd_MTRW},
  {"SELF", ftp_cmd_SELF},
  {"SCHK", ftp_cmd_SELFCHK},
  {"CHMOD", ftp_cmd_CHMOD},
  {"UMASK", ftp_cmd_UMASK},
  {"SYMLINK", ftp_cmd_SYMLINK},
  {"RMDIR", ftp_cmd_RMDA},
  {"CPFR", ftp_cmd_CPFR},
  {"CPTO", ftp_cmd_CPTO},
  {"COPY", ftp_cmd_COPY},
  {"XQUOTA", ftp_cmd_XQUOTA},

  // duplicates that ensure commands are 4 bytes long
  {"XCUP", ftp_cmd_CDUP},
  {"XMKD", ftp_cmd_MKD},
  {"XPWD", ftp_cmd_PWD},
  {"XRMD", ftp_cmd_RMD},

  // not yet implemnted
  {"XRCP", ftp_cmd_unavailable},
  {"XRSQ", ftp_cmd_unavailable},
  {"XSEM", ftp_cmd_unavailable},
  {"XSEN", ftp_cmd_unavailable},
};


/**
 * Number of FTP commands in the lookup table.
 **/
static int nb_ftp_commands = (sizeof(commands)/sizeof(ftp_command_t));


/**
 * Read a line from a file descriptor.
 **/
static int
ftp_reader_fill(ftp_reader_t *reader) {
  ssize_t len;

  reader->timed_out = 0;

  do {
    len = read(reader->fd, reader->buf, sizeof(reader->buf));
  } while(len == -1 && errno == EINTR);

  if(len <= 0) {
    if(len < 0 && (errno == EAGAIN
#ifdef EWOULDBLOCK
                   || errno == EWOULDBLOCK
#endif
#ifdef ETIMEDOUT
                   || errno == ETIMEDOUT
#endif
                   )) {
      reader->timed_out = 1;
    }
    return -1;
  }

  reader->pos = 0;
  reader->len = (size_t)len;

  return 0;
}

/**
 * Read a CRLF-terminated line from the control socket.
 **/
static char*
ftp_readline(ftp_reader_t *reader) {
  int bufsize = 1024;
  int position = 0;
  int line_ready = 0;
  int overflow = 0;
  char *buffer_backup;
  char *buffer = malloc(bufsize);

  if(!buffer) {
    FTP_LOG_PERROR("malloc");
    return NULL;
  }

  reader->line_too_long = 0;
  reader->timed_out = 0;

  while(1) {
    if(reader->pos >= reader->len) {
      if(ftp_reader_fill(reader)) {
        free(buffer);
        return NULL;
      }
    }

    char c = reader->buf[reader->pos++];

    if(c == '\r') {
      if(!overflow) {
        buffer[position] = '\0';
      }
      line_ready = 1;
      position = 0;
      continue;
    }

    if(c == '\n') {
      if(!line_ready && !overflow) {
        buffer[position] = '\0';
      }
      if(overflow) {
        buffer[0] = '\0';
      }
      return buffer;
    }

    if(line_ready) {
      line_ready = 0;
    }

    if(!overflow) {
      buffer[position++] = c;
    }

    if(position + 1 >= bufsize) {
      if(bufsize >= FTP_MAX_LINE) {
        overflow = 1;
        reader->line_too_long = 1;
        continue;
      }

      bufsize += 1024;
      if(bufsize > FTP_MAX_LINE) {
        bufsize = FTP_MAX_LINE;
      }
      buffer_backup = buffer;
      buffer = realloc(buffer, bufsize);
      if(!buffer) {
        FTP_LOG_PERROR("realloc");
        free(buffer_backup);
        return NULL;
      }
    }
  }
}

/**
 * Execute an FTP command.
 **/
static int
ftp_execute(ftp_env_t *env, char *line) {
  line += strspn(line, " ");
  if(!*line) {
    return 0;
  }

  char *sep = strchr(line, ' ');
  char *arg = strchr(line, 0);

  if(sep) {
    sep[0] = 0;
    arg = sep + 1;
  }

  arg += strspn(arg, " ");
  if(*arg) {
    char *end = arg + strlen(arg);
    while(end > arg && end[-1] == ' ') {
      end--;
    }
    *end = '\0';
  }

  for(char *p = line; *p; p++) {
    *p = (char)toupper((unsigned char)*p);
  }

  for(int i=0; i<nb_ftp_commands; i++) {
    if(strcmp(line, commands[i].name)) {
      continue;
    }

    return commands[i].func(env, arg);
  }

  return ftp_cmd_unknown(env, arg);
}


/**
 * Greet a new FTP connection.
 **/
static int
ftp_greet(ftp_env_t *env) {
  char msg[0x200];
  size_t len;

  snprintf(msg, sizeof(msg),
           "220-Welcome to ftpsrv.elf running on pid %d\r\n"
           "220-Version: %s (built %s %s)\r\n"
           "220 Service is ready\r\n",
           getpid(), VERSION_TAG, __DATE__, __TIME__);

  len = strlen(msg);
  if(io_nwrite(env->active_fd, msg, len)) {
    return -1;
  }

  return 0;
}


/**
 * Entry point for new FTP connections.
 **/
static void*
ftp_thread(void *args) {
  ftp_env_t env;
  ftp_reader_t reader;
  bool running;
  char *line;
  char *cmd;

  env.data_fd     = -1;
  env.passive_fd  = -1;
  env.active_fd   = (int)(long)args;

  env.type        = 'I';
  env.data_offset = 0;
  env.data_offset_is_rest = 0;
  env.self2elf    = 0;
  env.self_verify = 1;
  env.rename_ready = 0;
  env.copy_ready = 0;
  env.copy_in_progress = 0;
  env.copy_thread_valid = 0;

  pthread_mutex_init(&env.ctrl_mutex, NULL);
  pthread_mutex_init(&env.copy_mutex, NULL);

  strcpy(env.cwd, "/");
  memset(env.rename_path, 0, sizeof(env.rename_path));
  memset(env.copy_path, 0, sizeof(env.copy_path));
  memset(&env.data_addr, 0, sizeof(env.data_addr));
  env.xfer_buf_size = IO_COPY_BUFSIZE;
  env.xfer_buf = malloc(env.xfer_buf_size);
  if(!env.xfer_buf) {
    env.xfer_buf_size = 0;
  }
  memset(&reader, 0, sizeof(reader));
  reader.fd = env.active_fd;

  io_set_socket_opts(env.active_fd, 0);

  running = !ftp_greet(&env);

  while(running) {
    if(!(line = ftp_readline(&reader))) {
      if(reader.timed_out) {
        ftp_active_printf(&env, "421 Control connection timed out\r\n");
      }
      break;
    }

    if(reader.line_too_long) {
      ftp_active_printf(&env, "500 Line too long\r\n");
      free(line);
      continue;
    }

    cmd = line;
    if(strncasecmp(line, "SITE ", 5) == 0) {
      cmd += 5;
    }

    if(ftp_execute(&env, cmd)) {
      running = false;
    }

    free(line);
  }

  if(env.copy_thread_valid) {
    pthread_join(env.copy_thread, NULL);
  }

  if(env.active_fd >= 0) {
    close(env.active_fd);
  }

  if(env.passive_fd >= 0) {
    close(env.passive_fd);
  }

  if(env.data_fd >= 0) {
    close(env.data_fd);
  }

  if(env.xfer_buf) {
    free(env.xfer_buf);
  }

  pthread_mutex_destroy(&env.copy_mutex);
  pthread_mutex_destroy(&env.ctrl_mutex);

  pthread_exit(NULL);

  return NULL;
}


/**
 * Serve FTP on a given port.
 **/
int
ftp_serve(uint16_t port, int notify_user) {
  struct sockaddr_in server_addr;
  struct sockaddr_in client_addr;
  char ip[INET_ADDRSTRLEN];
  struct ifaddrs *ifaddr;
  int ifaddr_wait = 1;
  socklen_t addr_len;
  pthread_t trd;
  int connfd;
  int srvfd;

  if(notify_user) {
    puts(".-------------------------------------------------------------.");
    puts("|  __   _                                             _    __ |");
    puts("| / _| | |_   _ __    ___   _ __  __   __       ___  | |  / _||");
    puts("|| |_  | __| | '_ \\  / __| | '__| \\ \\ / /      / _ \\ | | | |_ |");
    puts("||  _| | |_  | |_) | \\__ \\ | |     \\ V /   _  |  __/ | | |  _||");
    puts("||_|    \\__| | .__/  |___/ |_|      \\_/   (_)  \\___| |_| |_|  |");
    puts("|            |_|                                              |");
    printf("| %-26s Copyright (C) 2025 John Törnblom |\n", VERSION_TAG);
    puts("|                                                   & drakmor |\n");
    puts("'-------------------------------------------------------------'");
  }

  if(getifaddrs(&ifaddr) == -1) {
    FTP_LOG_PERROR("getifaddrs");
    return 0;
  }

  // Enumerate all AF_INET IPs
  for(struct ifaddrs *ifa=ifaddr; ifa!=NULL; ifa=ifa->ifa_next) {
    if(ifa->ifa_addr == NULL) {
      continue;
    }

    if(ifa->ifa_addr->sa_family != AF_INET) {
      continue;
    }

    // skip localhost
    if(!strncmp("lo", ifa->ifa_name, 2)) {
      continue;
    }

    struct sockaddr_in *in = (struct sockaddr_in*)ifa->ifa_addr;
    inet_ntop(AF_INET, &(in->sin_addr), ip, sizeof(ip));

    // skip interfaces without an ip
    if(!strncmp("0.", ip, 2)) {
      continue;
    }

    if(notify_user) {
      notify("Serving FTP on %s:%d (%s)", ip, port, ifa->ifa_name);
    }

    ifaddr_wait = 0;
  }

  freeifaddrs(ifaddr);

  if(ifaddr_wait) {
    return 0;
  }

  if((srvfd=socket(AF_INET, SOCK_STREAM, 0)) < 0) {
    FTP_LOG_PERROR("socket");
    return -1;
  }

  if(setsockopt(srvfd, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int)) < 0) {
    FTP_LOG_PERROR("setsockopt");
    close(srvfd);
    return -1;
  }

  memset(&server_addr, 0, sizeof(server_addr));
  server_addr.sin_family = AF_INET;
  server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
  server_addr.sin_port = htons(port);

  if(bind(srvfd, (struct sockaddr*)&server_addr, sizeof(server_addr)) != 0) {
    FTP_LOG_PERROR("bind");
    close(srvfd);
    return -1;
  }

  if(listen(srvfd, FTP_LISTEN_BACKLOG) != 0) {
    FTP_LOG_PERROR("listen");
    close(srvfd);
    return -1;
  }

  while(1) {
    addr_len = sizeof(client_addr);
    if((connfd=accept(srvfd, (struct sockaddr*)&client_addr, &addr_len)) < 0) {
      if(errno == EINTR) {
        continue;
      }
      FTP_LOG_PERROR("accept");
      break;
    }

    if(pthread_create(&trd, NULL, ftp_thread,
                      (void *)(long)connfd)) {
      FTP_LOG_PERROR("pthread_create");
      close(connfd);
      continue;
    }
    pthread_detach(trd);
  }

  return close(srvfd);
}


/*
  Local Variables:
  c-file-style: "gnu"
  End:
*/