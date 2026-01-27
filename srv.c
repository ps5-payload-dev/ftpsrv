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
#include <errno.h>
#include <ifaddrs.h>
#include <netinet/tcp.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include "cmd.h"
#include "io.h"
#include "log.h"
#include "notify.h"


/**
 * Map names of commands to function entry points.
 **/
typedef struct ftp_command {
  const char       *name;
  ftp_command_fn_t *func;
} ftp_command_t;


/**
 * Lookup table for FTP commands.
 **/
static ftp_command_t commands[] = {
  {"APPE", ftp_cmd_APPE},
  {"CDUP", ftp_cmd_CDUP},
  {"CWD",  ftp_cmd_CWD},
  {"DELE", ftp_cmd_DELE},
  {"LIST", ftp_cmd_LIST},
  {"MKD",  ftp_cmd_MKD},
  {"NOOP", ftp_cmd_NOOP},
  {"PASV", ftp_cmd_PASV},
  {"PORT", ftp_cmd_PORT},
  {"PWD",  ftp_cmd_PWD},
  {"QUIT", ftp_cmd_QUIT},
  {"REST", ftp_cmd_REST},
  {"RETR", ftp_cmd_RETR},
  {"RMD",  ftp_cmd_RMD},
  {"RNFR", ftp_cmd_RNFR},
  {"RNTO", ftp_cmd_RNTO},
  {"SIZE", ftp_cmd_SIZE},
  {"STOR", ftp_cmd_STOR},
  {"SYST", ftp_cmd_SYST},
  {"TYPE", ftp_cmd_TYPE},
  {"USER", ftp_cmd_USER},

  // custom commands
  {"KILL", ftp_cmd_KILL},
  {"MTRW", ftp_cmd_MTRW},
  {"SELF", ftp_cmd_SELF},
  {"CHMOD", ftp_cmd_CHMOD},

  // duplicates that ensure commands are 4 bytes long
  {"XCUP", ftp_cmd_CWD},
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
static char*
ftp_readline(int fd) {
  int bufsize = 1024;
  int position = 0;
  char *buffer_backup;
  char *buffer = calloc(bufsize, sizeof(char));
  char c;

  if(!buffer) {
    FTP_LOG_PERROR("malloc");
    return NULL;
  }

  while(1) {
    int len = read(fd, &c, 1);
    if(len == -1 && errno == EINTR) {
      continue;
    }

    if(len <= 0) {
      free(buffer);
      return NULL;
    }

    if(c == '\r') {
      buffer[position] = '\0';
      position = 0;
      continue;
    }

    if(c == '\n') {
      return buffer;
    }

    buffer[position++] = c;

    if(position >= bufsize) {
      bufsize += 1024;
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
  char *sep = strchr(line, ' ');
  char *arg = strchr(line, 0);

  if(sep) {
    sep[0] = 0;
    arg = sep + 1;
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
  char msg[0x100];
  size_t len;

  snprintf(msg, sizeof(msg),
	   "220-Welcome to ftpsrv.elf running on pid %d, compiled at %s %s\r\n",
	   getpid(), __DATE__, __TIME__);
  strncat(msg, "220 Service is ready\r\n", sizeof(msg)-1);

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
  bool running;
  char *line;
  char* cmd;
  int opt;

  env.data_fd     = -1;
  env.passive_fd  = -1;
  env.active_fd   = (int)(long)args;

  env.type        = 'I';
  env.data_offset = 0;
  env.self2elf    = 1;

  strcpy(env.cwd, "/");
  memset(env.rename_path, 0, sizeof(env.rename_path));
  memset(&env.data_addr, 0, sizeof(env.data_addr));

  opt = 1;
  if(setsockopt(env.active_fd, IPPROTO_TCP, TCP_NODELAY, &opt, sizeof(opt))) {
    FTP_LOG_PERROR("setsockopt");
  }

  env.readbuf_size = IO_COPY_BUFSIZE;
  if(!(env.readbuf=malloc(env.readbuf_size))) {
    FTP_LOG_PERROR("malloc");
    running = 0;
  } else {
    running = !ftp_greet(&env);
  }

  while(running) {
    if(!(line=ftp_readline(env.active_fd))) {
      break;
    }

    cmd = line;
    if(!strncmp(line, "SITE ", 5)) {
      cmd += 5;
    }

    if(ftp_execute(&env, cmd)) {
      running = false;
    }

    free(line);
  }

  if(env.active_fd > 0) {
    close(env.active_fd);
  }

  if(env.passive_fd > 0) {
    close(env.passive_fd);
  }

  if(env.data_fd > 0) {
    close(env.data_fd);
  }

  if(env.readbuf) {
    free(env.readbuf);
  }

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
    printf("| %-16s Copyright (C) 2025 John Törnblom & drakmor |\n", VERSION_TAG);
    puts("'-------------------------------------------------------------'");
  }

  if(getifaddrs(&ifaddr) == -1) {
    FTP_LOG_PERROR("getifaddrs");
    return -1;
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

  if(listen(srvfd, SOMAXCONN) != 0) {
    FTP_LOG_PERROR("listen");
    close(srvfd);
    return -1;
  }

  addr_len = sizeof(client_addr);

  while(1) {
    if((connfd=accept(srvfd, (struct sockaddr*)&client_addr, &addr_len)) < 0) {
      FTP_LOG_PERROR("accept");
      break;
    }

    if(!pthread_create(&trd, NULL, ftp_thread, (void*)(long)connfd)) {
      pthread_detach(trd);
    }
  }

  return close(srvfd);
}


/*
  Local Variables:
  c-file-style: "gnu"
  End:
*/
