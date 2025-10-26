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


#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/sysctl.h>
#include <sys/syscall.h>

#include <ps4/kernel.h>

#include "srv.h"
#include "log.h"


/**
 * Fint the pid of a process with the given name.
 **/
static pid_t
find_pid(const char* name) {
  int mib[4] = {1, 14, 8, 0};
  pid_t mypid = getpid();
  pid_t pid = -1;
  size_t buf_size;
  uint8_t *buf;

  if(sysctl(mib, 4, 0, &buf_size, 0, 0)) {
    FTP_LOG_PERROR("sysctl");
    return -1;
  }

  if(!(buf=malloc(buf_size))) {
    FTP_LOG_PERROR("malloc");
    return -1;
  }

  if(sysctl(mib, 4, buf, &buf_size, 0, 0)) {
    FTP_LOG_PERROR("sysctl");
    free(buf);
    return -1;
  }

  for(uint8_t *ptr=buf; ptr<(buf+buf_size);) {
    int ki_structsize = *(int*)ptr;
    pid_t ki_pid = *(pid_t*)&ptr[72];
    char *ki_tdname = (char*)&ptr[447];

    ptr += ki_structsize;
    if(!strcmp(name, ki_tdname) && ki_pid != mypid) {
      pid = ki_pid;
    }
  }

  free(buf);

  return pid;
}


/**
 * Launch payload.
 **/
int
main() {
  uint16_t port = 2121;
  int notify_user = 1;
  pid_t pid;

  while((pid=find_pid("ftpsrv.elf")) > 0) {
    if(kill(pid, SIGKILL)) {
      FTP_LOG_PERROR("kill");
      return EXIT_FAILURE;
    }
    sleep(1);
  }

  syscall(SYS_thr_set_name, -1, "ftpsrv.elf");
  signal(SIGPIPE, SIG_IGN);

  FTP_LOG_PRINTF("FTP server was compiled at %s %s\n", __DATE__, __TIME__);

  while(1) {
    ftp_serve(port, notify_user);
    notify_user = 0;
    sleep(3);
  }

  return EXIT_SUCCESS; 
}


/*
  Local Variables:
  c-file-style: "gnu"
  End:
*/
