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

#include <unistd.h>
#include <signal.h>

#include "log.h"
#include "srv.h"


int
main() {
  uint16_t port = 2121;

  signal(SIGPIPE, SIG_IGN);

  while(1) {
    ftp_serve(port, 0);
    sleep(3);
  }

  return 0;
}


/*
  Local Variables:
  c-file-style: "gnu"
  End:
*/
