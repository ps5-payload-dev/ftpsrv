#   Copyright (C) 2025 John Törnblom
#
# This file is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; see the file COPYING. If not see
# <http://www.gnu.org/licenses/>.

PS5_HOST ?= ps5
PS5_PORT ?= 9021

ifdef PS5_PAYLOAD_SDK
    include $(PS5_PAYLOAD_SDK)/toolchain/prospero.mk
else
    $(error PS5_PAYLOAD_SDK is undefined)
endif

VERSION_TAG := $(shell git describe --abbrev=6 --dirty --always --tags)
TITLE_ID    := BREW10001
ASSETS      := assets/param.json assets/icon0.png assets/websrv.html

CFLAGS := -Wall -Werror -DVERSION_TAG=\"$(VERSION_TAG)\" -I.
CFLAGS += -DTITLE_ID=\"$(TITLE_ID)\"

SOURCE := srv.c cmd.c notify.c io.c self.c sha256.c
SOURCE += main-prospero.c cmd-prospero.c self-prospero.c
SOURCE += io-freebsd.c

all: ftpsrv-ps5.elf ftpsrv-ps5-install.elf

ftpsrv-ps5.elf: $(SOURCE)
	$(CC) $(CFLAGS) -o $@ $^

ftpsrv-ps5-install.elf: install-ps5.c $(ASSETS)
	$(CC) $(CFLAGS) -o $@ $< -lSceIpmi -lSceAppInstUtil

clean:
	rm -f *.elf

install: ftpsrv-ps5-install.elf
	$(PS5_DEPLOY) -h $(PS5_HOST) -p $(PS5_PORT) $^

test: ftpsrv-ps5.elf
	$(PS5_DEPLOY) -h $(PS5_HOST) -p $(PS5_PORT) $^

