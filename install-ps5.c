/* Copyright (C) 2026 John Törnblom

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

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include <sys/stat.h>

#include <ps5/kernel.h>


#define INCASSET(name, file)				      \
  __asm__(".section .rodata\n"				      \
	  ".global " #name "\n"				      \
	  ".global " #name "_end\n"			      \
	  ".global " #name "_size\n"			      \
	  ".align 16\n"					      \
	  #name ":\n"					      \
	  ".incbin \"" file "\"\n"			      \
	  #name "_end:\n"				      \
	  #name "_size:\n"				      \
	  ".quad " #name "_end - " #name "\n"		      \
	  ".previous\n");				      \
  extern const uint8_t name[];				      \
  extern const size_t name##_size;


int sceAppInstUtilInitialize(void);
int sceAppInstUtilAppInstallAll(void*);
int sceAppInstUtilAppUnInstall(const char*);


INCASSET(payload, "ftpsrv-ps5.elf");
INCASSET(param, "assets/param.json");
INCASSET(icon0, "assets/icon0.png");
INCASSET(websrv, "assets/websrv.html");
INCASSET(xterm_js, "assets/xterm.min.js");
INCASSET(xterm_css, "assets/xterm.min.css");


static int
install_file(const char* path, const uint8_t* data, size_t size) {
  FILE* f;

  if(!(f=fopen(path, "w"))) {
    return -1;
  }

  if(fwrite(data, size, 1, f) != 1) {
    fclose(f);
    return -1;
  }

  fclose(f);
  return 0;
}


static int
install_app(const char* title_id, const char* dir) {
  int (*sceAppInstUtilAppInstallTitleDir)(const char*, const char*, void*) = 0;
  const char* nid = "Wudg3Xe3heE";
  uint32_t handle;

  if(!kernel_dynlib_handle(-1, "libSceAppInstUtil.sprx", &handle)) {
    sceAppInstUtilAppInstallTitleDir = (void*)kernel_dynlib_resolve(-1, handle, nid);
  }

  if(sceAppInstUtilAppInstallTitleDir) {
    return sceAppInstUtilAppInstallTitleDir(title_id, dir, 0);
  }

  return sceAppInstUtilAppInstallAll(0);
}


int
main(int argc, char *argv[]) {
  int err;

  if((err=sceAppInstUtilInitialize())) {
    printf("sceAppInstUtilInitialize: error 0x%08X\n", err);
    return -1;
  }

  sceAppInstUtilAppUnInstall(TITLE_ID);

  if(mkdir("/user/app/"TITLE_ID, 0755)) {
    perror("mkdir");
    return -1;
  }
  if(mkdir("/user/app/"TITLE_ID"/sce_sys", 0755)) {
    perror("mkdir");
    return -1;
  }

  if(install_file("/user/app/"TITLE_ID"/payload.elf", payload, payload_size)) {
    perror("install_file");
    return -1;
  }

  if(install_file("/user/app/"TITLE_ID"/websrv.html", websrv, websrv_size)) {
    perror("install_file");
    return -1;
  }
  if(install_file("/user/app/"TITLE_ID"/xterm.js", xterm_js, xterm_js_size)) {
    perror("install_file");
    return -1;
  }
  if(install_file("/user/app/"TITLE_ID"/xterm.css", xterm_css, xterm_css_size)) {
    perror("install_file");
    return -1;
  }
  if(install_file("/user/app/"TITLE_ID"/sce_sys/icon0.png", icon0, icon0_size)) {
    perror("install_file");
    return -1;
  }
  if(install_file("/user/app/"TITLE_ID"/sce_sys/param.json", param, param_size)) {
    perror("install_file");
    return -1;
  }

  if((err=install_app(TITLE_ID, "/user/app/"))) {
    printf("install_app: error 0x%08X\n", err);
    return -1;
  }

  return 0;
}
