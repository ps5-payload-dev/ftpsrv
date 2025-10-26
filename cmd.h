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

#pragma once

#include <limits.h>
#include <stdatomic.h>
#include <netinet/in.h>
#include <unistd.h>


/**
 * Data structure that captures the current state of a client.
 **/
typedef struct ftp_env {
  int  data_fd;
  int  active_fd;
  int  passive_fd;
  char cwd[PATH_MAX];

  char type;
  int self2elf;
  off_t data_offset;
  char rename_path[PATH_MAX];
  struct sockaddr_in data_addr;
} ftp_env_t;


/**
 * Callback function prototype for ftp commands.
 **/
typedef int (ftp_command_fn_t)(ftp_env_t* env, const char* arg);


/**
 * Standard FTP commands.
 **/
int ftp_cmd_APPE(ftp_env_t *env, const char* arg);
int ftp_cmd_CDUP(ftp_env_t *env, const char* arg);
int ftp_cmd_CWD (ftp_env_t *env, const char* arg);
int ftp_cmd_DELE(ftp_env_t *env, const char* arg);
int ftp_cmd_LIST(ftp_env_t *env, const char* arg);
int ftp_cmd_MKD (ftp_env_t *env, const char* arg);
int ftp_cmd_NOOP(ftp_env_t *env, const char* arg);
int ftp_cmd_PASV(ftp_env_t *env, const char* arg);
int ftp_cmd_PORT(ftp_env_t *env, const char* arg);
int ftp_cmd_PWD (ftp_env_t *env, const char* arg);
int ftp_cmd_QUIT(ftp_env_t *env, const char* arg);
int ftp_cmd_REST(ftp_env_t *env, const char* arg);
int ftp_cmd_RETR(ftp_env_t *env, const char* arg);
int ftp_cmd_RMD (ftp_env_t *env, const char* arg);
int ftp_cmd_RNFR(ftp_env_t *env, const char* arg);
int ftp_cmd_RNTO(ftp_env_t *env, const char* arg);
int ftp_cmd_SIZE(ftp_env_t *env, const char* arg);
int ftp_cmd_STOR(ftp_env_t *env, const char* arg);
int ftp_cmd_SYST(ftp_env_t *env, const char* arg);
int ftp_cmd_TYPE(ftp_env_t *env, const char* arg);
int ftp_cmd_USER(ftp_env_t *env, const char* arg);


/**
 * Custom FTP commands.
 **/
int ftp_cmd_KILL(ftp_env_t *env, const char* arg);
int ftp_cmd_MTRW(ftp_env_t *env, const char* arg);
int ftp_cmd_CHMOD(ftp_env_t *env, const char* arg);
int ftp_cmd_2ELF(ftp_env_t *env, const char* arg);
int ftp_cmd_RETR_self2elf(ftp_env_t *env, const char* arg);


/**
 * Error responses to unknown/unavailable FTP commands.
 **/
int ftp_cmd_unavailable(ftp_env_t *env, const char* arg);
int ftp_cmd_unknown(ftp_env_t *env, const char* arg);


/**
 * Transmit a formatted string via an active connection.
 **/
int ftp_active_printf(ftp_env_t *env, const char *fmt, ...);


/**
 * Resolve a path to its absolute path.
 **/
void ftp_abspath(ftp_env_t *env, char *abspath, const char *path);


/**
 * Transmit an errno string via an active connection.
 **/
int ftp_perror(ftp_env_t *env);


/**
 * Open a new FTP data connection.
 **/
int ftp_data_open(ftp_env_t *env);


/**
 * Close an existing data connection.
 **/
int ftp_data_close(ftp_env_t *env);
