/*
  This file is part of xlogin display manager. Modifed from glibc-2.32 source.

  Copyright (C) 2021 Enrique Dominguez Pinos

  This program is free software: you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation, either version 3 of the License, or
  any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

/* Copyright (C) 1992-2020 Free Software Foundation, Inc.
   This file is part of the GNU C Library.

   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.

   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with the GNU C Library; if not, see
   <https://www.gnu.org/licenses/>.  */

#include <stdio.h>
#include <termios.h>
#include <stdlib.h> //free
#include <string.h> //memcpy

//#include "getpass.h"
char* getpass2 (const char *const prompt);

char* getpass2 (const char *const prompt) {
  FILE* fp;
  struct termios to, t; //to: initial terminal attrs
  char *buf;
  size_t bufsize=0;
  ssize_t nread;

  /* Try to write to and read from the terminal or fail (don't use sterr/stdin) */
  fp = fopen ("/dev/tty", "w+ce");//needs rw perms
  //fp = fopen ("/dev/tty", "w+cex");//x exclusive don't help because fail when exists
  if (fp==NULL) {
    fprintf(stderr,"Failed to open /dev/tty for writing the password prompt");
    return NULL;//error, we need the terminal
  }

  flockfile(fp);

  /* Turn echoing off if it is on now.  */
  if (tcgetattr (fileno (fp), &t) < 0) {
    fprintf(stderr,"Failed to get tty attributes: %m");//BUG check status?
    return NULL;
  }
  
  /* Save the old one. */
  memcpy(&to,&t,sizeof(to));
  //to = t;//BUG, works??
  /* Tricky, tricky. */
  t.c_lflag &= ~(ECHO|ISIG);
  if (tcsetattr(fileno(fp), TCSAFLUSH, &t) < 0) {
    fprintf(stderr,"Failed to set terminal attributes: %m");
    return NULL;      
  }

  /* Write the prompt.  */
  if (fprintf(fp,"%s","Password: ")<0) {
    fprintf(stderr,"Failed fprintf while writting the prompt");
    return NULL;
  }
  
  //fflush_unlocked(fp);
  if (fflush(fp)!=0) {
    fprintf(stderr,"Failed to get tty attributes: %m");
    return NULL;
  }
  
  /* Read the password.  */
  nread = getline(&buf, &bufsize, fp);
  if (nread < (ssize_t) 0) {
    free(buf);
    fprintf(stderr,"Failed to get password line: %m");
    return NULL;
  }

  if (buf==NULL) {
    fprintf(stderr,"Error occured, password reading success but buffer filling failed: %m");
    return NULL;    
  }
  
  if (buf[nread - 1] != '\n') {//char mandatory or password was too large
    fprintf(stderr,"Error password reading truncated");
    return NULL;
  } else {
    /* Remove the newline.  */
    buf[nread - 1] = '\0';//last char
    /* Write the newline that was not echoed.  */
    fprintf(fp,"\n");
  }

  /* Restore the original setting.  */
  if (tcsetattr (fileno (fp), TCSAFLUSH, &to)<0) {
    fprintf(stderr,"Failed to restore terminal attributes: %m");
    return NULL;
  }

  funlockfile(fp);

  if (fclose(fp)!=0) {
    fprintf(stderr,"Failed closing /dev/tty: %m");
    return NULL;
  }
  return buf;
}
