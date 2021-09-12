/*
  This file is part of xlogin display manager

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

#include <stdarg.h>
#include <stddef.h>//NULL
#include <syslog.h>//vsyslog
#include <stdio.h> //vsnprintf

void vwritelog(const char *const template, ...);
int vsnprintf_managed(char *str, const int size, const char *const template, ...);

/*
 * msg to syslog (%m means strerror(errno))
 */
void vwritelog(const char *const template, ...) {
  //man 3 syslog
  //man 3 stdarg
  va_list ap;
  va_start(ap,template);
  openlog(NULL,LOG_ODELAY,LOG_DAEMON);
  vsyslog(LOG_CRIT,template,ap);
  closelog();
  va_end(ap);
}

/*
 * snprintf_managed: helper setting str reading size from value and fail if value's size greater than size param
 */
int vsnprintf_managed(char *str, const int size, const char *const template, ...) {
  if (size==0) {
    vwritelog("vsnprintf_managed: error, size can't be 0");
    return 0;//false
  }
  //
  //man 3 stdarg
  va_list ap;
  va_start(ap,template);
  const int result=vsnprintf(str,size,template,ap);
  va_end(ap);
  //  
  if (result>=size){//size insuficent for value
    vwritelog("vsnprintf_managed: Failed to set char, insuficient size: %m");
    return 0;
  }
  if (result<0){//snprintf error
    vwritelog("vsnprintf_managed: Failed to set char because snprintf error %m");
    return 0;
  }
  return 1;//true
}

