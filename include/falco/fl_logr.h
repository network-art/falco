/*******************************************************************************
BSD 3-Clause License

Copyright (c) 2014 - 2020, NetworkArt Systems Private Limited (www.networkart.com)
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
   list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its
   contributors may be used to endorse or promote products derived from
   this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*******************************************************************************/

#ifndef _FL_LOGR_H_
#define _FL_LOGR_H_

#include <stdio.h>
#include <syslog.h>

#define LOG_PRIORITY_CMP(_log_prio_) (_log_prio_ <= cfg_log_priority)

#define FL_LOGR_EMERG(_fmt_...)                  \
  do {                                           \
    syslog(LOG_EMERG, _fmt_);                    \
    (void) fprintf(stderr, _fmt_);               \
  } while(0)

#define FL_LOGR_ALERT(_fmt_...)                  \
  do {                                           \
    syslog(LOG_ALERT, _fmt_);                    \
    (void) fprintf(stderr, _fmt_);               \
  } while(0)

#define FL_LOGR_CRIT(_fmt_...)                    \
  do {                                            \
    int _lp = LOG_CRIT;                           \
    if (LOG_PRIORITY_CMP(_lp)) {                  \
      syslog(_lp, _fmt_);                         \
      (void) fprintf(stderr, _fmt_);              \
    }                                             \
  } while(0)

#define FL_LOGR_ERR(_fmt_...)                    \
  do {                                           \
    int _lp = LOG_ERR;                           \
    if (LOG_PRIORITY_CMP(_lp)) {                 \
      syslog(_lp, _fmt_);                        \
    }                                            \
  } while(0)

#define FL_LOGR_WARNING(_fmt_...)                \
  do {                                           \
    int _lp = LOG_WARNING;                       \
    if (LOG_PRIORITY_CMP(_lp)) {                 \
      syslog(_lp, _fmt_);                        \
    }                                            \
  } while(0)

#define FL_LOGR_NOTICE(_fmt_...)                 \
  do {                                           \
    int _lp = LOG_NOTICE;                        \
    if (LOG_PRIORITY_CMP(_lp)) {                 \
      syslog(_lp, _fmt_);                        \
    }                                            \
  } while(0)

#define FL_LOGR_INFO(_fmt_...)                   \
  do {                                           \
    int _lp = LOG_INFO;                          \
    if (LOG_PRIORITY_CMP(_lp)) {                 \
      syslog(_lp, _fmt_);                        \
    }                                            \
  } while(0)

#define FL_LOGR_DEBUG(_fmt_...)                  \
  do {                                           \
    int _lp = LOG_DEBUG;                         \
    if (LOG_PRIORITY_CMP(_lp)) {                 \
      syslog(_lp, _fmt_);                        \
    }                                            \
  } while(0)

extern void fl_logr_openlog(const char *);
extern void fl_logr_closelog(const char *);
extern void fl_logr_cfg_priority(int);

extern int cfg_log_priority;

#endif /* _FL_LOGR_H_ */
