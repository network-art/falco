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

/**
 * @file
 * @brief Logging and Tracing
 */

#ifndef _FL_LOGR_H_
#define _FL_LOGR_H_

#include <stdio.h>
#include <stdarg.h>
#include <syslog.h>

#define LOG_PRIORITY_CMP(_log_prio_) (_log_prio_ <= cfg_log_priority)

/**
 * @brief Convenience macro to log a message with priority emergency.
 */
#define FL_LOGR_EMERG(_fmt_...)                  \
  do {                                           \
    syslog(LOG_EMERG, _fmt_);                    \
    (void) fprintf(stderr, _fmt_);               \
  } while(0)

/**
 * @brief Convenience macro to log a message with priority alert.
 */
#define FL_LOGR_ALERT(_fmt_...)                  \
  do {                                           \
    syslog(LOG_ALERT, _fmt_);                    \
    (void) fprintf(stderr, _fmt_);               \
  } while(0)

/**
 * @brief Convenience macro to log a message with priority critical.
 */
#define FL_LOGR_CRIT(_fmt_...)                    \
  do {                                            \
    int _lp = LOG_CRIT;                           \
    if (LOG_PRIORITY_CMP(_lp)) {                  \
      syslog(_lp, _fmt_);                         \
      (void) fprintf(stderr, _fmt_);              \
    }                                             \
  } while(0)

/**
 * @brief Convenience macro to log a message with priority error.
 */
#define FL_LOGR_ERR(_fmt_...)                    \
  do {                                           \
    int _lp = LOG_ERR;                           \
    if (LOG_PRIORITY_CMP(_lp)) {                 \
      syslog(_lp, _fmt_);                        \
    }                                            \
  } while(0)

/**
 * @brief Convenience macro to log a message with priority warning.
 */
#define FL_LOGR_WARNING(_fmt_...)                \
  do {                                           \
    int _lp = LOG_WARNING;                       \
    if (LOG_PRIORITY_CMP(_lp)) {                 \
      syslog(_lp, _fmt_);                        \
    }                                            \
  } while(0)

/**
 * @brief Convenience macro to log a message with priority notice.
 */
#define FL_LOGR_NOTICE(_fmt_...)                 \
  do {                                           \
    int _lp = LOG_NOTICE;                        \
    if (LOG_PRIORITY_CMP(_lp)) {                 \
      syslog(_lp, _fmt_);                        \
    }                                            \
  } while(0)

/**
 * @brief Convenience macro to log a message with priority informational.
 */
#define FL_LOGR_INFO(_fmt_...)                   \
  do {                                           \
    int _lp = LOG_INFO;                          \
    if (LOG_PRIORITY_CMP(_lp)) {                 \
      syslog(_lp, _fmt_);                        \
    }                                            \
  } while(0)

/**
 * @brief Convenience macro to log a message with priority debug.
 */
#define FL_LOGR_DEBUG(_fmt_...)                  \
  do {                                           \
    int _lp = LOG_DEBUG;                         \
    if (LOG_PRIORITY_CMP(_lp)) {                 \
      syslog(_lp, _fmt_);                        \
    }                                            \
  } while(0)

/**
 * @brief Open a connection to the system logger.
 *
 * Open a connection to the system logger for the application. The string
 * pointed to by @p ident is prepended to every message, and is typically set
 * to the program name.
 *
 * The following options are passed to the system logger:
 * LOG_CONS | LOG_NDELAY | LOG_PID, LOG_LOCAL0.
 *
 * @param[in] ident Typically the program or the application name
 *
 * @see Documentation for openlog() describes the options passed to the system
 * logger.
 *
 */
extern void fl_logr_openlog(const char *ident);

/**
 * @brief Close the connection to the system logger.
 *
 * Closes the connection the system logger (that was previously opened using
 * fl_logr_openlog()).
 *
 * @param[in] ident Typically the program or the application name, passed
 *                  previously to fl_logr_openlog().
 *
 */
extern void fl_logr_closelog(const char *ident);

/**
 * @brief Configure the priority for the logger.
 *
 * Configure/Set the priority for the logger. The default priority is the log
 * level LOG_INFO used in syslog.
 *
 * @param[in] priority Priority or syslog log level. Acceptable values are:
 *
 *     LOG_EMERG (highest)
 *     LOG_ALERT
 *     LOG_CRIT
 *     LOG_ERR
 *     LOG_WARNING
 *     LOG_NOTICE
 *     LOG_INFO (Default)
 *     LOG_DEBUG
 *
 */
extern void fl_logr_cfg_priority(int priority);

/**
 * @brief Generate and send message to the system logger.
 *
 * @param[in] priority Priority or syslog log level. See fl_logr_cfg_priority()
 *                     for a list of acceptable priorities.
 * @param[in] format Format string of the message followed by a variable number
 *                   of arguments
 *
 */
extern void fl_logr_log(int priority, const char *format, ...);

/**
 * @brief Generate and send message to the system logger.
 *
 * This function performs the same task as fl_logr_log() with the difference
 * that it takes a set of arguments which have been obtained using stdarg(3)
 * variable argument list macros.
 *
 * @param[in] priority Priority or syslog log level. See fl_logr_cfg_priority()
 *                     for a list of acceptable priorities.
 * @param[in] format Format string of the message
 * @param[in] args Variable arguments list
 *
 */
extern void fl_logr_vlog(int priority, const char *format, va_list args);

extern int cfg_log_priority;

#endif /* _FL_LOGR_H_ */
