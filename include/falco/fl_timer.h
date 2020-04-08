/*******************************************************************************
BSD 3-Clause License

Copyright (c) 2014 - 2020, NetworkArt Systems Private Limited (www.networkart.com).
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
 * @brief Timer Management
 *
 * Applications can use this module to create, start (arm), stop (disarm) and
 * delete timers. Methods (or callback routines) can be associated with a timer.
 * They are invoked when the timer fires (i.e. upon timeout).
 *
 * This module uses the timerfd infrastructure in linux. Underneath the APIs,
 * @c timerfd_create() is to used to create a timer. @c timerfd_settime() is
 * used to arm or disarm the timer. When a timer is deleted, the file
 * descriptor associated with the timer is closed.
 */

#ifndef _FL_TIMER_H_
#define _FL_TIMER_H_

#include <sys/queue.h>
#include <sys/timerfd.h>

#include "falco/fl_task.h"

/**
 * @brief Maximum length of a timer name (including the trailing delimiter).
 */
#define FL_TIMER_NAME_MAX_LEN 32

/**
 * @brief Type definition of callback routines or methods which are called when
 * a timer fires.
 */
typedef void (*fl_app_timer_method_t)(const char *timer_name, void *app_data);

/**
 * @brief Falco Timer
 */
typedef struct fl_timer_t_ {
  /**
   * @brief List connector for all timers.
   */
  LIST_ENTRY(fl_timer_t_) timer_lc;
  /**
   * @brief List connector for all timers associated with a task.
   */
  LIST_ENTRY(fl_timer_t_) task_timer_lc;

  /* Data provided by the application */
  int fire_when; ///< Initial expiration of the timer (in seconds)
  int fire_interval; ///< Interval for periodic timer (in seconds)
  /**
   * @brief Timer name specified by the application in #fl_timer_create().
   */
  char name[FL_TIMER_NAME_MAX_LEN];
  fl_app_timer_method_t timer_method; ///< Method invoked upon timeout
  /**
   * @brief Opaque data (or context) registered by the application in
   * #fl_timer_create(). This is passed to the application with the timeout
   * method.
   */
  void *app_data;

  /* Falco Timer module internal data */
  int timerfd; ///< (Timer) File descriptor returned by @c timerfd_create()
  struct itimerspec its; ///< Period interval
  fl_task_t *task; ///< Task with which this timer is associated

  /* Stats */
  /**
   * @brief Number of times this timer has been dispatched after
   * timeout/expiration
   */
  u_int32_t ndispatches;
} fl_timer_t;

/**
 * @brief Initialize timer management module
 *
 * @return On success, 0 is returned. On error, -1 is returned.
 */
extern int fl_timer_module_init(void);
/**
 * @brief Dump the status and state of the module.
 *
 * @param[in] fd Stream to which the status and state of all modules needs to
 *               be written. If this parameter is NULL, then the output is
 *               written to syslog.
 *
 * @return On success, 0 is returned. On error, -1 is returned.
 */
extern int fl_timer_module_dump(FILE *fd);

/**
 * @brief Create a new falco timer
 *
 * This function creates a new falco timer object. @c timerfd_create() is used
 * to create the timer, and the returned file descriptor is stored in timerfd.
 *
 * @param[in] task (Optional) Task to which this timer needs to be associated
 * @param[in] fire_when One shot timer expiration value
 * @param[in] fire_interval Periodic interval value
 * @param[in] timer_method Method (or callback routine) invoked when the timer
 *                         fires (reaches expiration)
 * @param[in] timer_name String of length not exceeding #FL_TIMER_NAME_MAX_LEN
 * @param[in] app_data Application data (or context) that needs to be presented
 *                     to the application when the timeout method is called.
 *
 * @return On success, a pointer to a falco timer object is returned.
 * Otherwise, NULL is returned.
 *
 * @see @c timerfd_create(2)
 */
extern void *fl_timer_create(fl_task_t *task, int fire_when, int fire_interval,
                             fl_app_timer_method_t timer_method,
                             const char *timer_name, void *app_data);

/**
 * @brief Start or arm a timer
 *
 * This function starts (or arms) the timer with the periodic interval value
 * that was supplied by the application in #fl_timer_create().
 *
 * @param[in] timer Pointer to the #fl_timer_t object
 * @param[in] app_data Application data (or context) that needs to be presented
 *                     to the application when the timeout method is called.
 *                     Note that this parameter overrides any application data
 *                     associated with the timer earlier (for example, data
 *                     provided during #fl_timer_create()).
 *
 * @return On success, 0 is returned. On error, -1 is returned.
 *
 * @see @c timerfd_settime(2)
 */
extern int fl_timer_start(fl_timer_t *timer, void *app_data);

/**
 * @brief Stop or disarm a timer
 *
 * @param[in] timer Pointer to the #fl_timer_t object
 *
 * @return On success, 0 is returned. On error, -1 is returned.
 *
 * @see @c timerfd_settime(2)
 */
extern int fl_timer_stop(fl_timer_t *timer);

/**
 * @brief Delete a timer
 *
 * The file descriptor (@c timerfd) associated with the timer is closed.
 *
 * @param[in] timer Pointer to the #fl_timer_t object
 *
 * @return On success, 0 is returned. On error, -1 is returned.
 */
extern int fl_timer_delete(fl_timer_t *timer);

/**
 * @brief Dispatch all timers which have expirations
 *
 * This function iterates through all the timers, checks if the timer has
 * expirations and invokes the corresponding application methods (with the
 * data or context presented by the application earlier).
 *
 * @param[in,out] nfds Number of file descriptors that need to be read. It is
 *                     decremented by the number of timers that were dispatched
 *                     in this dispatch run.
 * @param[in,out] rfds Set of file descriptors (associated with the timers).
 */
extern void fl_timers_dispatch(int *nfds, fd_set *rfds);

#endif /* _FL_TIMER_H_ */
