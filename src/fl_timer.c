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

#include <errno.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#include "falco/fl_stdlib.h"
#include "falco/fl_timer.h"
#include "falco/fl_logr.h"
#include "falco/fl_fds.h"

static LIST_HEAD(fl_timers_, fl_timer_t_) fl_timers;

static void fl_timer_dispatch(fl_timer_t *timer);

int fl_timer_module_init()
{
  LIST_INIT(&fl_timers);

  FL_LOGR_INFO("Falco Timer module initialized");
  return 0;
}

int fl_timer_module_dump(FILE *fd)
{
  register fl_timer_t *li;

  fprintf(fd, "\n--------------------------------------------------------------------------------\n");
  fprintf(fd, "Timers\n");
  fprintf(fd, "--------------------------------------------------------------------------------\n\n");

  if (LIST_EMPTY(&fl_timers)) {
    fprintf(fd, "    No timers are currently present\n");
    return 0;
  }

  LIST_FOREACH(li, &fl_timers, timer_lc) {
    fprintf(fd, "Name: %s(%d)\n", li->name, li->timerfd);
    if (li->task) {
      fprintf(fd, "    Task: %s\n", li->task->name);
    }
    fprintf(fd, "    when: %d seconds, interval: %d seconds\n",
            li->fire_when, li->fire_interval);
  }

  return 0;
}

void *fl_timer_create(fl_task_t *task, int fire_when, int fire_interval,
                      fl_app_timer_method_t timer_method,
                      const char *timer_name, void *app_data)
{
  register fl_timer_t *timer;

  FL_ASSERT((fire_interval > 0) && (fire_when == fire_interval));
  FL_ASSERT(timer_method);
  FL_ASSERT(timer_name && strlen(timer_name) &&
            (strlen(timer_name) < FL_TIMER_NAME_MAX_LEN));
  FL_LOGR_DEBUG("Request to create timer (%s)"
                "[fire at %d seconds, interval %d seconds]",
                timer_name, fire_when, fire_interval);

  FL_ALLOC(fl_timer_t, 1, timer, "Timer");
  if (!timer) {
    FL_LOGR_CRIT("%s(%s): Could not allocate memory for Timer",
                 __func__, timer_name);
    return NULL;
  }

  timer->timerfd = timerfd_create(CLOCK_MONOTONIC, 0);
  if (timer->timerfd < 0) {
    FL_LOGR_ERR("Timer (%s) creation failed, error <%s>", timer_name,
                strerror(errno));
    FL_FREE(timer, "Timer");
    return NULL;
  }

  timer->fire_when = fire_when;
  timer->fire_interval = fire_interval;
  timer->timer_method = timer_method;
  timer->app_data = app_data;
  (void) strcpy(timer->name, timer_name);

  if (LIST_EMPTY(&fl_timers)) {
    LIST_INSERT_HEAD(&fl_timers, timer, timer_lc);
  } else {
    fl_timer_t *timer_li;

    LIST_FOREACH(timer_li, &fl_timers, timer_lc) {
      if (timer_li->timerfd > timer->timerfd) {
        LIST_INSERT_BEFORE(timer_li, timer, timer_lc);
        break;
      }
      if (LIST_NEXT(timer_li, timer_lc) == NULL) {
        LIST_INSERT_AFTER(timer_li, timer, timer_lc);
        break;
      }
    }
  }

  if (task) {
    if (fl_task_validate_taskptr(task)) {
      if (LIST_EMPTY(&task->task_timers)) {
        LIST_INSERT_HEAD(&task->task_timers, timer, task_timer_lc);
      } else {
        fl_timer_t *timer_li;

        LIST_FOREACH(timer_li, &task->task_timers, task_timer_lc) {
          if (timer_li->timerfd > timer->timerfd) {
            LIST_INSERT_BEFORE(timer_li, timer, task_timer_lc);
            break;
          }
          if (LIST_NEXT(timer_li, task_timer_lc) == NULL) {
            LIST_INSERT_AFTER(timer_li, timer, task_timer_lc);
            break;
          }
        }
      }
      timer->task = task;
    } else {
      FL_LOGR_WARNING("Request to associate timer (%s) with an unrecognized "
                      "task (%s)", timer_name, task->name);
    }
  }

  FL_LOGR_DEBUG("Created timer (%s, %s, %d)"
                "[fire at %d seconds, interval %d seconds]",
                (task) ? task->name : "", timer_name, timer->timerfd,
                fire_when, fire_interval);
  return timer;
}

int fl_timer_start(fl_timer_t *timer)
{
  fl_task_t *task;

  if (!timer) {
    FL_ASSERT(timer);
    FL_LOGR_ERR("Request to start an invalid timer");
    return -1;
  }

  task = timer->task;

  timer->its.it_value.tv_sec = timer->fire_when;
  timer->its.it_interval.tv_sec = timer->fire_interval;
  if (timerfd_settime(timer->timerfd, 0, &(timer->its), NULL) < 0) {
    int save_errno = errno;
    FL_LOGR_ERR("Starting timer (%s, %s, %d) failed, error <%s>",
                (task) ? task->name : "", timer->name, timer->timerfd,
                strerror(save_errno));
    return -save_errno;
  }

  fl_fds_set_max_fd(timer->timerfd);
  FL_FD_SET(timer->timerfd, FL_FD_OP_READ);

  return 0;
}

int fl_timer_stop(fl_timer_t *timer)
{
  fl_task_t *task;

  if (!timer) {
    FL_ASSERT(timer);
    FL_LOGR_ERR("Request to stop an invalid (NULL) timer");
    return -1;
  }

  task = timer->task;

  timer->its.it_value.tv_sec = 0;
  timer->its.it_interval.tv_sec = 0;
  if (timerfd_settime(timer->timerfd, 0, &(timer->its), NULL) < 0) {
    int save_errno = errno;
    FL_LOGR_ERR("Stopping timer (%s, %s, %d) failed, error <%s>",
                (task) ? task->name : "", timer->name, timer->timerfd,
                strerror(save_errno));
    return -save_errno;
  }

  return 0;
}

int fl_timer_delete(fl_timer_t *timer)
{
  register fl_timer_t *timer_li;
  fl_task_t *task;

  char name[FL_TIMER_NAME_MAX_LEN] = { 0 };
  int fd, rc;

  if (!timer) {
    FL_ASSERT(timer);
    FL_LOGR_ERR("Request to delete an invalid timer");
    return -1;
  }

  LIST_FOREACH(timer_li, &fl_timers, timer_lc) {
    if (timer_li == timer) {
      break;
    }
  }
  if (!timer_li) {
    FL_ASSERT(timer_li);
    FL_LOGR_ERR("Request to delete timer (%s) not in list", timer->name);
    return -1;
  }

  task = timer->task;

  (void) strcpy(name, timer->name);
  fd = timer->timerfd;

  rc = close(fd);
  if (rc < 0) {
    FL_LOGR_ERR("Closing timer (%s, %s, %d) failed, error <%s>. "
                "Shall proceed to delete timer.",
                (task) ? task->name : "", name, fd, strerror(errno));
  }

  LIST_REMOVE(timer, timer_lc);
  FL_FREE(timer, "Timer");

  FL_LOGR_DEBUG("Deleted timer (%s, %s, %d)", (task) ? task->name : "",
                name, fd);
  return rc;
}

void fl_timers_dispatch(int *nfds, fd_set *fds)
{
  int save_nfds = *nfds;
  register fl_timer_t *timer;
  register int timerfd;

  FL_ASSERT((*nfds) >= 0);

  LIST_FOREACH(timer, &fl_timers, timer_lc) {
    timerfd = timer->timerfd;

    if (!FD_ISSET(timerfd, fds)) {
      continue;
    }

    FL_ASSERT(fl_fd_isset(timerfd, FL_FD_OP_READ));
    (*nfds)--;
    /* We do not clear timer fd from the read operation (i.e. select_rbits).
     * We only clear it from the exec_bits here.
     */
    FD_CLR(timerfd, fds);
    fl_timer_dispatch(timer);
  }

  if (save_nfds && ((save_nfds - *nfds) > 0)) {
    FL_LOGR_DEBUG("Processed %d timers", (save_nfds - *nfds));
  }
}

static void fl_timer_dispatch(fl_timer_t *timer)
{
  register int fd = timer->timerfd;
  register fl_task_t *task = timer->task;
  ssize_t rlen;
  uint64_t nexp;

  rlen = read(fd, &nexp, sizeof(uint64_t));
  if (rlen != sizeof(uint64_t)) {
    int save_errno = errno;
    FL_LOGR_ERR("Timer dispatch (%s, %s, %d) failed to read expirations, "
                "error %d, <%s>", (task) ? task->name : "", timer->name, fd,
                save_errno, strerror(save_errno));
  }

  if (nexp > 1) {
    FL_LOGR_ERR("Timer dispatch (%s, %s, %d) detected %llu expirations",
                (task) ? task->name : "", timer->name, fd,
                (unsigned long long) nexp);
  }

  FL_LOGR_DEBUG("Timer dispatch (%s, %s, %d) method started",
                (task) ? task->name : "", timer->name, fd);
  timer->timer_method(timer->name, timer->app_data);
  FL_LOGR_DEBUG("Timer dispatch (%s, %s, %d) method completed",
                (task) ? task->name : "", timer->name, fd);
}
