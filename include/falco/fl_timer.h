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

#ifndef _FL_TIMER_H_
#define _FL_TIMER_H_

#include <sys/queue.h>
#include <sys/timerfd.h>

#include "falco/fl_task.h"

#define FL_TIMER_NAME_MAX_LEN 32

typedef void (*fl_app_timer_method_t)(const char *timer_name, void *app_data);

typedef struct fl_timer_t_ {
  LIST_ENTRY(fl_timer_t_) timer_lc;
  LIST_ENTRY(fl_timer_t_) task_timer_lc;

  /* Data provided by the application */
  int fire_when;
  int fire_interval;
  char name[FL_TIMER_NAME_MAX_LEN];
  fl_app_timer_method_t timer_method;
  void *app_data;

  /* Falco Timer module internal data */
  int timerfd;
  struct itimerspec its;
  fl_task_t *task;
} fl_timer_t;

extern int fl_timer_module_init(void);
extern int fl_timer_module_dump(FILE *fd);

extern void *fl_timer_create(fl_task_t *task, int fire_when, int fire_interval,
                             fl_app_timer_method_t timer_method,
                             const char *timer_name, void *app_data);
extern int fl_timer_start(fl_timer_t *timer);
extern int fl_timer_stop(fl_timer_t *timer);
extern int fl_timer_delete(fl_timer_t *timer);

extern void fl_timers_dispatch(int *nfds, fd_set *rfds);

#endif /* _FL_TIMER_H_ */
