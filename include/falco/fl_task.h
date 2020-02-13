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

#ifndef _FL_TASK_H_
#define _FL_TASK_H_

#include <sys/queue.h>

#include "falco/fl_socket.h"

#define FL_TASK_NAME_MAX_LEN 32

typedef void (*fl_task_reinit_method_t)(struct fl_task_t_ *);
typedef void (*fl_task_terminate_method_t)(struct fl_task_t_ *);
typedef void (*fl_task_dump_method_t)(struct fl_task_t_ *);

typedef struct fl_task_t_ {
  LIST_ENTRY(fl_task_t_) task_lc;

  char name[FL_TASK_NAME_MAX_LEN];

  LIST_HEAD(, fl_timer_t_) task_timers;
  LIST_HEAD(, fl_socket_t_) task_sockets;

  fl_task_reinit_method_t reinit_method;
  fl_task_terminate_method_t terminate_method;
  fl_task_dump_method_t dump_method;

} fl_task_t;

extern int fl_task_module_init(void);
extern int fl_task_module_dump(FILE *fd);

extern fl_task_t *fl_task_create(const char *name);
extern void fl_task_delete(fl_task_t *task);
extern fl_task_t *fl_task_validate_taskptr(fl_task_t *task);

extern void fl_tasks_reinit();
extern void fl_tasks_terminate();

#endif /* _FL_TASK_H_ */
