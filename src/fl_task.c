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

#include <string.h>

#include "falco/fl_stdlib.h"
#include "falco/fl_task.h"
#include "falco/fl_socket.h"
#include "falco/fl_timer.h"

static LIST_HEAD(fl_tasks_, fl_task_t_) fl_tasks;

int fl_task_module_init(void)
{
  LIST_INIT(&fl_tasks);

  FL_LOGR_INFO("Falco Task module initialized");
  return 0;
}

int fl_task_module_dump(FILE *fd)
{
  register fl_task_t *task_li;
  register fl_timer_t *task_timer_li;
  register fl_socket_t *task_socket_li;
  register int ntimers, nsockets;

  fprintf(fd, "\n--------------------------------------------------------------------------------\n");
  fprintf(fd, "Tasks\n");
  fprintf(fd, "--------------------------------------------------------------------------------\n\n");

  if (LIST_EMPTY(&fl_tasks)) {
    fprintf(fd, "    No tasks are currently present\n");
    return 0;
  }

  LIST_FOREACH(task_li, &fl_tasks, task_lc) {
    ntimers = nsockets = 0;

    fprintf(fd, "%s\n", task_li->name);
    fprintf(fd, "--------------------------------\n");
    fprintf(fd, "    reinit method: %s\n",
            (task_li->reinit_method) ? "yes" : "no");
    fprintf(fd, "    reinit method: %s\n",
            (task_li->terminate_method) ? "yes" : "no");
    fprintf(fd, "    dump method:   %s\n",
            (task_li->dump_method) ? "yes" : "no");

    LIST_FOREACH(task_timer_li, &task_li->task_timers, task_timer_lc) {
      ntimers++;
    }
    LIST_FOREACH(task_socket_li, &task_li->task_sockets, task_socket_lc) {
      ntimers++;
    }

    fprintf(fd, "    %d timers, %d sockets\n", ntimers, nsockets);
    fprintf(fd, "\n");
  }

  return 0;
}

fl_task_t *fl_task_create(const char *name)
{
  fl_task_t *task;

  FL_ASSERT(name && strlen(name) && (strlen(name) < FL_TASK_NAME_MAX_LEN));

  FL_ALLOC(fl_task_t, 1, task, "Task");
  if (!task) {
    return NULL;
  }

  (void) strcpy(task->name, name);
  if (LIST_EMPTY(&fl_tasks)) {
    LIST_INSERT_HEAD(&fl_tasks, task, task_lc);
  } else {
    register fl_task_t *task_li;

    LIST_FOREACH(task_li, &fl_tasks, task_lc) {
      if (strcmp(task_li->name, task->name) > 0) {
        LIST_INSERT_BEFORE(task_li, task, task_lc);
        break;
      }
      if (!LIST_NEXT(task_li, task_lc)) {
        LIST_INSERT_AFTER(task_li, task, task_lc);
        break;
      }
    }
  }

  LIST_INIT(&task->task_timers);
  LIST_INIT(&task->task_sockets);

  return NULL;
}

void fl_task_delete(fl_task_t *task)
{
}

fl_task_t *fl_task_validate_taskptr(fl_task_t *task)
{
  register fl_task_t *task_li;

  LIST_FOREACH(task_li, &fl_tasks, task_lc) {
    if (task_li == task) {
      return task;
    }
  }

  return NULL;
}

void fl_tasks_reinit()
{
}

void fl_tasks_terminate()
{
}
