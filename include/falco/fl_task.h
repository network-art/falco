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
 * @brief Task Management
 *
 * Two sets of APIs are provided.
 * 1. APIs that start with @c fl_task_ operate on a single task.
 * 2. APIs that start with @c fl_tasks_ operate on all tasks.
 */

#ifndef _FL_TASK_H_
#define _FL_TASK_H_

#include <sys/queue.h>

#include "falco/fl_socket.h"

/**
 * @brief Maximum length of a task name (including the trailing delimiter).
 */
#define FL_TASK_NAME_MAX_LEN 32

/**
 * @brief Definition for methods that reinitialize a task.
 */
typedef void (*fl_task_reinit_method_t)(struct fl_task_t_ *);

/**
 * @brief Definition for methods that gracefully terminate a task.
 */
typedef void (*fl_task_terminate_method_t)(struct fl_task_t_ *);

/**
 * @brief Definition for methods that dump the status and state of a task.
 */
typedef void (*fl_task_dump_method_t)(struct fl_task_t_ *);

/**
 * @brief Representation of a falco task.
 */
typedef struct fl_task_t_ {
  LIST_ENTRY(fl_task_t_) task_lc;

  char name[FL_TASK_NAME_MAX_LEN];

  LIST_HEAD(, fl_timer_t_) task_timers;
  LIST_HEAD(, fl_socket_t_) task_sockets;

  fl_task_reinit_method_t reinit_method;
  fl_task_terminate_method_t terminate_method;
  fl_task_dump_method_t dump_method;

} fl_task_t;

/**
 * @brief Initialize task module.
 *
 * @return On success, 0 is returned. On error, -1 is returned.
 */
extern int fl_task_module_init(void);

/**
 * @brief Dump the status and state of the task module.
 *
 * @param[in] fd Stream to which the status and state of all modules needs to
 *               be written. If this parameter is NULL, then the output is
 *               written to syslog.
 *
 * @return On success, 0 is returned. On error, -1 is returned.
 */
extern int fl_task_module_dump(FILE *fd);

/**
 * @brief Create a task.
 *
 * @detail Create a task with its name set to the content of the string pointed
 * to by @p name.
 *
 * @param[in] name Mandatory parameter with a minimum length of 1 and maximum
 * length of @c FL_TASK_NAME_MAX_LEN minus @c 1.
 *
 * @return On success, a pointer to the task is returned.
 * On error, @c NULL is returned.
 */
extern fl_task_t *fl_task_create(const char *name);

/**
 * @brief Delete a task.
 *
 * @detail Delete the task pointed to by the parameter @p task.
 *
 * @return On success, 0 is returned. On error, -1 is returned.
 */
extern int fl_task_delete(fl_task_t *task);

/**
 * @brief Validate pointer to a task.
 *
 * @detail This is a convenience function for applications to verify or
 * validate a pointer to a task. The task pointer is compared with tasks
 * currently maintained by the module.
 *
 * @return If the @p task exists, then, the pointer to the @c task is returned.
 * If the @p task does not exist, then, @c NULL is returned.
 * 
 */
extern fl_task_t *fl_task_validate_taskptr(fl_task_t *task);

/**
 * @brief Reinitialize all tasks.
 *
 * @detail Reinitialize all tasks currently maintained by the module. This
 * function causes the @c reinit_method() of all the tasks to be invoked.
 *
 */
extern void fl_tasks_reinit();

/**
 * @brief Terminate all tasks.
 *
 * @detail Terminate all tasks currently maintained by the module. This
 * function causes the @c terminate_method() of all the tasks to be invoked.
 *
 */
extern void fl_tasks_terminate();

#endif /* _FL_TASK_H_ */
