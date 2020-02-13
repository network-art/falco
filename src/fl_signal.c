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
#include <errno.h>

#include "falco/fl_stdlib.h"
#include "falco/fl_tracevalue.h"
#include "falco/fl_logr.h"
#include "falco/fl_signal.h"

const values_t fl_signals[] = {
  { SIGHUP,  "Reconfigure"    },
  { SIGABRT, "Abort"          },
  { SIGKILL, "Kill"           },
  { SIGTERM, "Terminate"      },
  { SIGUSR1, "User 1"         },
  { SIGUSR2, "User 2"         },
  { SIGTSTP, "Stop from TTY", },
  { SIGTTIN, "TTY Input"      },
  { SIGTTOU, "TTY Output"     }
};

int fl_signal_register_handlers(fl_signal_handler_regn_t *sighandler_registrations)
{
  fl_signal_handler_regn_t *sr;

  for (sr = sighandler_registrations; sr->signum; sr++) {
    if (fl_signal_add(sr->signum, sr->signal_handler) < 0) {
      return -1;
    }
  }

  return 0;
}

int fl_signal_add(int signum, fl_signal_handler_t sighandler)
{
  struct sigaction act;

  (void) memset(&act, 0, sizeof(struct sigaction));
  act.sa_flags = SA_SIGINFO;
  act.sa_sigaction = sighandler;
  sigemptyset(&act.sa_mask);

  if (sigaction(signum, &act, NULL) < 0) {
    FL_LOGR_ERR("Unable to add handler for %d(%s), error <%s>",
                signum, fl_trace_value(fl_signals, signum), strerror(errno));
    return(-1);
  }
  FL_LOGR_DEBUG("Added handler for %d(%s)",
                signum, fl_trace_value(fl_signals, signum));
  return(0);
}

int fl_signal_remove(int signum)
{
  struct sigaction act;

  (void) memset(&act, 0, sizeof(struct sigaction));

  if (sigaction(signum, &act, NULL) < 0) {
    FL_LOGR_ERR("Unable to remove handler for %d(%s), error <%s>",
                signum, fl_trace_value(fl_signals, signum), strerror(errno));
    return(-1);
  }
  FL_LOGR_DEBUG("Removed handler for %d(%s)",
                signum, fl_trace_value(fl_signals, signum));
  return(0);
}

int fl_signals_block(int *signals, sigset_t *set)
{
  int *signum, save_errno, added;

  FL_ASSERT(set);
  if (sigemptyset(set)) {
    save_errno = errno;
    FL_LOGR_ERR("Could not initialize signal set for blocking, error %d <%s>",
                save_errno, strerror(save_errno));
    return 0;
  }

  added = 0;
  for (signum = signals; *signum; signum++) {
    if (sigaddset(set, *signum)) {
      save_errno = errno;
      FL_LOGR_ERR("Could not add %d(%s) signal set, error %d <%s>",
                  *signum, fl_trace_value(fl_signals, *signum),
                  save_errno, strerror(save_errno));
    } else {
      added++;
    }
  }

  if (!added) {
    return 0;
  }

  if (sigprocmask(SIG_BLOCK, set, NULL)) {
    save_errno = errno;
    FL_LOGR_ERR("Could not block signals, error %d <%s>",
                save_errno, strerror(save_errno));
    return 0;
  }

  return 1;
}

int fl_signals_unblock(sigset_t *set)
{
  if (sigprocmask(SIG_UNBLOCK, set, NULL)) {
    int save_errno = errno;
    FL_LOGR_ERR("Could not unblock signals, error %d <%s>",
                save_errno, strerror(save_errno));
    return -1;
  }

  return 0;
}
