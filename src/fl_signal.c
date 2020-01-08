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

#include "falco/fl_logr.h"
#include "falco/fl_signal.h"

const values_t fl_signals[] = {
  { SIGHUP,  "Reconfigure" },
  { SIGABRT, "Abort" },
  { SIGKILL, "Kill" },
  { SIGTERM, "Terminate" },
  { SIGUSR1, "User 1" },
  { SIGUSR2, "User 2" },
  { SIGTSTP, "Stop from Tty", },
  { SIGTTIN, "TTY Input" },
  { SIGTTOU, "TTY Output" }
};

int fl_signal_add(int sig, fl_sighandler_t sighandler)
{
  struct sigaction sigact;

  (void) memset(&sigact, 0, sizeof(struct sigaction));
  sigact.sa_flags = SA_SIGINFO;
  sigact.sa_sigaction = sighandler;
  sigemptyset(&sigact.sa_mask);

  if (sigaction(sig, &sigact, NULL) < 0) {
    FL_LOGR_ERR("Unable to add handler for %d(%s), error <%s>",
                sig, fl_trace_value(fl_signals, sig), strerror(errno));
    return(-1);
  }
  FL_LOGR_DEBUG("Added handler for %d(%s)",
                sig, fl_trace_value(fl_signals, sig));
  return(0);
}

int fl_signal_remove(int sig)
{
  struct sigaction sigact;

  (void) memset(&sigact, 0, sizeof(struct sigaction));

  if (sigaction(sig, &sigact, NULL) < 0) {
    FL_LOGR_ERR("Unable to remove handler for %d(%s), error <%s>",
                sig, fl_trace_value(fl_signals, sig), strerror(errno));
    return(-1);
  }
  FL_LOGR_DEBUG("Removed handler for %d(%s)",
                sig, fl_trace_value(fl_signals, sig));
  return(0);
}
