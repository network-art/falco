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

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

#include "falco/fl_logr.h"
#include "falco/fl_signal.h"
#include "falco/fl_process.h"

int fl_daemonize_process(void)
{
  int new_pid;

  (void) fl_signal_remove(SIGTSTP);
  (void) fl_signal_remove(SIGTTOU);
  (void) fl_signal_remove(SIGTTIN);

  switch (fork()) {
  case -1:
    {
      FL_LOGR_CRIT("Couldn't daemonize, something is terribly wrong, "
                   "error <%s>, exiting.", strerror(errno));
      exit(1);
    }
    break;

  case 0:
    /* Success, I am a child now */
    break;

  default:
    /* Success, I am the parent now, let me go away silently and let my child
     * do her job
     */
    exit(0);
  }

  new_pid = setsid();
  if (new_pid < 0) {
    FL_LOGR_ERR("Could not create new session, error %d <%s>", new_pid,
                strerror(errno));
    return(new_pid);
  }
  FL_LOGR_INFO("now belongs to new session %d", new_pid);

  switch (fork()) {
  case -1:
    {
      FL_LOGR_CRIT("Couldn't fork the second time, something is terribly"
                   " wrong, error <%s>, exiting.", strerror(errno));
      exit(1);
    }
    break;

  case 0:
    /* Success, I am a child now */
    break;

  default:
    /* Success, I am the parent now, let me go away silently and let my child
     * do her job.
     */
    exit(0);
  }

  umask(022);
  return(0);
}
