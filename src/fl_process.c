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
#include <sys/file.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

#include "falco/fl_defs.h"
#include "falco/fl_logr.h"
#include "falco/fl_signal.h"
#include "falco/fl_timer.h"
#include "falco/fl_task.h"
#include "falco/fl_socket.h"
#include "falco/fl_process.h"

int fl_init(void)
{

  if (fl_timer_module_init() < 0) {
    FL_LOGR_CRIT("Falco Timer module initialization failed");
    return -1;
  }
  if (fl_socket_module_init() < 0) {
    FL_LOGR_CRIT("Falco Socket module initialization failed");
    return -1;
  }
  if (fl_task_module_init() < 0) {
    FL_LOGR_CRIT("Falco Task module initialization failed");
    return -1;
  }

  return 0;
}

int fl_process_daemonize(void)
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

int fl_process_open_pid_file(const char *progname)
{
  char pid_filepath[MAXPATHLEN] = { 0 };
  char pid_buf[LINE_MAX] = { 0 };
  int pid = getpid(), fd, rc, len;

  if (!progname || !strlen(progname)) {
    FL_LOGR_ERR("Program name / PID file path cannot be NULL or empty");
    return -EINVAL;
  }

  if (progname[0] == '/') {
    (void) sprintf(pid_filepath, "%s", progname);
  } else {
    (void) sprintf(pid_filepath, "%s%s.pid", _PATH_PID, progname);
  }

  fd = open(pid_filepath, O_RDWR | O_CREAT | O_SYNC, 0644);
  if (fd < 0) {
    int save_errno = errno;
    FL_LOGR_ERR("Could not open %s to store PID %d, error <%s>",
                pid_filepath, pid, strerror(save_errno));
    return -save_errno;
  }

  rc = flock(fd, LOCK_EX | LOCK_NB);
  if (rc < 0) {
    int save_errno = errno;
    int epid;

    if (save_errno == EWOULDBLOCK) {
      len = read(fd, pid_buf, sizeof(pid_buf));
      if ((len > 0) && (epid = atoi(pid_buf))) {
        FL_LOGR_ERR("Could not obtain lock on %s, %s[%d] seems to be "
                    "still running", pid_filepath, progname, epid);
      } else {
        FL_LOGR_ERR("Could not obtain lock on %s, another instance of %s seems "
                    "to be running", pid_filepath, progname);
      }
      FL_LOGR_ERR("If you are sure that no other instance of %s is running, "
                  "then please remove %s and restart the program.",
                  progname, pid_filepath);
    } else {
      FL_LOGR_ERR("Failed to obtain lock on %s, error <%s>", pid_filepath,
                  strerror(save_errno));
    }

    (void) close(fd);
    return -save_errno;
  }

  len = sprintf(pid_buf, "%d\n", pid);
  if (write(fd, pid_buf, len) != len) {
    int save_errno = errno;
    FL_LOGR_ERR("Could not write pid(%d) to file %s, error <%s>", pid,
                pid_filepath, strerror(save_errno));
    return -save_errno;
  }

  FL_LOGR_INFO("%s now records pid %d", pid_filepath, pid);
  return fd;
}

int fl_process_close_pid_file(const char *progname, int pid_fd)
{
  char pid_filepath[MAXPATHLEN] = { 0 };

  if (pid_fd && (close(pid_fd) == -1)) {
    FL_LOGR_ERR("Attempt to close PID fd %d failed, error <%s>", pid_fd,
                strerror(errno));
  }

  if (!progname || !strlen(progname)) {
    FL_LOGR_ERR("Program name / PID file path cannot be NULL or empty");
    return -EINVAL;
  }

  if (progname[0] == '/') {
    (void) sprintf(pid_filepath, "%s", progname);
  } else {
    (void) sprintf(pid_filepath, "%s%s.pid", _PATH_PID, progname);
  }

  if (unlink(pid_filepath) == -1) {
    int save_errno = errno;
    FL_LOGR_ERR("Could not remove %s, error <%s>", pid_filepath,
                strerror(save_errno));
    return -save_errno;
  }

  FL_LOGR_INFO("Removed %s", pid_filepath);
  return 0;
}
