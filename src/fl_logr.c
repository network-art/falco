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

#include "falco/fl_logr.h"
#include "falco/fl_tracevalue.h"

int cfg_log_priority = LOG_INFO;

static const values_t syslog_priorities[] = {
  { LOG_EMERG,   "Emergency" },
  { LOG_ALERT,   "Alert"     },
  { LOG_CRIT,    "Critical"  },
  { LOG_ERR,     "Error"     },
  { LOG_WARNING, "Warning"   },
  { LOG_NOTICE,  "Notice"    },
  { LOG_INFO,    "Info"      },
  { LOG_DEBUG,   "Debug"     },
  { 0, NULL }
};

void fl_logr_openlog(const char *ident)
{
  openlog(ident, LOG_CONS | LOG_NDELAY | LOG_PID, LOG_LOCAL0);
  FL_LOGR_INFO("Logging started for %s", ident);
}

void fl_logr_closelog(const char *ident)
{
  openlog(ident, LOG_CONS | LOG_NDELAY | LOG_PID, LOG_LOCAL0);
  FL_LOGR_INFO("Logging stopped for %s", ident);
}

void fl_logr_cfg_priority(int priority)
{
  if ((priority < LOG_EMERG) && (priority > LOG_DEBUG)) {
    FL_LOGR_ERR("Invalid syslog priority (%d) configuration", priority);
    return;
  }

  if (cfg_log_priority != priority) {
    FL_LOGR_INFO("Log priority configuration changed from %s(%d) -> %s(%d)",
                 fl_trace_value(syslog_priorities, cfg_log_priority),
                 cfg_log_priority,
                 fl_trace_value(syslog_priorities, priority), priority);
    cfg_log_priority = priority;
  }
}

void fl_logr_log(int priority, const char *format, ...)
{
  va_list args;

  va_start(args, format);
  fl_logr_vlog(priority, format, args);
  va_end(args);
}

void fl_logr_vlog(int priority, const char *format, va_list args)
{
  if (LOG_PRIORITY_CMP(priority)) {
    vsyslog(priority, format, args);
  }
}
