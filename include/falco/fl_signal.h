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

#ifndef _FL_SIGNAL_H_
#define _FL_SIGNAL_H_

#include <signal.h>

#include "falco/fl_tracevalue.h"

typedef void (*fl_signal_handler_t)(int, siginfo_t *, void *);

/* Convenience structure for applications to define a list of signals and their
 * respective handlers.
 */
typedef struct fl_signal_handler_regn_t_ {
  int signum;
  fl_signal_handler_t signal_handler;
} fl_signal_handler_regn_t;

extern int fl_signal_register_handlers(fl_signal_handler_regn_t *sighandler_registrations);
extern int fl_signal_add(int signum, fl_signal_handler_t sighandler);
extern int fl_signal_remove(int signum);
extern int fl_signals_block(int signals[], sigset_t *set);
extern int fl_signals_unblock(sigset_t *set);

extern const values_t fl_signals[];

#endif /* _FL_SIGNAL_H_ */
