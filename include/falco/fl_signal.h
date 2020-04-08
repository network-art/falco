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
 * @brief Signal Handlers Management
 */

#ifndef _FL_SIGNAL_H_
#define _FL_SIGNAL_H_

#include <signal.h>

#include "falco/fl_tracevalue.h"

/**
 * @brief Type definition of a signal handler routine.
 */
typedef void (*fl_signal_handler_t)(int, siginfo_t *, void *);

/**
 * @brief Representation of a signal handler registration.
 *
 * This is a convenience structure for applications to define a list of signals
 * and their respective handlers.
 */
typedef struct fl_signal_handler_regn_t_ {
  /**
   * @brief Signal number.
   *
   * For example: SIGSTP, SIGTERM.
   */
  int signum;
  /**
   * @brief Pointer to function that implements #fl_signal_handler_t.
   */
  fl_signal_handler_t signal_handler;
} fl_signal_handler_regn_t;

/**
 * @brief Register a set of signal handlers.
 *
 * @param[in] sighandler_registrations List of signals and their respective
 *                                     handlers represented by
 *                                     #fl_signal_handler_regn_t
 *
 * @return On success, 0 is returned. On failure, -1 is returned.
 *
 */
extern int fl_signal_register_handlers(fl_signal_handler_regn_t *sighandler_registrations);

/**
 * @brief Register/Add a signal handler.
 *
 * @param[in] signum Signal number, for example: SIGTERM, SIGHUP
 * @param[in] sighanlder Pointer to a function that implements
 *                       #fl_signal_handler_t
 *
 * @return On success, 0 is returned. On failure, -1 is returned.
 *
 */
extern int fl_signal_add(int signum, fl_signal_handler_t sighandler);

/**
 * @brief Deregister/Remove a signal handler.
 *
 * @param[in] signum Signal number, for example: SIGTERM, SIGHUP
 *
 * @return On success, 0 is returned. On failure, -1 is returned.
 *
 */
extern int fl_signal_remove(int signum);

/**
 * @brief Block a list of signals.
 *
 * @param[in] signals Array of signals (signal numbers) to be blocked
 * @param[in, out] set Signal set returned by this function containing those
 *                     signals that were successfully blocked.
 *
 * @return On success, 1 is returned. On failure, 0 is returned.
 *
 */
extern int fl_signals_block(int signals[], sigset_t *set);

/**
 * @brief Unblock signals for the caller.
 *
 * @param[in] set Set of signals currently blocked. Typically this is the set
 *                of signals post a call to fl_signals_block().
 *
 * @return On success, 0 is returned. On failure, -1 is returned.
 *
 */
extern int fl_signals_unblock(sigset_t *set);

extern const values_t fl_signals[];

#endif /* _FL_SIGNAL_H_ */
