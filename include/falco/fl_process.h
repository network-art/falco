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
 * @brief Convenience functions/utilities for application process
 */

#ifndef _FL_PROCESS_H_
#define _FL_PROCESS_H_

/**
 * @brief Initialize all falco modules.
 *
 * Initialize the timer, socket, task, and (network) interface modules in the
 * order listed. Post initialization, the function dumps all the network
 * interfaces read from the kernel.
 *
 * @return -1 on error, 0 on success.
 */
extern int fl_init(void);

/**
 * @brief Dump status and state of all falco modules.
 *
 * @param[in] fd Stream to which the status and state of all modules needs to
 *               be written. If this parameter is NULL, then the output is
 *               written to syslog.
 *
 * @return -1 on error, 0 on success.
 */
extern int fl_dump(FILE *fd);

/**
 * @brief Daemonize the application process.
 *
 * This function uses the double fork() method to daemonize the process.
 * It causes the application process to exit() if attempts to fork() fail or the
 * attempt to create a session fails.
 *
 * @return -1 on error, 0 on success.
 */
extern int fl_process_daemonize(void);

/**
 * @brief Open a file and record the PID of the application.
 *
 * Open the file whose name is the string pointed to by progname.
 *
 * If the caller supplies a complete path, that is, progname contains a
 * forward slash '/' in the first character, then the argument is treated as
 * the full path. Otherwise, it is treated as the name of the application and
 * the file is opened in the _PATH_PID directory.
 *
 * The file is created if it does not exist. The PID of the application is
 * recorded in the file, and the file is locked.
 *
 * @param[in] progname The name of the application or the complete path to a
 *                     file that should contain the PID.
 *
 * @return On success, a file descriptor for the PID file is returned. On error,
 *         a negative value (representing the errno) is returned.
 */
extern int fl_process_open_pid_file(const char *progname);

/**
 * @brief Close the PID file descriptor and delete the PID file.
 *
 * Close the file descriptor and delete the PID file whose name is the string
 * pointed to by progname.
 *
 * If the caller supplies a complete path, that is, progname contains a
 * forward slash '/' in the first character, then the argument is treated as
 * the full path. Otherwise, it is treated as the name of the application and
 * the file is deleted from the _PATH_PID directory.
 *
 * @param[in] progname The name of the application or the complete path to a
 *                     file that should contain the PID.
 * @param[in] pid_fd A File descriptor of the PID file.
 *
 * @return On success, 0 is returned.
 * On error, a negative value (representing the errno) is returned.
 */
extern int fl_process_close_pid_file(const char *progname, int pid_fd);

#endif /* _FL_PROCESS_H_ */
