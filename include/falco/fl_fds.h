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
 * @brief File Descriptors Management
 */

#ifndef _FL_FDS_H_
#define _FL_FDS_H_

#include <sys/types.h>
#include <sys/select.h>

/**
 * @brief Set read/accept or write except bit for the supplied file descriptor.
 *
 * @detail Read and Accept operations both set the read bit.
 *
 * @param[in] fd File descriptor
 * @param[in] op Enumerated value of read/write/accept/except operation
 *            (from @link #fl_fd_op_e)
 *
 */
#define FL_FD_SET(_fd_, _op_)                           \
  do {                                                  \
    fl_fd_set_t *_fl_fds_ = fl_fds_get_set((_op_));     \
    if (FD_ISSET((_fd_), &_fl_fds_->fd_bits)) {         \
      FL_ASSERT(0);                                     \
      FL_LOGR_NOTICE("FD (%d) is already set", (_fd_)); \
    } else {                                            \
      FD_SET((_fd_), &_fl_fds_->fd_bits);               \
      _fl_fds_->nfds++;                                 \
    }                                                   \
  } while (0)

/**
 * @brief Clear read/accept or write except bit for the supplied file
 * descriptor.
 *
 * @detail Read and Accept operations both clear the read bit.
 *
 * @param[in] fd File descriptor
 * @param[in] op Enumerated value of read/write/accept/except operation
 *            (from @link #fl_fd_op_e)
 *
 */
#define FL_FD_CLR(_fd_, _op_)                           \
  do {                                                  \
    fl_fd_set_t *_fl_fds_ = fl_fds_get_set((_op_));     \
    FL_ASSERT(_fl_fds_->nfds);                          \
    if (!FD_ISSET((_fd_), &_fl_fds_->fd_bits)) {        \
      FL_ASSERT(0);                                     \
      FL_LOGR_NOTICE("FD (%d) is not set", (_fd_));     \
    } else {                                            \
      FD_CLR((_fd_), &_fl_fds_->fd_bits);               \
      _fl_fds_->nfds--;                                 \
    }                                                   \
  } while (0)

/**
 * @brief Clear bits of all file descriptors for an operation.
 *
 * @detail Read and Accept operations both clear the read bits.
 *
 * @param[in] op Enumerated value of read/write/accept/except operation
 *            (from @link #fl_fd_op_e)
 *
 */
#define FL_FD_ZERO(_op_)                                \
  do {                                                  \
    fl_fd_set_t *_fl_fds_ = fl_fds_get_set((_op_));     \
    FL_ASSERT(_fl_fds_);                                \
    FD_ZERO(&_fl_fds_->fd_bits);                        \
    _fl_fds_->nfds = 0;                                 \
  } while (0)

/**
 * @brief Enumeration of all operations on a set of file descriptors (fd_set).
 */
typedef enum fl_fd_op_e_ {
  FL_FD_OP_READ,
  FL_FD_OP_WRITE,
  FL_FD_OP_ACCEPT,
  FL_FD_OP_EXCEPT
} fl_fd_op_e;

/**
 * @brief An fd_set with capability to track the number of file descriptors
 * that are set.
 */
typedef struct fl_fd_set_t_ {
  fd_set fd_bits;
  u_int16_t nfds;
} fl_fd_set_t;

/**
 * @brief Get fd set for an operation.
 *
 * @param[in] op Enumerated value of read/write/accept/except operation
 *               (from #fl_fd_op_e)
 *
 * @return If parameter @p op is one of the defined enumerated values, then, a
 * pointer to the corresponding fd set is returned. Otherwise, NULL is returned.
 * A pointer to the read fd set is returned for both read and accept operations.
 */
extern fl_fd_set_t *fl_fds_get_set(fl_fd_op_e op);

/**
 * @brief Get the maximum fd number.
 *
 * @detail There are situations where an application will create file
 * descriptors which the falco library shall not be aware of. In these
 * situations, applications must call fl_fds_set_max_fd() to let falco know
 * about these file descriptors.
 *
 * @return The maximum file descriptor recorded by falco.
 */
extern int fl_fds_get_max_fd(void);

/**
 * @brief Set the maximum fd number.
 *
 * @detail There are situations where an application will create file
 * descriptors which the falco library shall not be aware of. In these
 * situations, applications can use this function to let falco know about these
 * file descriptors.
 *
 * @param[in] fd File descriptor
 */
extern void fl_fds_set_max_fd(int fd);

/**
 * @brief Check to see if any file descriptors are set for an operation.
 *
 * @param[in] op Enumerated value of read/write/accept/except operation
 *               (from #fl_fd_op_e)
 *
 * @return Returns 1 if any file descriptors are set for the operation.
 * Otherwise, 0 is returned.
 */
extern int fl_fds_anyfds_set(fl_fd_op_e op);

/**
 * @brief Check to see if a file descriptor is set for an operation.
 *
 * @param[in] fd File descriptor
 * @param[in] op Enumerated value of read/write/accept/except operation
 *               (from #fl_fd_op_e)
 *
 * @return Returns 1 if the file descriptor is set for the operation.
 * Otherwise, 0 is returned.
 */
extern int fl_fd_isset(int fd, fl_fd_op_e op);

#endif /* _FL_FDS_H_ */
