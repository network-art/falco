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

#ifndef _FL_FDS_H_
#define _FL_FDS_H_

#include <sys/types.h>
#include <sys/select.h>

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

#define FL_FD_ZERO(_op_)                                \
  do {                                                  \
    fl_fd_set_t *_fl_fds_ = fl_fds_get_set((_op_));     \
    FL_ASSERT(_fl_fds_);                                \
    FD_ZERO(&_fl_fds_->fd_bits);                        \
    _fl_fds_->nfds = 0;                                 \
  } while (0)

typedef enum fl_fd_op_e_ {
  FL_FD_OP_READ,
  FL_FD_OP_WRITE,
  FL_FD_OP_ACCEPT,
  FL_FD_OP_EXCEPT
} fl_fd_op_e;

typedef struct fl_fd_set_t_ {
  fd_set fd_bits;
  u_int16_t nfds;
} fl_fd_set_t;

extern fl_fd_set_t *fl_fds_get_set(fl_fd_op_e op);

inline int FL_FD_ISSET(int fd, fl_fd_op_e op)
{
  register fl_fd_set_t *fdset = fl_fds_get_set(op);
  return FD_ISSET(fd, &fdset->fd_bits);
}

inline int FL_FDS_ANYFDS_SET(fl_fd_op_e op)
{
  fl_fd_set_t *fdset = fl_fds_get_set(op);
  return (fdset->nfds > 0);
}

extern int fl_fds_get_max_fd(void);
extern void fl_fds_set_max_fd(int fd);

#endif /* _FL_FDS_H_ */
