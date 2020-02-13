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

#ifndef _FL_SOCKET_H_
#define _FL_SOCKET_H_

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/queue.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdarg.h>

#include "falco/fl_stdlib.h"
#include "falco/fl_bits.h"
#include "falco/fl_tracevalue.h"

#define FL_SOCKET_NAME_MAX_LEN   128

/* Flags for socket state and options */
#define FL_SOCKF_BOUND_IN           BITVAL(0x00000001)
#define FL_SOCKF_BOUND_IN6          BITVAL(0x00000002)
#define FL_SOCKF_BOUND_UNIX         BITVAL(0x00000004)
#define FL_SOCKF_CONNECTED          BITVAL(0x00000008)
#define FL_SOCKF_LISTEN             BITVAL(0x00000010)
#define FL_SOCKF_NONBLOCKING        BITVAL(0x00000020)
#define FL_SOCKF_RCVWAIT            BITVAL(0x00000040)

struct fl_socket_t_;

typedef void (*fl_socket_accept_method_t)(struct fl_socket_t_ *);
typedef void (*fl_socket_connect_method_t)(struct fl_socket_t_ *);
typedef void (*fl_socket_connect_error_method_t)(struct fl_socket_t_ *, int);
typedef void (*fl_socket_connect_complete_method_t)(struct fl_socket_t_ *);
typedef void (*fl_socket_recv_method_t)(struct fl_socket_t_ *, void *buf, size_t len, struct sockaddr *src_addr, socklen_t *addrlen);
typedef void (*fl_socket_nb_recv_method_t)(struct fl_socket_t_ *);
typedef int (*fl_socket_recv_is_msg_complete_method_t)(struct fl_socket_t_ *);
typedef void (*fl_socket_recv_complete_method_t)(struct fl_socket_t_ *);
typedef void (*fl_socket_recv_error_method_t)(struct fl_socket_t_ *);
typedef ssize_t (*fl_socket_send_method_t)(struct fl_socket_t_ *, void *buf, size_t len, const struct sockaddr *dest_addr, socklen_t addrlen);
typedef void (*fl_socket_nb_send_method_t)(struct fl_socket_t_ *);
typedef void (*fl_socket_send_complete_method_t)(struct fl_socket_t_ *);
typedef void (*fl_socket_send_error_method_t)(struct fl_socket_t_ *);

typedef struct fl_socket_t_ {
  LIST_ENTRY(fl_socket_t_) socket_lc;
  LIST_ENTRY(fl_socket_t_) task_socket_lc;

  char name[FL_SOCKET_NAME_MAX_LEN];
  int domain;
  int type;
  int protocol;

  fl_socket_accept_method_t accept_method;
  fl_socket_connect_method_t connect_method;
  fl_socket_connect_complete_method_t connect_complete_method;
  fl_socket_recv_method_t recv_method;
  fl_socket_nb_recv_method_t nb_recv_method;
  fl_socket_recv_is_msg_complete_method_t recv_is_msg_complete_method;
  fl_socket_recv_complete_method_t recv_complete_method;
  fl_socket_recv_error_method_t recv_error_method;
  fl_socket_send_method_t send_method;
  fl_socket_nb_send_method_t nb_send_method;
  fl_socket_send_complete_method_t send_complete_method;
  fl_socket_send_error_method_t send_error_method;

  int sockfd;
  flag_t flags;
  struct sockaddr_storage sa_local;
  /* From sys/un.h sun_path length is 108. This value should be more than
   * sufficient across platforms.
   */
#define FL_SOCKADDR_STR_MAX_LEN 130
  char local_addr[FL_SOCKADDR_STR_MAX_LEN];

  struct sockaddr_storage sa_remote;
  char remote_addr[FL_SOCKADDR_STR_MAX_LEN];

  /* Data Buffers */
  void *rbuf;        /* Read data buffer supplied by app */
  size_t trbuf_len;  /* Total read data buffer length supplied by app */
  size_t crdata_len; /* Current read data buffer updated by the recv method */
  struct sockaddr_storage rbuf_src_addr;

  void *wbuf;        /* Write data buffer supplied by app */
  size_t twbuf_len;  /* Total write data buffer length supplied by app */
  size_t cwdata_len; /* Current write data buffer updated by the write method */
  struct sockaddr_storage wbuf_dest_addr;

  struct fl_task_t_ *task;
} fl_socket_t;

typedef enum fl_sockoption_e_ {
  FL_SOCKOPT_MIN = 1,
  FL_SOCKOPT_NONBLOCKING = FL_SOCKOPT_MIN,
  FL_SOCKOPT_RCVWAIT,
  FL_SOCKOPT_RCVTIMEO,
  FL_SOCKOPT_SNDTIMEO,
  FL_SOCKOPT_MAX = FL_SOCKOPT_SNDTIMEO,
} fl_sockoption_e;

extern int fl_socket_module_init(void);
extern int fl_socket_module_dump(FILE *fd);

extern fl_socket_t *fl_socket_socket(struct fl_task_t_ *task, const char *name,
                                     int domain, int type, int protocol);
extern int fl_socket_setsockopt(fl_socket_t *flsk, fl_sockoption_e option, ...);
extern int fl_socket_bind(fl_socket_t *flsk,
                          const struct sockaddr_storage *addr,
                          socklen_t addrlen);
extern int fl_socket_set_remote_addr(fl_socket_t *flsk,
                                     const struct sockaddr_storage *addr,
                                     socklen_t addrlen);
extern int fl_socket_listen(fl_socket_t *flsk, int backlog);
extern int fl_socket_select(fd_set **rfds, fd_set **wfds, fd_set **efds);

extern void fl_socket_generic_accept(fl_socket_t *flsk);
extern int fl_socket_generic_connect(fl_socket_t *flsk,
                                     const struct sockaddr_storage *addr,
                                     socklen_t addrlen);
extern ssize_t fl_socket_generic_recv(fl_socket_t *flsk, void *buf, size_t len,
                                      struct sockaddr_storage *src_addr,
                                      socklen_t *addrlen);
extern ssize_t fl_socket_generic_send(fl_socket_t *flsk, void *buf, size_t len,
                                      const struct sockaddr_storage *dest_addr,
                                      socklen_t addrlen);

extern void fl_socket_set_connect_complete_method(fl_socket_t *flsk, fl_socket_connect_complete_method_t connect_complete_method);
extern void fl_socket_set_recv_is_msg_complete_method(fl_socket_t *flsk, fl_socket_recv_is_msg_complete_method_t recv_is_msg_complete_method);
extern void fl_socket_set_recv_complete_method(fl_socket_t *flsk, fl_socket_recv_complete_method_t recv_complete_method);
extern void fl_socket_set_send_complete_method(fl_socket_t *flsk, fl_socket_send_complete_method_t send_complete_method);

extern void fl_socket_process_reads(int *nfds, fd_set *fds);
extern void fl_socket_process_writes(int *nfds, fd_set *fds);
extern void fl_socket_process_connections(int *nfds, fd_set *fds);

inline void FL_SOCKADDR_DUP(struct sockaddr_storage *dst,
                            const struct sockaddr_storage *src,
                            socklen_t srclen)
{
  FL_ASSERT(dst && src && srclen &&
            (sizeof(srclen) <= sizeof(struct sockaddr_storage)));
  FL_ASSERT((src->ss_family == AF_INET) || (src->ss_family == AF_INET6) ||
            (src->ss_family == AF_UNIX));
  (void) memcpy(dst, src, srclen);
}

inline socklen_t FL_SOCKADDR_LEN(struct sockaddr *sa)
{
  register socklen_t addrlen = 0;
  register int sa_family = sa->sa_family;

  switch(sa_family) {
  case AF_INET: {
    addrlen = sizeof(struct sockaddr_in);
    break;
  }
  case AF_INET6: {
    addrlen = sizeof(struct sockaddr_in6);
    break;
  }
  case AF_UNIX: {
    register struct sockaddr_un *sa_un = (struct sockaddr_un *)sa;
    addrlen = (strlen(sa_un->sun_path) + 1) + (sizeof(sa_un) - 1);
    break;
  }
  default:
    FL_ASSERT(0);
  }

  return addrlen;
}

inline const char *FL_SOCKADDR_NTOP(const struct sockaddr_storage *ss,
                                    char *dst, socklen_t size)
{
  register int ss_family = ss->ss_family;

  switch(ss_family) {
  case AF_INET: {
    FL_ASSERT(dst && (size >= INET_ADDRSTRLEN));
    return inet_ntop(AF_INET, &((struct sockaddr_in *)ss)->sin_addr, dst, size);
  }
  case AF_INET6: {
    FL_ASSERT(dst && (size >= INET6_ADDRSTRLEN));
    return inet_ntop(AF_INET, &((struct sockaddr_in6 *)ss)->sin6_addr, dst, size);
  }
  case AF_UNIX: {
    return ((struct sockaddr_un *)ss)->sun_path;
  }
  default:
    FL_ASSERT(0);
  }

  return NULL;
}

inline u_int16_t FL_SOCKADDR_PORT_HBO(const struct sockaddr_storage *ss)
{
  register int ss_family = ss->ss_family;

  switch(ss_family) {
  case AF_INET: {
    return ntohs(((struct sockaddr_in *)ss)->sin_port);
  }
  case AF_INET6: {
    return ntohs(((struct sockaddr_in6 *)ss)->sin6_port);
  }
  case AF_UNIX:
    break;
  default:
    FL_ASSERT(0);
  }

  return 0;
}

#endif /* _FL_SOCKET_H_ */
