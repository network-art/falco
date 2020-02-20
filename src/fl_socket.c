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

#include <sys/ioctl.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>

#include "falco/fl_stdlib.h"
#include "falco/fl_fds.h"
#include "falco/fl_task.h"

#define SA_CAST(_addr_)  (struct sockaddr *)(_addr_)
#define SA_CCAST(_addr_) (const struct sockaddr *)(_addr_)

#define CMP_AND_RETURN(_a_, _b_)                \
  do {                                          \
    if ((_a_) != (_b_)) {                       \
      return ((_a_) < (_b_)) ? -1 : 1;          \
    }                                           \
  } while(0)

static fd_set exec_rbits, exec_wbits, exec_ebits;
static LIST_HEAD(fl_sockets_, fl_socket_t_) fl_sockets;

static const values_t fl_socket_domains[] = {
  { AF_INET,   "AF_INET"   },
  { AF_INET6,  "AF_INET6"  },
  { AF_UNIX,   "AF_UNIX"   },
  { AF_UNSPEC, "AF_UNSPEC" },
  { 0, NULL }
};

static const values_t fl_socket_types[] = {
  { SOCK_DGRAM,     "SOCK_DATAGRAM"  },
  { SOCK_RAW,       "SOCK_RAW"       },
  { SOCK_SEQPACKET, "SOCK_SEQPACKET" },
  { SOCK_STREAM,    "SOCK_STREAM"    },
  { 0, NULL }
};

/* Standard well-defined IP protocols.  */
static const values_t fl_socket_protocols[] = {
  { IPPROTO_ICMP,      "ICMP"      },
  { IPPROTO_ICMPV6,    "ICMPV6"    },
  { IPPROTO_IGMP,      "IGMP"      },
  { IPPROTO_IP,        "IP"        },
  { IPPROTO_IPV6,      "IPV6"      },
  { IPPROTO_RAW,       "RAW"       },
  { IPPROTO_TCP,       "TCP"       },
  { IPPROTO_UDP,       "UDP"       },
  { 0, NULL }
};

static const values_t fl_sockoptions[] = {
  { FL_SOCKOPT_NONBLOCKING,         "Non-Blocking"               },
  { FL_SOCKOPT_RCVTIMEO,            "Recv-Timeout"               },
  { FL_SOCKOPT_RCVWAIT,             "Recv-Wait"                  },
  { FL_SOCKOPT_SNDTIMEO,            "Send-Timeout"               },
  { 0, NULL }
};

static const values_t fl_sockflags[] = {
  { FL_SOCKF_BOUND_IN,           "Bound-IPv4"          },
  { FL_SOCKF_BOUND_IN6,          "Bound-IPv6"          },
  { FL_SOCKF_BOUND_UNIX,         "Bound-Unix"          },
  { FL_SOCKF_CONNECTED,          "Connected"           },
  { FL_SOCKF_LISTEN,             "Listen"              },
  { FL_SOCKF_NONBLOCKING,        "Non-Blocking"        },
  { FL_SOCKF_RCVWAIT,            "Recv-Wait"           },
  { 0, NULL }
};

static fl_socket_t *fl_socket_alloc(fl_task_t *task, const char *name,
                                    int domain, int type, int protocol,
                                    int sockfd);
static int fl_socket_get_local_addr(fl_socket_t *nflsk);

static ssize_t fl_socket_recvfrom(fl_socket_t *flsk, void *buf, size_t len,
                                  struct sockaddr_storage *src_addr,
                                  socklen_t *addrlen);
static ssize_t fl_socket_recvmsg(fl_socket_t *flsk, struct msghdr *msg);
static ssize_t fl_socket_recv(fl_socket_t *flsk, void *buf, size_t len);

static ssize_t fl_socket_sendto(fl_socket_t *flsk, const void *buf, size_t len,
                                const struct sockaddr_storage *dest_addr,
                                socklen_t addrlen);
static ssize_t fl_socket_sendmsg(fl_socket_t *flsk, const struct msghdr *msg);
static ssize_t fl_socket_send(fl_socket_t *flsk, const void *buf, size_t len);

int fl_socket_module_init(void)
{
  LIST_INIT(&fl_sockets);

  FL_LOGR_INFO("Falco Socket module initialized");
  return 0;
}

int fl_socket_module_dump(FILE *fd)
{
  register fl_socket_t *li;

  fprintf(fd, "\n--------------------------------------------------------------------------------\n");
  fprintf(fd, "Sockets\n");
  fprintf(fd, "--------------------------------------------------------------------------------\n\n");

  if (LIST_EMPTY(&fl_sockets)) {
    fprintf(fd, "    No sockets are currently present\n");
    return 0;
  }

  LIST_FOREACH(li, &fl_sockets, socket_lc) {
    register int sr = (fl_fd_isset(li->sockfd, FL_FD_OP_READ) ||
                       fl_fd_isset(li->sockfd, FL_FD_OP_ACCEPT));
    register int sw = fl_fd_isset(li->sockfd, FL_FD_OP_WRITE);
    register int se = fl_fd_isset(li->sockfd, FL_FD_OP_EXCEPT);

    fprintf(fd, "Name: %s(%d)\n", li->name, li->sockfd);

    if (li->task) {
      fprintf(fd, "    Task: %s\n", li->task->name);
    }
    fprintf(fd, "    Domain %s(%d), Type %s(%d), Protocol %s(%d)\n",
            fl_trace_value(fl_socket_domains, li->domain), li->domain,
            fl_trace_value(fl_socket_types, li->type), li->type,
            fl_trace_value(fl_socket_protocols, li->protocol), li->protocol);
    if (li->flags) {
      fprintf(fd, "    %s\n", fl_trace_flags(fl_sockflags, li->flags));
    }
    fprintf(fd, "    Local address: %s, Remote address: %s\n",
            (strlen(li->local_addr)) ? li->local_addr : "None",
            (strlen(li->remote_addr)) ? li->remote_addr : "None");
    if (sr || sw || se) {
      fprintf(fd, "    Selected for:                %s%s%s\n",
              (sr) ? "Read " : "",
              (sw) ? "Write " : "",
              (se) ? "Except" : "");
    }
    if (li->rbuf) {
      fprintf(fd, "    Read buffer size:  %d bytes\n", (int) li->trbuf_len);
      fprintf(fd, "    Read data length:  %d bytes (current)\n", (int) li->crdata_len);
    }
    if (li->wbuf) {
      fprintf(fd, "    Write buffer size: %d bytes\n", (int) li->twbuf_len);
      fprintf(fd, "    Write data length: %d bytes (current)\n", (int) li->cwdata_len);
    }

    fprintf(fd, "    accept_method:               %s\n",
            (li->accept_method) ? "yes" : "no");
    fprintf(fd, "    connect_method:              %s\n",
            (li->connect_method) ? "yes" : "no");
    fprintf(fd, "    connect_complete_method:     %s\n",
            (li->connect_complete_method) ? "yes" : "no");
    fprintf(fd, "    recv_method:                 %s\n",
            (li->recv_method) ? "yes" : "no");
    fprintf(fd, "    nb_recv_method:              %s\n",
            (li->nb_recv_method) ? "yes" : "no");
    fprintf(fd, "    recv_is_msg_complete_method: %s\n",
            (li->recv_is_msg_complete_method) ? "yes" : "no");
    fprintf(fd, "    recv_error_method:           %s\n",
            (li->recv_error_method) ? "yes" : "no");
    fprintf(fd, "    send_method:                 %s\n",
            (li->send_method) ? "yes" : "no");
    fprintf(fd, "    nb_send_method:              %s\n",
            (li->nb_send_method) ? "yes" : "no");
    fprintf(fd, "    send_complete_method:        %s\n",
            (li->send_complete_method) ? "yes" : "no");
    fprintf(fd, "    send_error_method:           %s\n",
            (li->send_error_method) ? "yes" : "no");
  }

  return 0;
}

struct sockaddr_storage *fl_sockaddr_dup(struct sockaddr_storage *dst,
                                         const struct sockaddr_storage *src,
                                         socklen_t srclen)
{
  FL_ASSERT(dst && src && srclen &&
            (sizeof(srclen) <= sizeof(struct sockaddr_storage)));
  FL_ASSERT((src->ss_family == AF_INET) || (src->ss_family == AF_INET6) ||
            (src->ss_family == AF_UNIX));
  (void) memcpy(dst, src, srclen);
  return dst;
}

socklen_t fl_sockaddr_len(struct sockaddr *sa)
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

const char *fl_sockaddr_ntop(const struct sockaddr_storage *ss,
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

u_int16_t fl_sockaddr_port_hbo(const struct sockaddr_storage *ss)
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

int fl_sockaddr_cmp(const struct sockaddr *sa1, const struct sockaddr *sa2)
{
  FL_ASSERT(sa1 && sa2);
  FL_ASSERT((sa1->sa_family == AF_INET) || (sa1->sa_family == AF_INET6) ||
            (sa1->sa_family == AF_UNIX));
  FL_ASSERT((sa2->sa_family == AF_INET) || (sa2->sa_family == AF_INET6) ||
            (sa2->sa_family == AF_UNIX));

  CMP_AND_RETURN(sa1->sa_family, sa2->sa_family);

  if (sa1->sa_family == AF_INET) {
    return memcmp(sa1, sa2, sizeof(struct sockaddr_in));
  }

  if (sa1->sa_family == AF_INET6) {
    return memcmp(sa1, sa2, sizeof(struct sockaddr_in6));
  }

  if (sa1->sa_family == AF_UNIX) {
    return memcmp(sa1, sa2, sizeof(struct sockaddr_un));
  }

  FL_ASSERT(0);
  return -1;
}

int fl_sockaddr_nw_cmp(const struct sockaddr *sa1,
                       const struct sockaddr *sa2,
                       const struct sockaddr *netmask)
{

  FL_ASSERT(sa1 && sa2 && netmask);
  FL_ASSERT(sa1->sa_family == AF_INET);
  FL_ASSERT(sa2->sa_family == AF_INET);
  FL_ASSERT(netmask->sa_family == AF_INET);

  CMP_AND_RETURN(sa1->sa_family, sa2->sa_family);
  CMP_AND_RETURN(sa1->sa_family, netmask->sa_family);

  if (sa1->sa_family == AF_INET) {
    struct sockaddr_in sin1, sin2, sin_mask;

    memcpy(&sin1, sa1, sizeof(struct sockaddr_in));
    memcpy(&sin2, sa2, sizeof(struct sockaddr_in));
    memcpy(&sin_mask, netmask, sizeof(struct sockaddr_in));

    CMP_AND_RETURN(ntohl(sin1.sin_addr.s_addr) &
                   ntohl(sin_mask.sin_addr.s_addr),
                   ntohl(sin2.sin_addr.s_addr) &
                   ntohl(sin_mask.sin_addr.s_addr));
    return 0;
 }

  FL_ASSERT(0);
  return -1;
}

fl_socket_t *fl_socket_socket(fl_task_t *task, const char *name,
                              int domain, int type, int protocol)
{
  int retries, sockfd, save_errno;
  fl_socket_t *flsk;

  FL_ASSERT((domain == AF_INET) || (domain == AF_INET6) || (domain == AF_UNIX));
  FL_ASSERT((type == SOCK_DGRAM) || (type == SOCK_RAW) ||
            (type == SOCK_SEQPACKET) || (type == SOCK_STREAM));
  /* For now we don't accept any value other than 0. */
  FL_ASSERT((protocol == IPPROTO_ICMPV6) || (protocol == IPPROTO_TCP) ||
            (protocol == IPPROTO_UDP));
  if (name) {
    FL_ASSERT(strlen(name) < FL_SOCKET_NAME_MAX_LEN);
  }

  retries = 3;
  while (((sockfd = socket(domain, type, protocol)) < 0) && retries--) {
    save_errno = errno;

    FL_LOGR_ERR("Socket creation for %s%s%s domain %s(%d), type %s(%d), "
                "protocol %s(%d) failed, error %d <%s>",
                (name) ? "\"" : "", (name) ? name : "", (name) ? "\", " : "",
                fl_trace_value(fl_socket_domains, domain), domain,
                fl_trace_value(fl_socket_types, type), type,
                fl_trace_value(fl_socket_protocols, protocol), protocol,
                save_errno, strerror(save_errno));

    if (save_errno == EINTR) {
      retries++;
      continue;
    } else if ((save_errno == EMFILE) || (save_errno == ENFILE) ||
               (save_errno == ENOBUFS) || (save_errno == ENOMEM)) {
      /* Let us wait to see if any resources will get freed in the system. */
      sleep(3);
    } else {
      break;
    }
  }

  if (sockfd < 0) {
    return NULL;
  }

  flsk = fl_socket_alloc(task, name, domain, type, protocol, sockfd);
  if (!flsk) {
    FL_LOGR_ERR("Closing socket (%s, %s, %d)",
                (task) ? task->name : "", (name) ? name : "", sockfd);
    (void) close(sockfd);
    return NULL;
  }

  fl_fds_set_max_fd(sockfd);

  return flsk;
}

int fl_socket_setsockopt(fl_socket_t *flsk, fl_sockoption_e option, ...)
{
  register int sockfd;
  int rc = 0, intv = 0;
  va_list vargs;

  FL_ASSERT(flsk && (flsk->sockfd >= 0));
  FL_ASSERT((option >= FL_SOCKOPT_MIN) && (option <= FL_SOCKOPT_MAX));

  sockfd = flsk->sockfd;
  FL_LOGR_DEBUG("Set socket (%s, %d) option %s(%d)",
                flsk->name, sockfd,
                fl_trace_value(fl_sockoptions, option), option);

  va_start(vargs, option);

  switch (option) {
  case FL_SOCKOPT_NONBLOCKING:
    /* Only for non-blocking option we go via ioctl. For the rest we directly
     * use setsockopt() method.
     */
    {
      intv = va_arg(vargs, int);
      rc = ioctl(sockfd, (unsigned long) FIONBIO,
                 (char *) &intv, sizeof(intv));
      if (!rc) {
        FL_SET_BIT(flsk->flags, FL_SOCKF_NONBLOCKING);
      }
    }
    break;

  case FL_SOCKOPT_RCVWAIT:
    {
      FL_SET_BIT(flsk->flags, FL_SOCKF_RCVWAIT);
    }
    break;

  case FL_SOCKOPT_RCVTIMEO:
  case FL_SOCKOPT_SNDTIMEO:
    {
      struct timeval tv;

      int timeout = va_arg(vargs, int);
      tv.tv_sec = timeout / 1000;
      tv.tv_usec = (timeout % 1000) * 1000;

      rc = setsockopt(sockfd, SOL_SOCKET,
                      (option == FL_SOCKOPT_RCVTIMEO) ?
                      SO_RCVTIMEO : SO_SNDTIMEO,
                      &tv, sizeof(tv));
    }
    break;

  default:
    rc = -1;
    errno = EINVAL;
  }

  if (rc < 0) {
    FL_LOGR_WARNING("Set socket (%s, %d) option %s(%d) failed, error %d <%s>",
                    flsk->name, flsk->sockfd,
                    fl_trace_value(fl_sockoptions, option), option,
                    errno, strerror(errno));
  }

  va_end(vargs);
  return(rc);
}

void fl_socket_set_accept_method(fl_socket_t *flsk,
                                 fl_socket_accept_method_t accept_method)
{
  FL_ASSERT(flsk);
  flsk->accept_method = accept_method;
}

void fl_socket_set_connect_complete_method(fl_socket_t *flsk, fl_socket_connect_complete_method_t connect_complete_method)
{
  FL_ASSERT(flsk);
  flsk->connect_complete_method = connect_complete_method;
}

void fl_socket_set_recv_method(fl_socket_t *flsk,
                               fl_socket_recv_method_t recv_method)
{
  FL_ASSERT(flsk);
  flsk->recv_method = recv_method;
}

void fl_socket_set_nb_recv_method(fl_socket_t *flsk,
                                  fl_socket_nb_recv_method_t nb_recv_method)
{
  FL_ASSERT(flsk);
  flsk->nb_recv_method = nb_recv_method;
}

void fl_socket_set_recv_is_msg_complete_method(fl_socket_t *flsk, fl_socket_recv_is_msg_complete_method_t recv_is_msg_complete_method)
{
  FL_ASSERT(flsk);
  flsk->recv_is_msg_complete_method = recv_is_msg_complete_method;
}

void fl_socket_set_recv_complete_method(fl_socket_t *flsk, fl_socket_recv_complete_method_t recv_complete_method)
{
  FL_ASSERT(flsk);
  flsk->recv_complete_method = recv_complete_method;
}

void fl_socket_set_recv_error_method(fl_socket_t *flsk, fl_socket_recv_error_method_t recv_error_method)
{
  FL_ASSERT(flsk);
  flsk->recv_error_method = recv_error_method;
}

void fl_socket_set_send_method(fl_socket_t *flsk, fl_socket_send_method_t send_method)
{
  FL_ASSERT(flsk);
  flsk->send_method = send_method;
}

void fl_socket_set_nb_send_method(fl_socket_t *flsk, fl_socket_nb_send_method_t nb_send_method)
{
  FL_ASSERT(flsk);
  flsk->nb_send_method = nb_send_method;
}

void fl_socket_set_send_complete_method(fl_socket_t *flsk, fl_socket_send_complete_method_t send_complete_method)
{
  FL_ASSERT(flsk);
  flsk->send_complete_method = send_complete_method;
}

void fl_socket_set_send_error_method(fl_socket_t *flsk, fl_socket_send_error_method_t send_error_method)
{
  FL_ASSERT(flsk);
  flsk->send_error_method = send_error_method;
}

int fl_socket_bind(fl_socket_t *flsk,
                   const struct sockaddr_storage *addr, socklen_t addrlen)
{
  int rc;
  char addrstr[INET6_ADDRSTRLEN+1] = { 0 };

  FL_ASSERT(flsk && flsk->sockfd);
  FL_ASSERT(addr && addrlen);
  FL_ASSERT(!FL_TEST_BIT(flsk->flags, FL_SOCKF_BOUND_IN | FL_SOCKF_BOUND_IN6));

  rc = bind(flsk->sockfd, SA_CCAST(addr), addrlen);
  if (rc < 0) {
    int save_errno = errno;
    FL_LOGR_ERR("Socket (%s, %s, %d) bind to %s:%d failed, error %d <%s>",
                (flsk->task) ? flsk->task->name : "", flsk->name, flsk->sockfd,
                fl_sockaddr_ntop(addr, addrstr, INET6_ADDRSTRLEN),
                fl_sockaddr_port_hbo(addr), save_errno, strerror(save_errno));
    return -1;
  }

  (void) fl_sockaddr_ntop(addr, flsk->local_addr, FL_SOCKADDR_STR_MAX_LEN);
  FL_SET_BIT(flsk->flags,
             (flsk->domain == AF_INET)  ? FL_SOCKF_BOUND_IN  :
             (flsk->domain == AF_INET6) ? FL_SOCKF_BOUND_IN6 :
             FL_SOCKF_BOUND_UNIX);

  FL_LOGR_INFO("Socket (%s, %s, %d) bound to %s:%d",
               (flsk->task) ? flsk->task->name : "", flsk->name, flsk->sockfd,
               fl_sockaddr_ntop(addr, addrstr, INET6_ADDRSTRLEN),
               fl_sockaddr_port_hbo(addr));
  return 0;
}

int fl_socket_listen(fl_socket_t *flsk, int backlog)
{
  register fl_task_t *task = flsk->task;
  int rc;

  FL_ASSERT(flsk && flsk->sockfd);
  FL_ASSERT(FL_TEST_BIT(flsk->flags, (FL_SOCKF_BOUND_IN | FL_SOCKF_BOUND_IN6 |
                                      FL_SOCKF_BOUND_UNIX)));
  FL_ASSERT((flsk->type == SOCK_STREAM) || (flsk->type == SOCK_SEQPACKET));
  FL_ASSERT(flsk->accept_method && flsk->connect_complete_method);

  rc = listen(flsk->sockfd, backlog);
  if (rc < 0) {
    int save_errno = errno;
    FL_LOGR_ERR("Listen on socket (%s, %s, %d) (with backlog %d) failed, "
                "error %d <%s>",
                (task) ? task->name : "", flsk->name, flsk->sockfd, backlog,
                save_errno, strerror(save_errno));
    return(rc);
  }

  FL_FD_SET(flsk->sockfd, FL_FD_OP_ACCEPT);

  FL_LOGR_ERR("Socket (%s, %s, %d) is now to set to listen <%s>",
              (flsk->task) ? flsk->task->name : "", flsk->name, flsk->sockfd,
              fl_trace_flags(fl_sockflags, flsk->flags));
  return(0);
}

void fl_socket_generic_accept(fl_socket_t *flsk)
{
  register fl_task_t *task = flsk->task;
  struct sockaddr_storage addr;
  socklen_t addrlen = sizeof(addr);
  int peerfd, save_errno, retries;
  fl_socket_t *nflsk;
  char addrstr[INET6_ADDRSTRLEN+1] = { 0 };

  FL_LOGR_DEBUG("Process accept on socket (%s, %s, %d)",
                (task) ? task->name : "", flsk->name, flsk->sockfd);
  FL_ASSERT(flsk->connect_complete_method);

  retries = 3;
  while (((peerfd = accept(flsk->sockfd, (struct sockaddr *)&addr,
                           &addrlen)) < 0) &&
         retries--) {
    save_errno = errno;

    FL_LOGR_ERR("accept() on socket (%s, %s, %d) failed, error %d <%s>",
                (task) ? task->name : "", flsk->name, flsk->sockfd,
                save_errno, strerror(save_errno));

    if (save_errno == EINTR) {
      retries++;
      continue;
    } else if ((save_errno == EMFILE) || (save_errno == ENFILE) ||
               (save_errno == ENOBUFS) || (save_errno == ENOMEM)) {
      /* Let us wait to see if any resources will get freed in the system. */
      sleep(3);
    } else {
      break;
    }
  }

  if (peerfd < 0) {
    if ((save_errno == EAGAIN) || (save_errno == EWOULDBLOCK) ||
        (save_errno == ECONNABORTED)) {
      /* We will set the fd again so that we can come back to this later. */
      FL_FD_SET(flsk->sockfd, FL_FD_OP_ACCEPT);
      return;
    }

    FL_LOGR_CRIT("accept() on socket (%s, %s, %d) failed, "
                 "irrecoverable error %d <%s>. This socket shall not be "
                 "processed further.",
                 (task) ? task->name : "", flsk->name, flsk->sockfd,
                 save_errno, strerror(save_errno));
    return;
  }

  fl_fds_set_max_fd(peerfd);

  /* Set the fd again so that we can process other incoming connections */
  FL_FD_SET(flsk->sockfd, FL_FD_OP_ACCEPT);

  nflsk = fl_socket_alloc(task, "", flsk->domain, flsk->type, flsk->protocol,
                          peerfd);
  if (!nflsk || (fl_socket_get_local_addr(nflsk) < 0)) {
    FL_LOGR_ERR("Closing connection from %s:%d on socket (%s, %s, %d)",
                fl_sockaddr_ntop(&addr, addrstr, INET6_ADDRSTRLEN),
                fl_sockaddr_port_hbo(&addr),
                (task) ? task->name : "", "", peerfd);
    (void) close(peerfd);
    return;
  }

  fl_sockaddr_dup(&nflsk->sa_remote, &addr, addrlen);
  memset(flsk->remote_addr, 0, FL_SOCKADDR_STR_MAX_LEN);
  if (((flsk->domain == AF_INET) || (flsk->domain == AF_INET6)) &&
      ((flsk->type == SOCK_DGRAM) || (flsk->type == SOCK_SEQPACKET) ||
       (flsk->type == SOCK_STREAM))) {
    sprintf(flsk->remote_addr, "%s:%d",
            fl_sockaddr_ntop(&flsk->sa_remote, flsk->remote_addr,
                             FL_SOCKADDR_STR_MAX_LEN - 1),
            fl_sockaddr_port_hbo(&flsk->sa_remote));
  } else {
    sprintf(flsk->remote_addr, "%s",
            fl_sockaddr_ntop(&flsk->sa_remote, flsk->remote_addr,
                             FL_SOCKADDR_STR_MAX_LEN - 1));
  }

  FL_LOGR_INFO("Accepted connection %s -> %s on socket (%s, %s, %d)",
               nflsk->local_addr, nflsk->remote_addr,
               (task) ? task->name : "", "", peerfd);

  flsk->connect_complete_method(nflsk);
}

int fl_socket_generic_connect(fl_socket_t *flsk,
                              const struct sockaddr_storage *addr,
                              socklen_t addrlen)
{
  fl_task_t *task;
  int rc, save_errno;
  char addrstr[FL_SOCKADDR_STR_MAX_LEN] = { 0 };

  FL_ASSERT(flsk &&
            ((flsk->type == SOCK_SEQPACKET) || (flsk->type == SOCK_STREAM)));
  /* For now, we allow non-blocking mode only after the connection is
   * complete.
   */
  FL_ASSERT(!FL_TEST_BIT(flsk->flags, FL_SOCKF_NONBLOCKING));
  FL_ASSERT(!FL_TEST_BIT(flsk->flags, FL_SOCKF_CONNECTED));

  task = flsk->task;

  do {
    rc = connect(flsk->sockfd, SA_CCAST(addr), addrlen);
    save_errno = errno;
  } while ((rc == -1) && (errno == EINTR));

  if (rc == -1) {
    save_errno = errno;
    FL_LOGR_ERR("Attempt to connect to %s:%d on socket (%s, %s, %d) failed, "
                "error %d <%s>",
                fl_sockaddr_ntop(addr, addrstr, sizeof(addrstr)),
                fl_sockaddr_port_hbo(addr),
                (task) ? task->name : "", flsk->name, flsk->sockfd,
                save_errno, strerror(save_errno));
    return rc;
  }

  if (fl_socket_get_local_addr(flsk) < 0) {
    FL_LOGR_ERR("Closing connection to %s:%d on socket (%s, %s, %d)",
                fl_sockaddr_ntop(addr, addrstr, INET6_ADDRSTRLEN),
                fl_sockaddr_port_hbo(addr),
                (task) ? task->name : "", flsk->name, flsk->sockfd);
    (void) close(flsk->sockfd);
    return -1;
  }

  fl_sockaddr_dup(&flsk->sa_remote, addr, addrlen);
  memset(flsk->remote_addr, 0, FL_SOCKADDR_STR_MAX_LEN);
  sprintf(flsk->remote_addr, "%s:%d",
          fl_sockaddr_ntop(&flsk->sa_remote, flsk->remote_addr,
                           FL_SOCKADDR_STR_MAX_LEN - 1),
          fl_sockaddr_port_hbo(&flsk->sa_remote));

  FL_LOGR_ERR("Connected from %s -> %s on socket (%s, %s, %d)",
              flsk->local_addr, flsk->remote_addr,
              (task) ? task->name : "", flsk->name, flsk->sockfd);
  return 0;
}

ssize_t fl_socket_generic_recv(fl_socket_t *flsk, void *buf, size_t len,
                               struct sockaddr_storage *src_addr,
                               socklen_t *addrlen)
{

  FL_ASSERT(flsk && buf && len);
  /* There can be only one outstanding recv buffer (for now) */
  FL_ASSERT(!flsk->rbuf && !flsk->trbuf_len && !flsk->crdata_len);
  if (FL_TEST_BIT(flsk->flags, FL_SOCKF_NONBLOCKING)) {
    FL_ASSERT(flsk->nb_recv_method && flsk->recv_complete_method &&
              flsk->recv_error_method);
  }
  if (flsk->type == SOCK_STREAM) {
    FL_ASSERT(flsk->recv_is_msg_complete_method);
  }

  flsk->rbuf = buf;
  flsk->trbuf_len = len;

  if (FL_TEST_BIT(flsk->flags, FL_SOCKF_NONBLOCKING)) {
    /* We will set the fd for writing and return. The process_sockets shall take
     * care of calling the non-blocking send routine.
     */
    FL_FD_SET(flsk->sockfd, FL_FD_OP_READ);
    return 0;
  }

  if (flsk->type == SOCK_DGRAM) {
    return fl_socket_recvfrom(flsk, buf, len, src_addr, addrlen);
  } else if (flsk->type == SOCK_RAW) {
    return fl_socket_recvmsg(flsk, buf);
  } else if (flsk->type == SOCK_STREAM) {
    return fl_socket_recv(flsk, buf, len);
  }

  FL_ASSERT(0);
  return -1;
}

void fl_socket_generic_nb_recv(fl_socket_t *flsk)
{
  register fl_task_t *task;
  ssize_t rlen;
  int retries = 3, save_errno;
  socklen_t addrlen;

  FL_ASSERT(flsk);
  task = flsk->task;

  if ((flsk->type == SOCK_DGRAM) || (flsk->type == SOCK_RAW)) {
    addrlen = sizeof(flsk->rbuf_src_addr);

    while (retries > 0) {
      if (flsk->type == SOCK_DGRAM) {
        rlen = recvfrom(flsk->sockfd, flsk->rbuf,
                        flsk->trbuf_len,
                        FL_TEST_BIT(flsk->flags, FL_SOCKF_NONBLOCKING) ?
                        MSG_DONTWAIT : 0,
                        SA_CAST(&flsk->rbuf_src_addr), &addrlen);
      } else {
        rlen = recvmsg(flsk->sockfd, (struct msghdr *) flsk->rbuf,
                       FL_TEST_BIT(flsk->flags, FL_SOCKF_NONBLOCKING) ?
                       MSG_DONTWAIT : 0);
      }

      if (rlen == 0) {
        /* We should not be here, but let us debug. */
        FL_ASSERT(0);
      }
      if (rlen > 0) {
        break;
      }

      save_errno = errno;
      if (save_errno == EINTR) {
        retries++;
        continue;
      }
      if ((save_errno == EAGAIN) || (save_errno == EWOULDBLOCK)) {
        FL_FD_SET(flsk->sockfd, FL_FD_OP_READ);
        return;
      }

      FL_LOGR_ERR("NBRx on socket (%s, %s, %d) failed, error %d <%s>. "
                  "recv shall not be attempted on this socket.",
                  (task) ? task->name : "", flsk->name, flsk->sockfd,
                  save_errno, strerror(save_errno));
      flsk->recv_error_method(flsk);
      return;
    }

    FL_LOGR_DEBUG("Received %d bytes on socket (%s, %s, %d)", (int)rlen,
                  (task) ? task->name : "", flsk->name, flsk->sockfd);
    flsk->recv_complete_method(flsk);
    return;
  }

  while (retries--) {
    rlen = recv(flsk->sockfd, ((u_int8_t *)flsk->rbuf) + flsk->crdata_len,
                (flsk->trbuf_len - flsk->crdata_len),
                FL_TEST_BIT(flsk->flags, FL_SOCKF_NONBLOCKING) ?
                MSG_DONTWAIT : 0);

    if (rlen == 0) {
      FL_LOGR_ERR("Detected connection close on socket (%s, %s, %d)",
                  (task) ? task->name : "", flsk->name, flsk->sockfd);
      flsk->recv_error_method(flsk);
      return;
    }

    if (rlen < 0) {
      save_errno = errno;

      if (save_errno == EINTR) {
        retries++;
        continue;
      }
      if ((save_errno == EAGAIN) || (save_errno == EWOULDBLOCK)) {
        FL_FD_SET(flsk->sockfd, FL_FD_OP_READ);
        return;
      }

      FL_LOGR_ERR("Rx on socket (%s, %s, %d) failed, error %d <%s>. "
                  "Send shall not be attempted on this socket.",
                  (task) ? task->name : "", flsk->name, flsk->sockfd,
                  save_errno, strerror(save_errno));
      flsk->recv_error_method(flsk);
      return;
    }

    /* We have transmitted something. */
    flsk->crdata_len += rlen;
    if (flsk->recv_is_msg_complete_method(flsk)) {
      flsk->recv_complete_method(flsk);
      return;
    }

    retries = 3;
  } /* while (retries--) */

}

ssize_t fl_socket_generic_send(fl_socket_t *flsk, void *buf, size_t len,
                               const struct sockaddr_storage *dest_addr,
                               socklen_t addrlen)
{

  FL_ASSERT(flsk && buf && len);
  /* There can be only one outstanding send buffer (for now) */
  FL_ASSERT(!flsk->wbuf && !flsk->twbuf_len && !flsk->cwdata_len);
  if (FL_TEST_BIT(flsk->flags, FL_SOCKF_NONBLOCKING)) {
    FL_ASSERT(flsk->nb_send_method && flsk->send_complete_method &&
              flsk->send_error_method);
  }
  if ((flsk->type == SOCK_DGRAM) || (flsk->type == SOCK_RAW)) {
    FL_ASSERT(dest_addr && addrlen);
  }

  flsk->wbuf = buf;
  flsk->twbuf_len = len;

  if (FL_TEST_BIT(flsk->flags, FL_SOCKF_NONBLOCKING)) {
    if ((flsk->type == SOCK_DGRAM) || (flsk->type == SOCK_RAW)) {
      fl_sockaddr_dup(&flsk->wbuf_dest_addr, dest_addr, addrlen);
    }

    /* We will set the fd for writing and return. The process_sockets shall take
     * care of calling the non-blocking send routine.
     */
    FL_FD_SET(flsk->sockfd, FL_FD_OP_WRITE);
    return 0;
  }

  if (flsk->type == SOCK_DGRAM) {
    return fl_socket_sendto(flsk, buf, len, dest_addr, addrlen);
  } else if (flsk->type == SOCK_RAW) {
    return fl_socket_sendmsg(flsk, buf);
  } else if (flsk->type == SOCK_STREAM) {
    return fl_socket_send(flsk, buf, len);
  }

  FL_ASSERT(0);
  return -1;
}

void fl_socket_generic_nb_send(fl_socket_t *flsk)
{
  register fl_task_t *task;
  ssize_t wlen;
  int retries = 3, sleep_duration = 3;

  FL_ASSERT(flsk);
  task = flsk->task;

  while (retries > 0) {

    if (flsk->type == SOCK_DGRAM) {
      wlen = sendto(flsk->sockfd, ((u_int8_t *)flsk->wbuf) + flsk->cwdata_len,
                    (flsk->twbuf_len - flsk->cwdata_len),
                    FL_TEST_BIT(flsk->flags, FL_SOCKF_NONBLOCKING) ?
                    MSG_DONTWAIT : 0,
                    SA_CAST(&flsk->wbuf_dest_addr),
                    fl_sockaddr_len(SA_CAST(&flsk->wbuf_dest_addr)));
    } else if (flsk->type == SOCK_RAW) {
      wlen = sendmsg(flsk->sockfd, (const struct msghdr *) flsk->wbuf,
                    FL_TEST_BIT(flsk->flags, FL_SOCKF_NONBLOCKING) ?
                    MSG_DONTWAIT : 0);
    } else {
      wlen = send(flsk->sockfd, ((u_int8_t *)flsk->wbuf) + flsk->cwdata_len,
                  (flsk->twbuf_len - flsk->cwdata_len),
                  FL_TEST_BIT(flsk->flags, FL_SOCKF_NONBLOCKING) ?
                  MSG_DONTWAIT : 0);
    }

    if (wlen == 0) {
      if (flsk->type == SOCK_STREAM) {
        FL_LOGR_ERR("Connection closed on socket (%s, %s, %d)",
                    (task) ? task->name : "", flsk->name, flsk->sockfd);
        flsk->send_error_method(flsk);
        return;
      }

      /* We should not be hitting here for sendto and sendmsg */
      FL_ASSERT(0);
    }

    if (wlen < 0) {
      int save_errno = errno;

      if (save_errno == EINTR) {
        retries++;
      } else if ((save_errno == ENETUNREACH) || (save_errno == EHOSTUNREACH) ||
                 (save_errno == ENOBUFS)) {
        retries--;
        FL_LOGR_NOTICE("Tx on socket (%s, %s, %d) failed, error %d <%s>. "
                       "Shall retry after %d seconds",
                       (task) ? task->name : "", flsk->name, flsk->sockfd,
                       save_errno, strerror(save_errno), sleep_duration);
        sleep(sleep_duration);
      } else if ((save_errno == EAGAIN) || (save_errno == EWOULDBLOCK)) {
        break;
      } else {
        FL_LOGR_ERR("Tx on socket (%s, %s, %d) failed, error %d <%s>. "
                    "Send shall not be attempted on this socket.",
                    (task) ? task->name : "", flsk->name, flsk->sockfd,
                    save_errno, strerror(save_errno));
        flsk->send_error_method(flsk);
        return;
      }

    } else {

      /* We have tranmistted something. */
      flsk->cwdata_len += wlen;

      if (flsk->cwdata_len == flsk->twbuf_len) {
        flsk->send_complete_method(flsk);
        return;
      }

      retries = 3;
    }

  } /* while (retries) */

  FL_FD_SET(flsk->sockfd, FL_FD_OP_WRITE);
}

int fl_socket_select(fd_set **rfds, fd_set **wfds, fd_set **efds)
{
  fl_fd_set_t *fdset;
  int nfds, njobs = 0;
  struct timeval tv = { 0 };

  FL_ASSERT(rfds && wfds && efds);
  *rfds = *wfds = *efds = NULL;

  if (fl_fds_anyfds_set(FL_FD_OP_READ)) {
    *rfds = &exec_rbits;
    fdset = fl_fds_get_set(FL_FD_OP_READ);
    memcpy(*rfds, &fdset->fd_bits, sizeof(fd_set));
  }
  if (fl_fds_anyfds_set(FL_FD_OP_WRITE)) {
    *wfds = &exec_wbits;
    fdset = fl_fds_get_set(FL_FD_OP_WRITE);
    memcpy(*wfds, &fdset->fd_bits, sizeof(fd_set));
  }
  if (fl_fds_anyfds_set(FL_FD_OP_EXCEPT)) {
    *efds = &exec_ebits;
    fdset = fl_fds_get_set(FL_FD_OP_EXCEPT);
    memcpy(*efds, &fdset->fd_bits, sizeof(fd_set));
  }

 retry_select:
  nfds = select(fl_fds_get_max_fd() + 1, *rfds, *wfds, *efds,
                (njobs) ? &tv : NULL);
  if ((nfds == 0) && !njobs) {
    FL_LOGR_ERR("select() fired with no fds");
    FL_ASSERT(0);
  } else if (nfds < 0) {
    int save_errno = errno;

    if (save_errno == EINTR) {
      goto retry_select;
    }
    FL_LOGR_EMERG("select() fired with error %d<%s>",
                  save_errno, strerror(save_errno));
    return -1;
  }

  return nfds;
}

void fl_socket_process_reads(int *nfds, fd_set *fds)
{
  int save_nfds = *nfds;
  register fl_socket_t *li;

  FL_ASSERT(*nfds);

  LIST_FOREACH(li, &fl_sockets, socket_lc) {
    register int sockfd = li->sockfd;

    if (!FD_ISSET(sockfd, fds)) {
      continue;
    }

    FL_ASSERT(fl_fd_isset(sockfd, FL_FD_OP_READ));
    FL_ASSERT(li->nb_recv_method || li->accept_method);

    /* We only handle the here. New connections (via accept methods) are
     * handled in process_connections.
     */
    if (li->nb_recv_method) {
      /* Clear the fd because we are going to process it now. If the app wants
       * to read again, then it will have to set it again.
       */
      FL_FD_CLR(sockfd, FL_FD_OP_READ);
      /* Clear the fd from the exec_rbits */
      FD_CLR(sockfd, fds);
      (*nfds)--;
      li->nb_recv_method(li);
    }
  }

  if (save_nfds && ((save_nfds - *nfds) > 0)) {
    FL_LOGR_DEBUG("Processed %d socket reads", (save_nfds - *nfds));
  }
}

void fl_socket_process_writes(int *nfds, fd_set *fds)
{
  int save_nfds = *nfds;
  register fl_socket_t *li;

  FL_ASSERT(*nfds);

  LIST_FOREACH(li, &fl_sockets, socket_lc) {
    register int sockfd = li->sockfd;

    if (!FD_ISSET(sockfd, fds)) {
      continue;
    }

    FL_ASSERT(fl_fd_isset(sockfd, FL_FD_OP_WRITE));
    FL_ASSERT(li->nb_send_method);

    FL_FD_CLR(sockfd, FL_FD_OP_WRITE);
    FD_CLR(sockfd, fds);
    (*nfds)--;
    li->nb_send_method(li);
  }

  if (save_nfds && ((save_nfds - *nfds) > 0)) {
    FL_LOGR_DEBUG("Processed %d socket writes", (save_nfds - *nfds));
  }
}

void fl_socket_process_connections(int *nfds, fd_set *fds)
{
  int save_nfds = *nfds;
  register fl_socket_t *li;

  FL_ASSERT(*nfds);

  LIST_FOREACH(li, &fl_sockets, socket_lc) {
    register int sockfd = li->sockfd;

    if (!FD_ISSET(sockfd, fds)) {
      continue;
    }

    FL_ASSERT(fl_fd_isset(sockfd, FL_FD_OP_ACCEPT));
    FL_ASSERT(li->accept_method);

    FL_FD_CLR(sockfd, FL_FD_OP_ACCEPT);
    FD_CLR(sockfd, fds);
    (*nfds)--;
    li->accept_method(li);
  }

  if (save_nfds && ((save_nfds - *nfds) > 0)) {
    FL_LOGR_DEBUG("Processed %d new connections", (save_nfds - *nfds));
  }
}

static fl_socket_t *fl_socket_alloc(fl_task_t *task, const char *name,
                                    int domain, int type, int protocol,
                                    int sockfd)
{
  fl_socket_t *flsk;

  if (name && (strlen(name) >= FL_SOCKET_NAME_MAX_LEN)) {
    FL_ASSERT(0);
    return NULL;
  }

  FL_ALLOC(fl_socket_t, 1, flsk, "Socket");
  if (!flsk) {
    return NULL;
  }

  strcpy(flsk->name, name);
  flsk->domain = domain;
  flsk->type = type;
  flsk->protocol = protocol;
  flsk->sockfd = sockfd;

  if (LIST_EMPTY(&fl_sockets)) {
    LIST_INSERT_HEAD(&fl_sockets, flsk, socket_lc);
  } else {
    fl_socket_t *li;

    LIST_FOREACH(li, &fl_sockets, socket_lc) {
      if (li->sockfd > sockfd) {
        LIST_INSERT_BEFORE(li, flsk, socket_lc);
        break;
      }
      if (!LIST_NEXT(li, socket_lc)) {
        LIST_INSERT_AFTER(li, flsk, socket_lc);
        break;
      }
    }
  }

  if (task) {
    if (fl_task_validate_taskptr(task)) {
      if (LIST_EMPTY(&task->task_sockets)) {
        LIST_INSERT_HEAD(&task->task_sockets, flsk, task_socket_lc);
      } else {
        fl_socket_t *li;

        LIST_FOREACH(li, &task->task_sockets, task_socket_lc) {
          if (li->sockfd > sockfd) {
            LIST_INSERT_BEFORE(li, flsk, task_socket_lc);
            break;
          }
          if (LIST_NEXT(li, task_socket_lc) == NULL) {
            LIST_INSERT_AFTER(li, flsk, task_socket_lc);
            break;
          }
        }
      }
      flsk->task = task;
    } else {
      FL_LOGR_WARNING("Request to associate socket (%s, %d) with an "
                      "unrecognized task (%s)",
                      (name) ? name : "", sockfd, task->name);
    }
  }

  return flsk;
}

static int fl_socket_get_local_addr(fl_socket_t *flsk)
{
  register fl_task_t *task;
  int rc;
  socklen_t addrlen = sizeof(struct sockaddr_storage);

  FL_ASSERT(flsk && flsk->sockfd);
  task = flsk->task;

  rc = getsockname(flsk->sockfd, SA_CAST(&flsk->sa_local), &addrlen);
  if (rc < 0) {
    int save_errno = errno;
    FL_LOGR_ERR("Attempt to get local address on socket (%s, %s, %d) failed, "
                "error %d <%s>", (task) ? task->name : "",
                flsk->name, flsk->sockfd, save_errno, strerror(save_errno));
    return rc;
  }

  memset(flsk->local_addr, 0, FL_SOCKADDR_STR_MAX_LEN);
  if (((flsk->domain == AF_INET) || (flsk->domain == AF_INET6)) &&
      ((flsk->type == SOCK_DGRAM) || (flsk->type == SOCK_SEQPACKET) ||
       (flsk->type == SOCK_STREAM))) {
    sprintf(flsk->local_addr, "%s:%d",
            fl_sockaddr_ntop(&flsk->sa_local, flsk->local_addr,
                             FL_SOCKADDR_STR_MAX_LEN - 1),
            fl_sockaddr_port_hbo(&flsk->sa_local));
  } else {
    sprintf(flsk->local_addr, "%s",
            fl_sockaddr_ntop(&flsk->sa_local, flsk->local_addr,
                             FL_SOCKADDR_STR_MAX_LEN - 1));
  }

  return 0;
}

static ssize_t fl_socket_recvfrom(fl_socket_t *flsk, void *buf, size_t len,
                                  struct sockaddr_storage *src_addr,
                                  socklen_t *addrlen)
{
  ssize_t rc;
  int save_errno;

  FL_ASSERT(flsk && (flsk->sockfd >= 0));
  FL_ASSERT(!FL_TEST_BIT(flsk->flags, FL_SOCKF_NONBLOCKING));

  do {
    rc = recvfrom(flsk->sockfd, buf, len, 0, SA_CAST(src_addr), addrlen);
    save_errno = errno;
  } while ((rc == -1) && (errno == EINTR));

  if (rc == -1) {
    FL_LOGR_ERR("recvfrom on socket (%s, %s, %d) failed, "
                "error %d <%s>",
                (flsk->task) ? flsk->task->name : "", flsk->name,
                flsk->sockfd, save_errno, strerror(save_errno));
  }

  return rc;
}

static ssize_t fl_socket_recvmsg(fl_socket_t *flsk, struct msghdr *msg)
{
  ssize_t rc;
  int save_errno;

  FL_ASSERT(flsk && (flsk->sockfd >= 0));
  FL_ASSERT(!FL_TEST_BIT(flsk->flags, FL_SOCKF_NONBLOCKING));

  do {
    rc = recvmsg(flsk->sockfd, msg, 0);
    save_errno = errno;
  } while ((rc == -1) && (errno == EINTR));

  if (rc == -1) {
    FL_LOGR_ERR("recvmsg on socket (%s, %s, %d) failed, "
                "error %d <%s>",
                (flsk->task) ? flsk->task->name : "", flsk->name, flsk->sockfd,
                save_errno, strerror(save_errno));
  }

  return rc;
}

static ssize_t fl_socket_recv(fl_socket_t *flsk, void *buf, size_t len)
{
  ssize_t rc;
  int save_errno;

  FL_ASSERT(flsk && (flsk->sockfd >= 0));
  FL_ASSERT(!FL_TEST_BIT(flsk->flags, FL_SOCKF_NONBLOCKING));

  do {
    rc = recv(flsk->sockfd, buf, len, 0);
    save_errno = errno;
  } while ((rc == -1) && (errno == EINTR));

  if (rc == -1) {
    FL_LOGR_ERR("recv on socket (%s, %s, %d) failed, "
                "error %d <%s>",
                (flsk->task) ? flsk->task->name : "", flsk->name, flsk->sockfd,
                save_errno, strerror(save_errno));
  }

  return rc;
}

static ssize_t fl_socket_sendto(fl_socket_t *flsk, const void *buf, size_t len,
                                const struct sockaddr_storage *dest_addr,
                                socklen_t addrlen)
{
  ssize_t rc;
  int save_errno;
  char addrstr[INET6_ADDRSTRLEN+1] = { 0 };

  FL_ASSERT(flsk && (flsk->sockfd >= 0));
  FL_ASSERT(!FL_TEST_BIT(flsk->flags, FL_SOCKF_NONBLOCKING));

  do {
    rc = sendto(flsk->sockfd, buf, len, 0, SA_CCAST(dest_addr), addrlen);
    save_errno = errno;
  } while ((rc == -1) && (errno == EINTR));

  if (rc == -1) {
    FL_LOGR_ERR("sendto %s:%d (%d bytes) on socket (%s, %s, %d) failed, "
                "error %d <%s>",
                fl_sockaddr_ntop(dest_addr, addrstr, INET6_ADDRSTRLEN),
                fl_sockaddr_port_hbo(dest_addr),
                (int) len, (flsk->task) ? flsk->task->name : "", flsk->name,
                flsk->sockfd, save_errno, strerror(save_errno));
  }

  return rc;
}

static ssize_t fl_socket_sendmsg(fl_socket_t *flsk, const struct msghdr *msg)
{
  ssize_t rc;
  int save_errno;

  FL_ASSERT(flsk && (flsk->sockfd >= 0));
  FL_ASSERT(!FL_TEST_BIT(flsk->flags, FL_SOCKF_NONBLOCKING));

  do {
    rc = sendmsg(flsk->sockfd, msg, 0);
    save_errno = errno;
  } while ((rc == -1) && (errno == EINTR));

  if (rc == -1) {
    FL_LOGR_ERR("sendmsg on socket (%s, %s, %d) failed, error %d <%s>",
                (flsk->task) ? flsk->task->name : "", flsk->name, flsk->sockfd,
                save_errno, strerror(save_errno));
  }

  return rc;
}

static ssize_t fl_socket_send(fl_socket_t *flsk, const void *buf, size_t len)
{
  ssize_t rc;
  int save_errno;
  char addrstr[INET6_ADDRSTRLEN+1] = { 0 };

  FL_ASSERT(flsk && (flsk->sockfd >= 0));
  FL_ASSERT(!FL_TEST_BIT(flsk->flags, FL_SOCKF_NONBLOCKING));

  do {
    rc = send(flsk->sockfd, buf, len, 0);
    save_errno = errno;
  } while ((rc == -1) && (errno == EINTR));

  if (rc == -1) {
    FL_LOGR_ERR("send to %s:%d (%d bytes) on socket (%s, %s, %d) failed, "
                "error %d <%s>",
                fl_sockaddr_ntop(&flsk->sa_remote, addrstr,
                                 INET6_ADDRSTRLEN),
                fl_sockaddr_port_hbo(&flsk->sa_remote),
                (int) len,
                (flsk->task) ? flsk->task->name : "", flsk->name, flsk->sockfd,
                save_errno, strerror(save_errno));
  }

  return rc;
}
