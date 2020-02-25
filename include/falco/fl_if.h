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

#ifndef _FL_IF_H_
#define _FL_IF_H_

#include <features.h>

#include <sys/socket.h>
#include <sys/queue.h>

#include <net/if.h>
#include <netinet/in.h>
#include <linux/if_ether.h>

#include "falco/fl_tracevalue.h"

#define FL_IF_TRACEFLAGS(_f_) fl_trace_flags(fl_if_flags, (_f_))

/* Interface changes */
#define FL_IFC_IN6ADDR        BITVAL(0x01)
#define FL_IFC_INADDR         BITVAL(0x02)
#define FL_IFC_NAME           BITVAL(0x04)
#define FL_IFC_STATUS         BITVAL(0x08)

#define FL_IF_SIN_ADDR(_if_)  (_if_)->in.addr
#define FL_IF_IN_ADDR(_if_)   FL_IF_SIN_ADDR((_if_)).sin_addr
#define FL_IF_SIN_MASK(_if_)  (_if_)->in.netmask
#define FL_IF_IN_MASK(_if_)   FL_IF_SIN_MASK((_if_)).sin_addr

#define FL_IF_SIN6_ADDR(_if_) (_if_)->in6.addr
#define FL_IF_IN6_ADDR(_if_)  FL_IF_SIN6_ADDR((_if_)).sin6_addr
#define FL_IF_SIN6_MASK(_if_) (_if_)->in6.netmask
#define FL_IF_IN6_MASK(_if_)  FL_IF_SIN6_MASK((_if_)).sin6_addr

typedef struct fl_nwif_t_ {
  LIST_ENTRY(fl_nwif_t_) nwif_lc;

  char name[IFNAMSIZ];
  flag_t flags;
  u_int32_t index;
  u_int8_t macaddr[ETH_ALEN];

  struct {
    struct sockaddr_in addr;
    struct sockaddr_in netmask;
    union {
      struct sockaddr_in broadaddr;
      struct sockaddr_in dstaddr;
    } ifa_ifu;
  } in;

  struct {
    struct sockaddr_in6 addr;
    struct sockaddr_in6 netmask;
    union {
      struct sockaddr_in6 broadaddr;
      struct sockaddr_in6 dstaddr;
    } ifa_ifu;
  } in6;

} fl_nwif_t;

typedef LIST_HEAD(fl_nwif_list_t_, fl_nwif_t_) fl_nwif_list_t;

extern int fl_if_module_init(void);
extern void fl_if_module_cleanup(void);

extern fl_nwif_list_t *fl_if_get_all(void);
extern void fl_if_dump_all(FILE *fd);

extern fl_nwif_t *fl_if_get_by_mac_address(const u_int8_t *addr);

extern int fl_if_get_mac_address(const char *if_name, u_int8_t *addr);

extern const values_t fl_if_flags[];
extern const values_t fl_if_changes[];

#endif /*_FL_IF_H_ */
