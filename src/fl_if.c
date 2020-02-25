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
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <ifaddrs.h>
#include <arpa/inet.h>

#include "falco/fl_stdlib.h"
#include "falco/fl_if.h"
#include "falco/fl_logr.h"

#define FL_NWIF_MEM_BLOCK_NAME "Falco Network Interface"

const values_t fl_if_flags[] = {
  { IFF_ALLMULTI,           "ALLMULTI"          },
  { IFF_AUTOMEDIA,          "AUTOMEDIA"         },
  { IFF_BROADCAST,          "BROADCAST"         },
  { IFF_DEBUG,              "DEBUG"             },
  { IFF_DYNAMIC,            "DYNAMIC"           },
  { IFF_LOOPBACK,           "LOOPBACK"          },
  { IFF_MASTER,             "MASTER"            },
  { IFF_MULTICAST,          "MULTICAST"         },
  { IFF_NOARP,              "NOARP"             },
  { IFF_NOTRAILERS,         "NOTRAILERS"        },
  { IFF_POINTOPOINT,        "POINTOPOINT"       },
  { IFF_PORTSEL,            "PORTSEL"           },
  { IFF_PROMISC,            "PROMISC"           },
  { IFF_RUNNING,            "RUNNING"           },
  { IFF_SLAVE,              "SLAVE"             },
  { IFF_UP,                 "UP"                },
  { 0, NULL }
};

const values_t fl_if_changes[] = {
  { FL_IFC_IN6ADDR,         "IPv6_ADDR"         },
  { FL_IFC_INADDR,          "IPv4_ADDR"         },
  { FL_IFC_NAME,            "NAME"              },
  { FL_IFC_STATUS,          "STATUS"            },
  { 0, NULL }
};

static void fl_if_free_all(fl_nwif_list_t *list);

static fl_nwif_list_t fl_nwifs;

int fl_if_module_init()
{
  int rc, save_errno, family;
  struct ifaddrs *ifaddr = NULL;
  register struct ifaddrs *ifa;
  fl_nwif_t *nwif;
  register fl_nwif_t *li;
  register fl_nwif_list_t *list = &fl_nwifs;

  LIST_INIT(list);

  rc = getifaddrs(&ifaddr);
  if (rc == -1) {
    save_errno = errno;
    FL_LOGR_ERR("%s(): Retrieving network interfaces failed, error %d<%s>",
                __func__, save_errno, strerror(save_errno));
    return -1;
  }

  if (!ifaddr) {
    FL_LOGR_NOTICE("%s(): No network interfaces were retrieved", __func__);
    return 0;
  }

  for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
    family = ifa->ifa_addr->sa_family;
    if ((family != AF_INET) && (family != AF_INET6)) {
      /* We care about IPv4 and IPv6 network interfaces */
      continue;
    }

    /* See if we have matching interface in our list that is getting built */
    LIST_FOREACH(li, list, nwif_lc) {
      if (!strcmp(li->name, ifa->ifa_name)) {
        break;
      }
    }

    if (li) {
      nwif = li;
    } else {
      FL_ALLOC(fl_nwif_t, 1, nwif, FL_NWIF_MEM_BLOCK_NAME);
      if (!nwif) {
        FL_ASSERT(0);
        FL_LOGR_ERR("%s(): Could not allocate memory for %s", __func__,
                    FL_NWIF_MEM_BLOCK_NAME);
        fl_if_free_all(list);
        return -1;
      }
      if (fl_if_get_mac_address(ifa->ifa_name, nwif->macaddr) < 0) {
        FL_ASSERT(0);
        FL_LOGR_ERR("%s: Failed to get MAC address for interface %s", __func__,
                    ifa->ifa_name);
        fl_if_free_all(list);
        return -1;
      }
      nwif->index = if_nametoindex(ifa->ifa_name);
      if (!nwif->index) {
        FL_ASSERT(0);
        save_errno = errno;
        FL_LOGR_ERR("%s: Failed to get interface index for %s, error %d<%s>",
                    __func__, ifa->ifa_name, save_errno, strerror(save_errno));
        fl_if_free_all(list);
        return -1;
      }

      strcpy(nwif->name, ifa->ifa_name);
      LIST_INSERT_HEAD(list, nwif, nwif_lc);
    }

    if (family == AF_INET) {
      memcpy(&FL_IF_SIN_ADDR(nwif), ifa->ifa_addr,
             sizeof(FL_IF_SIN_ADDR(nwif)));
      memcpy(&FL_IF_SIN_MASK(nwif), ifa->ifa_netmask,
             sizeof(FL_IF_SIN_MASK(nwif)));
      memcpy(&nwif->in.ifa_ifu, &ifa->ifa_ifu, sizeof(nwif->in.ifa_ifu));
    } else {
      nwif->flags = ifa->ifa_flags;
      memcpy(&FL_IF_SIN6_ADDR(nwif), ifa->ifa_addr,
             sizeof(FL_IF_SIN6_ADDR(nwif)));
      memcpy(&FL_IF_SIN6_MASK(nwif), ifa->ifa_netmask,
             sizeof(FL_IF_SIN6_MASK(nwif)));
      memcpy(&nwif->in6.ifa_ifu, &ifa->ifa_ifu, sizeof(nwif->in6.ifa_ifu));
    }
  }

  freeifaddrs(ifaddr);
  return 0;
}

void fl_if_module_cleanup()
{
  fl_if_free_all(&fl_nwifs);
}

fl_nwif_list_t *fl_if_get_all()
{
  return &fl_nwifs;
}

void fl_if_dump_all(FILE *fd)
{
  register fl_nwif_t *li;
  register fl_nwif_list_t *list = &fl_nwifs;
  char inaddrstr[INET6_ADDRSTRLEN] = { 0 };
  char inmaskstr[INET6_ADDRSTRLEN] = { 0 };
  char in6addrstr[INET6_ADDRSTRLEN] = { 0 };
  char in6maskstr[INET6_ADDRSTRLEN] = { 0 };

  if (fd) {
    fprintf(fd, "\n--------------------------------------------------------------------------------\n");
    fprintf(fd, "Network Interfaces\n");
    fprintf(fd, "--------------------------------------------------------------------------------\n");
  }

  if (LIST_EMPTY(list)) {
    if (fd) {
      fprintf(fd, "    No network interfaces are present\n");
    } else {
      FL_LOGR_INFO("No network interfaces are present");
    }
    return;
  }

  LIST_FOREACH(li, list, nwif_lc) {
    if (fd) {
      fprintf(fd, "\n%s (index %d): %s/%s, %s/%s\n",
              li->name, li->index,
              inet_ntop(AF_INET, &FL_IF_IN_ADDR(li), inaddrstr,
                        INET6_ADDRSTRLEN),
              inet_ntop(AF_INET, &FL_IF_IN_MASK(li), inmaskstr,
                        INET6_ADDRSTRLEN),
              inet_ntop(AF_INET6, &FL_IF_IN6_ADDR(li), in6addrstr,
                        INET6_ADDRSTRLEN),
              inet_ntop(AF_INET6, &FL_IF_IN6_MASK(li), in6maskstr,
                        INET6_ADDRSTRLEN));
      fprintf(fd, "    MAC address: %02x:%02x:%02x:%02x:%02x:%02x\n",
              li->macaddr[0], li->macaddr[1], li->macaddr[2],
              li->macaddr[3], li->macaddr[4], li->macaddr[5]);
      fprintf(fd, "    Flags: 0x%08x< %s>", li->flags,
              fl_trace_flags(fl_if_flags, li->flags));
      fprintf(fd, "\n");
    } else {
      FL_LOGR_INFO("Interface (%s, %d): %s/%s, %s/%s, MAC address "
                   "%02x:%02x:%02x:%02x:%02x:%02x, 0x%08x< %s>",
                   li->name, li->index,
                   inet_ntop(AF_INET, &FL_IF_IN_ADDR(li), inaddrstr,
                             INET6_ADDRSTRLEN),
                   inet_ntop(AF_INET, &FL_IF_IN_MASK(li), inmaskstr,
                             INET6_ADDRSTRLEN),
                   inet_ntop(AF_INET6, &FL_IF_IN6_ADDR(li), in6addrstr,
                             INET6_ADDRSTRLEN),
                   inet_ntop(AF_INET6, &FL_IF_IN6_MASK(li), in6maskstr,
                             INET6_ADDRSTRLEN),
                   li->macaddr[0], li->macaddr[1], li->macaddr[2],
                   li->macaddr[3], li->macaddr[4], li->macaddr[5],
                   li->flags, fl_trace_flags(fl_if_flags, li->flags));
    }
  }
}

fl_nwif_t *fl_if_get_by_mac_address(const u_int8_t *addr)
{
  register fl_nwif_t *li;

  LIST_FOREACH(li, &fl_nwifs, nwif_lc) {
    if (!memcmp(li->macaddr, addr, sizeof(li->macaddr))) {
      return li;
    }
  }

  return NULL;
}

int fl_if_get_mac_address(const char *if_name, u_int8_t *addr)
{
  register int sockfd, rc = 0, save_errno;
  struct ifreq ifr;

  if (!if_name || !strlen(if_name) || (strlen(if_name) >= IFNAMSIZ)) {
    FL_ASSERT(0);
    FL_LOGR_ERR("%s: Interface name (%s) is either null or empty or length "
                "exceeds %d bytes", __func__,
                (if_name) ? ((strlen(if_name)) ? if_name : "\"\"") : "",
                IFNAMSIZ - 1);
    return -1;
  }
  if (!addr) {
    FL_ASSERT(0);
    FL_LOGR_ERR("%s: Parameter to store the MAC address into is NULL",
                __func__);
    return -1;
  }

  strcpy((char *)&ifr.ifr_name, if_name);

  do {
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd == -1) {
      save_errno = errno;
      FL_LOGR_ERR("Failed to create dgram socket to get interface address of "
                  "%s, error %d<%s>", if_name,
                  save_errno, strerror(save_errno));
      rc = -1;
      break;
    }

    rc = ioctl(sockfd, SIOCGIFHWADDR, &ifr);
    if (rc < 0) {
      save_errno = errno;
      FL_LOGR_ERR("Failed to get MAC address for interface %s, error %d<%s>",
                  if_name, save_errno, strerror(save_errno));
      break;
    }

    memcpy(addr, &ifr.ifr_hwaddr.sa_data, sizeof(ifr.ifr_hwaddr.sa_data));
  } while(0);

  if (sockfd >= 0) {
    close(sockfd);
  }

  return rc;
}

static void fl_if_free_all(fl_nwif_list_t *list)
{
  register fl_nwif_t *li;

  FL_ASSERT(list);
  while (!LIST_EMPTY(list)) {
    li = LIST_FIRST(list);
    LIST_REMOVE(li, nwif_lc);
    FL_FREE(li, FL_NWIF_MEM_BLOCK_NAME);
  }
}
