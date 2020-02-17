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
#include <net/if.h>

#include "falco/fl_if.h"

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
