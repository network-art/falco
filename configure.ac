# BSD 3-Clause License
#
# Copyright (c) 2020, NetworkArt Systems Private Limited (www.networkart.com)
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice, this
#    list of conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright notice,
#    this list of conditions and the following disclaimer in the documentation
#    and/or other materials provided with the distribution.
#
# 3. Neither the name of the copyright holder nor the names of its
#    contributors may be used to endorse or promote products derived from
#    this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

AC_INIT([falco], [0.2], [info@networkart.com])
AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_MACRO_DIR([m4])
AC_PREFIX_DEFAULT(/usr)

AM_INIT_AUTOMAKE([-Wall -Werror foreign])
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES(yes)], [])
AM_PROG_AR

AC_SUBST(FALCO_MAJOR_VERSION, 0)
AC_SUBST(FALCO_MINOR_VERSION, 2)
AC_SUBST(FALCO_PATCH_VERSION, 0)

CFLAGS="${CFLAGS} -Wall -Werror"

# Checks for programs
AC_PROG_CC
LT_INIT

# Checks for header files
AC_CHECK_HEADERS([arpa/inet.h \
  assert.h \
  features.h \
  limits.h \
  linux/if_ether.h \
  net/if.h \
  netinet/in.h \
  paths.h signal.h \
  stdarg.h \
  stdio.h \
  stdlib.h \
  sys/param.h \
  sys/queue.h \
  sys/select.h \
  sys/socket.h \
  sys/timerfd.h \
  sys/types.h \
  sys/un.h \
  syslog.h \
])

# Checks for typedefs, structures and compiler characteristics

# Checks for library functions
AC_CHECK_FUNCS([malloc])

AC_CONFIG_FILES([Makefile \
  include/Makefile \
  src/Makefile \
  src/falco.pc \
])
AC_OUTPUT
