/*******************************************************************************
BSD 3-Clause License

Copyright (c) 2014 - 2020, NetworkArt Systems Private Limited (www.networkart.com)
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

#include <string.h>

#include "falco/fl_tracevalue.h"

#define FLAGS_TRACE_STORE_BUFSIZ 2048
static char flags_trace_store[FLAGS_TRACE_STORE_BUFSIZ];

const char *fl_trace_value(const values_t *values, int value)
{
  const values_t *pval;

  for (pval = values; pval->valname; pval++) {
    if (pval->val == (u_int32_t) value) {
      return(pval->valname);
    }
  }

  return((char *) NULL);
}

const char *fl_trace_flags(const values_t *values, flag_t flags)
{
  const values_t *pval;
  flag_t visited = 0;
  char *dbuf = flags_trace_store;
  u_int16_t written = 0;

  *dbuf = '\0';

  for (pval = values; pval->val; pval++) {
    const char *sbuf = pval->valname;

    if (!(FL_MATCH_BIT(flags, pval->val) &&
          !FL_MATCH_BIT(visited, pval->val))) {
      continue;
    }

    FL_SET_BIT(visited, pval->val);

    while (*sbuf && (written < (sizeof(flags_trace_store) - 4))) {
      *dbuf++ = *sbuf++;
      written++;
    }

    if (written >= (sizeof(flags_trace_store) - 4)) {
      *dbuf++ = '.';
      *dbuf++ = '.';
      written++;
      break;
    } else {
      *dbuf++ = ' ';
    }
    written++;
  }

  *dbuf = '\0';

  return flags_trace_store;
}
