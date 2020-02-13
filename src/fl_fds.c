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

#include "falco/fl_stdlib.h"
#include "falco/fl_tracevalue.h"
#include "falco/fl_fds.h"

fl_fd_set_t select_rbits;
fl_fd_set_t select_wbits;
fl_fd_set_t select_ebits;

const values_t fl_fd_ops[] = {
  { FL_FD_OP_READ,   "Read"   },
  { FL_FD_OP_WRITE,  "Write"  },
  { FL_FD_OP_ACCEPT, "Accept" },
  { FL_FD_OP_EXCEPT, "Except" },
  { 0, NULL }
};

fl_fd_set_t *fl_fds_get_set(fl_fd_op_e op)
{
  switch (op) {
  case FL_FD_OP_READ:   return &select_rbits;
  case FL_FD_OP_WRITE:  return &select_wbits;
  case FL_FD_OP_ACCEPT: return &select_rbits;
  default:
  case FL_FD_OP_EXCEPT: return &select_ebits;
  }

  FL_ASSERT(0);
  return NULL;
}
