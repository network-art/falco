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

#ifndef _FL_STDLIB_H_
#define _FL_STDLIB_H_

#include <stdlib.h>
#include <assert.h>

#include "falco/fl_logr.h"

#if (defined(ENABLE_ASSERTIONS))
#define FL_ASSERT(_cond_) assert((_cond_))
#else /* !ENABLE_ASSERTIONS */
#define FL_ASSERT(_cond_)
#endif /* !ENABLE_ASSERTIONS */      

#define FL_ALLOC(_casttotype_, _n_, _var_, _msg_)                   \
  do {                                                              \
    _var_ = (_casttotype_ *) calloc((_n_), sizeof(_casttotype_));   \
    if (!_var_) {                                                   \
      FL_ASSERT(0);                                                 \
      FL_LOGR_CRIT("%s, %d: Unable to allocate memory "             \
                   "[Requested %d blocks of size %d each] for %s",  \
                   __func__, __LINE__,                              \
                   (unsigned int)_n_, (int) sizeof(_casttotype_),   \
                   _msg_);                                          \
    }                                                               \
  } while (0)

#define FL_REALLOC(_casttotype_, _n_, _var_, _msg_)                 \
  do {                                                              \
    _var_ = (_casttotype_ *)                                        \
      realloc((_var_), ((_n_) * sizeof(_casttotype_)));             \
    if (!_var_) {                                                   \
      FL_ASSERT(0);                                                 \
      FL_LOGR_CRIT("%s, %d: Unable to allocate memory "             \
                   "[Requested %d blocks of size %d each] for %s",  \
                   __func__, __LINE__,                              \
                   _n_, (int) sizeof(_casttotype_), _msg_);         \
    }                                                               \
  } while (0)

#define FL_FREE(_var_, _msg_)                                       \
  do {                                                              \
    free((_var_));                                                  \
    FL_LOGR_DEBUG("%s, %d: Freed memory of type %s",                \
                  __func__, __LINE__, _msg_);                       \
    (_var_) = NULL;                                                 \
  } while (0)

#endif /* _FL_STDLIB_H_ */
