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

#ifndef _FL_BITS_H_
#define _FL_BITS_H_

#include <sys/types.h>

#define FL_SET_BIT(_var_, _val_)              ((_var_) |= _val_)
#define FL_RESET_BIT(_var_, _val_)            ((_var_) &= ~(_val_))
#define FL_FLIP_BIT(_var_, _val_)             ((_var_) ^= (_val_))
#define FL_TEST_BIT(_var_, _val_)             ((_var_) &  (_val_))
#define FL_MATCH_BIT(_var_, _val_)            (((_var_) & (_val_)) == (_val_))
#define FL_CMP_BIT(_var_, _val1_, _val2_)     (((_var_) & (_val1_)) == _val2_)
#define FL_MATCH_BIT_MASK(_var_, _m_, _val_)  (!(((_var_) ^ (_m_)) & (_val_)))

#ifndef BITVAL
#define BITVAL(_b_) _b_ ## UL
#endif /* BITVAL */

typedef u_int32_t flag_t;

#endif /* _FL_BITS_H_ */
