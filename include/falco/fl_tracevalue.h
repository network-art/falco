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

/**
 * @file
 * @brief Trace utility
 */

#ifndef _FL_TRACEVALUE_H_
#define _FL_TRACEVALUE_H_

#include <sys/types.h>
#include <stdlib.h>

#include "falco/fl_bits.h"

/**
 * @brief Data type to associate an unsigned integer (32-bit) value with a name.
 * Useful for printing information that can help in debugging and
 * troubleshooting.
 */
typedef struct _values_t_ {
  u_int32_t val;
  const char *valname;
} values_t;

/**
 * @brief Trace/Print value
 *
 * This function prints the name of a value, if found in the list of values
 * (definitions).
 *
 * @param[in] values Pointer to an array of value definitions (#values_t)
 * @param[in] value Value to be matched
 *
 * @return If value is found, a pointer to the name is returned.
 * Otherwise, NULL is returned.
 */
extern const char *fl_trace_value(const values_t *values, int value);

/**
 * @brief Trace/Print flags
 *
 * This function matches the all bits present in @p flags against different
 * value definitions in @p values. Names of the flags (that have matched) are
 * printed to an array, and pointer to the array is returned.
 *
 * @param[in] values Pointer to an array of value definitions (#values_t)
 * @param[in] flags Flags that need to be matched in values and printed
 *
 * @return Pointer to an array containing the names of the flags.
 */
extern const char *fl_trace_flags(const values_t *values, flag_t flags);

#endif /* _FL_TRACEVALUE_H_ */
