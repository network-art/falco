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

project(falco)
# CMake minimum required version is that Ubuntu Xenial default installation
cmake_minimum_required(VERSION 3.5 FATAL_ERROR)

enable_language(C)

option(BUILD_TESTS "Build unit tests" OFF)
option(ENABLE_CC_DEBUG_SYMBOLS "Produce debugging information for GDB" ON)
option(ENABLE_CC_OPTIMIZATION "Enable optimizations that can be done by GCC" ON)
option(ENABLE_ASSERTIONS "Enable assert calls" ON)

if(ENABLE_CC_DEBUG_SYMBOLS)
  add_compile_options(-g)
endif()

if(ENABLE_CC_OPTIMIZATION)
  add_compile_options(-O3)
endif()

add_compile_options(
	-Wall
	-Wcast-align
	-Werror
	-Wextra
	-Wformat
	-Wformat-security
	-Wno-format-zero-length
	-Wno-unused-parameter
	-Wsign-compare
	-Wwrite-strings
	-Wno-variadic-macros
	-fdiagnostics-show-option
	-pedantic
)

if(NOT DEFINED INCLUDE_INSTALL_PREFIX)
  set(INCLUDE_INSTALL_PREFIX "include")
endif()

if(NOT DEFINED LIBRARY_INSTALL_DIR)
  set(LIBRARY_INSTALL_DIR "lib")
endif()

include_directories(include)

add_library(${PROJECT_NAME}_s STATIC
  src/fl_fds.c
  src/fl_if.c
  src/fl_logr.c
  src/fl_process.c
  src/fl_signal.c
  src/fl_socket.c
  src/fl_task.c
  src/fl_timer.c
  src/fl_tracevalue.c
)

install(
  DIRECTORY "include/falco"
  DESTINATION ${INCLUDE_INSTALL_PREFIX}
	FILES_MATCHING PATTERN "*.h"
)

install(TARGETS
  ${PROJECT_NAME}_s
  ARCHIVE DESTINATION ${LIBRARY_INSTALL_DIR}
  LIBRARY DESTINATION ${LIBRARY_INSTALL_DIR}
)
