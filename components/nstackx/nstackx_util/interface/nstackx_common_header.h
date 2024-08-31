/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef NSTACKX_COMMON_HEADER_H
#define NSTACKX_COMMON_HEADER_H

#include "sys_common_header.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

// C standard library header files
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdarg.h>
#include <string.h>
#include <time.h>

#define PIPE_OUT 0
#define PIPE_IN 1
#define PIPE_FD_NUM 2

#define BYTE_BITS_NUM 8
#define TYPE_BITS_NUM(_type) (sizeof(_type) * BYTE_BITS_NUM)

typedef enum {
    CIPHER_AES_GCM = 0,
    CIPHER_CHACHA,
    CIPHER_AES_NI, // hardware optimize
} DFileCipherType;

#endif // NSTACKX_COMMON_HEADER_H
