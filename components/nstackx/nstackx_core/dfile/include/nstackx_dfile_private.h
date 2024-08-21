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

#ifndef NSTACKX_DFILE_PRIVATE_H
#define NSTACKX_DFILE_PRIVATE_H

#include "nstackx_dfile.h"

#ifdef __cplusplus
extern "C" {
#endif

enum {
    INTERNAL_CAPS_NORW = 0,
    INTERNAL_CAPS_MEMLOG,
    INTERNAL_CAPS_RECV_FEEDBACK,
    /* add more capability here */
    INTERNAL_CAPS_MAX,
};

#define NSTACKX_INTERNAL_CAPS_NORW                   NBITS(INTERNAL_CAPS_NORW)
#define NSTACKX_INTERNAL_CAPS_MEMLOG                 NBITS(INTERNAL_CAPS_MEMLOG)
#define NSTACKX_INTERNAL_CAPS_RECV_FEEDBACK          NBITS(INTERNAL_CAPS_RECV_FEEDBACK)

#define NSTACKX_CIPHER_AES_GCM                       NBITS(CIPHER_AES_GCM)
#define NSTACKX_CIPHER_CHACHA                        NBITS(CIPHER_CHACHA)
#define NSTACKX_CIPHER_AES_NI                        NBITS(CIPHER_AES_NI)

#ifdef __cplusplus
}
#endif

#endif /* #ifndef NSTACKX_DFILE_PRIVATE_H */
