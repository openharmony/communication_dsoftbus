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
    CAPS_DEBUG = CAPS_MAX,
    CAPS_MULTIPATH,
    CAPS_NORW,
    CAPS_MEMLOG,
    CAPS_RECV_FEEDBACK,
    CAPS_REALMAX,
};

#define NSTACKX_CAPS_MULTIPATH              NBITS(CAPS_MULTIPATH)
#define NSTACKX_CAPS_NORW                   NBITS(CAPS_NORW)
#define NSTACKX_CAPS_MEMLOG                 NBITS(CAPS_MEMLOG)
#define NSTACKX_CAPS_RECV_FEEDBACK          NBITS(CAPS_RECV_FEEDBACK)
#define NSTACKX_CAPS_MASK                   (NBITS(CAPS_REALMAX) - 1)

#ifdef __cplusplus
}
#endif

#endif /* #ifndef NSTACKX_DFILE_PRIVATE_H */
