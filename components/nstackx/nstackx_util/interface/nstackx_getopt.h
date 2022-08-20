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

#ifndef NSTACKX_GETOPT_H
#define NSTACKX_GETOPT_H
#include "sys_common_header.h"

#ifdef __cplusplus
extern "C" {
#endif

#define NSTACK_GETOPT_END_OF_STR (-1)
#define NSTACK_GETOPT_UNKNOW_OPT '?'

typedef struct {
    int32_t argvIdx;
    int32_t argvOffset;
    const char *attachArg;
} NstackGetOptMsg;

NSTACKX_EXPORT int32_t NstackInitGetOptMsg(NstackGetOptMsg *optMsg);
NSTACKX_EXPORT int32_t NstackGetOpt(NstackGetOptMsg *optMsg, int32_t argc, const char *const *argv, const char *opts);
NSTACKX_EXPORT const char *NstackGetOptArgs(const NstackGetOptMsg *optMsg);

#ifdef __cplusplus
}
#endif
#endif /* NSTACKX_GETOPT_H */

