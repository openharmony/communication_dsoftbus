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

#ifndef NSTACKX_QDISC_H
#define NSTACKX_QDISC_H

#include <stdint.h>

#define QDISC_FILE_NAME_NAX_LENGTH 100
#define QDISC_MAX_LENGTH 10000
#define QDISC_DEFAULT_LENGTH 1000
#define QDISC_MIN_LENGTH 100

#define FIRST_QDISC_LEN 20
#define SECOND_QDISC_LEN 50

typedef struct _QdiscArg {
    int32_t ifIndex;
    int32_t protocol;
} QdiscArg;

typedef struct _QdiscValue {
    int32_t qlen;
} QdiscValue;

int32_t GetQdiscLeftLength(const char *devName, int32_t protocol, uint32_t *len);
#endif