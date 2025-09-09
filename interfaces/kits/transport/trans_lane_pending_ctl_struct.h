/*
 * Copyright (c) 2022-2025 Huawei Device Co., Ltd.
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

#ifndef TRANS_LANE_PENDING_CTL_STRUCT_H
#define TRANS_LANE_PENDING_CTL_STRUCT_H

#include <stdint.h>
#include <stdbool.h>
#include "softbus_def.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

typedef struct {
    char sessionName[SESSION_NAME_SIZE_MAX];
    bool isNetWorkingChannel;
    int32_t channelId;
} NetWorkingChannelInfo;

#ifdef __cplusplus
}
#endif /* __cplusplus */
#endif
