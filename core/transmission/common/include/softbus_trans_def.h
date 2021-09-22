/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#ifndef SOFTBUS_TRANS_DEF_H
#define SOFTBUS_TRANS_DEF_H

#include "session.h"

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

    typedef struct {
        const char* sessionName;
        const char* peerSessionName;
        const char* peerDeviceId;
        const char* groupId;
        const SessionAttribute* attr;
    } SessionParam;

    typedef struct {
        int32_t channelId;
        int32_t channelType;
    } TransInfo;

    typedef struct {
        TransInfo transInfo;
        int32_t ret;
    } TransSerializer;

#ifdef __cplusplus
}
#endif // __cplusplus
#endif // SOFTBUS_TRANS_DEF_H