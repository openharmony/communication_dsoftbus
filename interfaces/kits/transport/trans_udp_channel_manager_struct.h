/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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

#ifndef TRANS_UDP_CHANNEL_MANAGER_STRUCT_H
#define TRANS_UDP_CHANNEL_MANAGER_STRUCT_H

#include <stdint.h>
#include "softbus_app_info.h"
#include "softbus_common.h"
// 需要改成struct
#include "trans_uk_manager.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    UDP_CHANNEL_STATUS_INIT = 0,
    UDP_CHANNEL_STATUS_OPEN_AUTH,
    UDP_CHANNEL_STATUS_NEGING,
    UDP_CHANNEL_STATUS_DONE
} UdpChannelStatus;

typedef struct {
    bool isMeta;
    bool isReply;
    uint8_t tos;
    UdpChannelStatus status;
    uint32_t requestId;
    int32_t errCode;
    uint32_t timeOut;
    int64_t seq;
    ListNode node;
    AuthHandle authHandle;
    UkIdInfo ukIdInfo;
    AppInfo info;
} UdpChannelInfo;

typedef struct {
    ListNode node;
    int64_t channelId;
    int pid;
    char pkgName[PKG_NAME_SIZE_MAX];
} UdpChannelNotifyInfo;

#ifdef __cplusplus
}
#endif

#endif // !TRANS_UDP_CHANNEL_MANAGER_STRUCT_H
