/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef TRANS_NETWORK_STATISTICS_H
#define TRANS_NETWORK_STATISTICS_H

#include "softbus_common.h"
#include "softbus_def.h"

#ifdef __cplusplus
extern "C" {
#endif

#define MAX_LANE_ID_LEN 64
#define MAX_SOCKET_RESOURCE_NUM 128
#define MAX_NETWORK_RESOURCE_NUM 128
#define MAX_CHANNEL_INFO_NUM 128
#define MAX_SOCKET_RESOURCE_LEN 1024

typedef struct {
    ListNode node;
    char socketName[SESSION_NAME_SIZE_MAX];
    int32_t socketId;
    int32_t channelId;
    int32_t channelType;
    uint64_t laneId;
    int64_t traffic;
    int64_t startTime;
    int64_t endTime;
} SocketResource;

typedef struct {
    uint64_t laneId;
    char localUdid[UDID_BUF_LEN];
    char peerUdid[UDID_BUF_LEN];
    int32_t laneLinkType;
} NetworkResource;

void AddChannelStatisticsInfo(int32_t channelId, int32_t channelType);

void AddNetworkResource(NetworkResource *networkResource);

void UpdateNetworkResourceByLaneId(int32_t channelId, int32_t channelType, uint64_t laneId, const void *dataInfo,
    uint32_t len);

void DeleteNetworkResourceByLaneId(uint64_t laneId);

int32_t TransNetworkStatisticsInit(void);

void TransNetworkStatisticsDeinit(void);

#ifdef __cplusplus
}
#endif
#endif // TRANS_NETWORK_STATISTICS_H