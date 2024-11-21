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

#ifndef SOFTBUS_TRANS_DEF_H
#define SOFTBUS_TRANS_DEF_H

#include <stdbool.h>
#include "session.h"

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

#define DISABLE_FD (-1)

#define MSG_FLAG_REQUEST 0
#define MES_FLAG_REPLY 1
#define TRAFFIC_LEN 32
#define UNKNOW_OS_TYPE 1 /* peer osType unknow */

typedef struct {
    const char *sessionName;
    const char *peerSessionName;
    const char *peerDeviceId;
    const char *groupId;
    const SessionAttribute *attr;
    QosTV qos[QOS_TYPE_BUTT];
    uint32_t qosCount;
    int32_t sessionId;
    bool isQosLane;
    bool isAsync;
    uint32_t actionId;
    int32_t pid;
} SessionParam;

typedef struct {
    int32_t channelId;
    int32_t channelType;
    int32_t eventId;
    int32_t tvCount;
    int32_t pid;
    const QosTv *tvList;
} QosParam;

typedef struct {
    int32_t channelId;
    int32_t channelType;
} TransInfo;

typedef struct {
    TransInfo transInfo;
    int32_t ret;
} TransSerializer;

typedef enum {
    FRAME_COST_LT10MS = 0,
    FRAME_COST_LT30MS,
    FRAME_COST_LT50MS,
    FRAME_COST_LT75MS,
    FRAME_COST_LT100MS,
    FRAME_COST_LT120MS,
    FRAME_COST_GE120MS,
    FRAME_COST_BUTT,
} StreamFrameCost;

typedef enum {
    FRAME_BIT_RATE_LT3M = 0,
    FRAME_BIT_RATE_LT6M,
    FRAME_BIT_RATE_LT10M,
    FRAME_BIT_RATE_LT20M,
    FRAME_BIT_RATE_LT30M,
    FRAME_BIT_RATE_GE30M,
    FRAME_BIT_RATE_BUTT,
} StreamFrameBitRate;

typedef struct {
    uint32_t costTimeStatsCnt[FRAME_COST_BUTT];
    uint32_t sendBitRateStatsCnt[FRAME_BIT_RATE_BUTT];
} StreamSendStats;

typedef struct {
    unsigned char stats[TRAFFIC_LEN];
} TrafficStats;

typedef struct TransReceiveData {
    void *data;
    uint32_t dataLen;
    int32_t dataType;
} TransReceiveData;
#ifdef __cplusplus
}
#endif // __cplusplus
#endif // SOFTBUS_TRANS_DEF_H
