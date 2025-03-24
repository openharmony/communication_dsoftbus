/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef LNN_LANE_DFX_H
#define LNN_LANE_DFX_H

#include <stdint.h>
#include "lnn_event.h"
#include "lnn_lane_link_p2p.h"
#include "lnn_lane_interface.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    EVENT_LANE_STAGE = 0x0,         // the lane state when report lane event info
    EVENT_LANE_HANDLE,              // lane handle
    EVENT_LANE_LINK_TYPE,           // lane link type
    EVENT_LANE_MIN_BW,              // qos info lane min bw
    EVENT_LANE_MAX_LANE_LATENCY,    // qos info lane max lane latency
    EVENT_LANE_MIN_LANE_LATENCY,    // qos info lane min lane latency
    EVENT_LANE_RTT_LEVEL,           // pos info lane rtt level
    EVENT_TRANS_TYPE,               // trans type
    EVENT_LOCAL_CAP,                // local dynamic capability
    EVENT_REMOTE_CAP,               // remote dynamic capability
    EVENT_ONLINE_STATE,             // online type
    EVENT_GUIDE_TYPE,               // lane guide type
    EVENT_GUIDE_RETRY,              // is lane guide retry
    EVENT_HML_REUSE,                // is HML retry
    EVENT_WIFI_DETECT_STATE,        // wifi detect state
    EVENT_DELAY_FREE,               // is delay free
    EVENT_32_BIT_BUTT,
} LaneEventType32Bit;

typedef enum {
    EVENT_LANE_ID = 0x0,            // lane id
    EVENT_BUILD_LINK_TIME,          // lane bulid link time
    EVENT_WIFI_DETECT_TIME,         // wifi detect time
    EVENT_FREE_LINK_TIME,           // lane free link time
    EVENT_64_BIT_BUTT,
} LaneEventType64Bit;

typedef enum {
    LANE_PROCESS_TYPE_UINT32 = 0x0,
    LANE_PROCESS_TYPE_UINT64,
    LANE_PROCESS_TYPE_BUTT,
} LaneProcessValueType; // indicates whether the type of the reported information is uint32_t or uint64_t

typedef enum {
    WIFI_DETECT_SUCC,           // wifi detect success
    WIFI_DETECT_FAIL,           // wifi detect fail
    WIFI_DETECT_BUTT,
} WifiDetectState;

typedef struct {
    ListNode node;
    uint32_t laneProcessList32Bit[EVENT_32_BIT_BUTT];
    uint64_t laneProcessList64Bit[EVENT_64_BIT_BUTT];
    char peerNetWorkId[NETWORK_ID_BUF_LEN];
} LaneProcess;

int32_t CreateLaneEventInfo(const LaneProcess *processInfo);
int32_t UpdateLaneEventInfo(uint32_t laneHandle, uint32_t eventType, LaneProcessValueType valueType, void *arg);
int32_t GetLaneEventInfo(uint32_t laneHandle, LaneProcess *laneProcess);
int32_t ReportLaneEventInfo(uint32_t laneHandle, int32_t result);
int32_t InitLaneEvent(void);
void DeinitLaneEvent(void);

#ifdef __cplusplus
}
#endif
#endif // LNN_LANE_DFX_H