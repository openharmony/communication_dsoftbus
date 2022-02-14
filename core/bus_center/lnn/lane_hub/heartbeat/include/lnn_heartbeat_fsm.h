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

#ifndef LNN_HEARTBEAT_FSM_H
#define LNN_HEARTBEAT_FSM_H

#include "softbus_common.h"

#ifdef __cplusplus
extern "C" {
#endif

#define SHORT_UDID_HASH_LEN 8
#define SHORT_UDID_HASH_HEX_LEN 16
#define SHORT_USRID_HASH_HEX_LEN 4

typedef enum {
    STATE_NONE_BEAT_INDEX = 0,
    STATE_BEAT_NORMAL_NODE_INDEX,
    STATE_BEAT_MASTER_NODE_INDEX,
    STATE_BEAT_INDEX_MAX,
} LnnHeartbeatState;

typedef enum {
    EVENT_BEAT_ENTER = 0,
    EVENT_BEAT_START,
    EVENT_BEAT_ONCE_ENTER,
    EVENT_BEAT_DEVICE_LOST,
    EVENT_BEAT_AS_MASTER_NODE,
    EVENT_BEAT_AS_NORMAL_NODE = 5,
    EVENT_BEAT_MONITOR_DEV,
    EVENT_BEAT_REPEAT_CYCLE,
    EVENT_BEAT_ONCE_OUT,
    EVENT_BEAT_STOP,
    EVENT_BEAT_TIMEOUT = 10,
    EVENT_BEAT_EXIT,
    EVENT_BEAT_MAX,
} LnnHeartbeatEventType;

int32_t LnnPostMsgToBeatFsm(int32_t eventType, void *obj);
int32_t LnnPostDelayMsgToBeatFsm(int32_t eventType, void *obj, uint64_t delayMillis);
int32_t LnnRemoveBeatFsmMsg(int32_t eventType, uint64_t para, void *obj);

int32_t LnnHeartbeatRelayBeat(ConnectionAddrType type);
int32_t LnnHeartbeatMonitorDevInfo(ConnectionAddrType type, uint64_t delayMillis);
int32_t LnnHeartbeatAsNormalNode(void);
int32_t LnnHeartbeatNodeOffline(const char *networkId, ConnectionAddrType addrType, uint64_t delayMillis);

int32_t LnnHeartbeatFsmStart(int32_t beatStateIndex, uint64_t delayMillis);
int32_t LnnHeartbeatFsmStop(uint64_t delayMillis);

int32_t LnnHeartbeatFsmInit(void);
void LnnHeartbeatFsmDeinit(void);

#ifdef __cplusplus
}
#endif
#endif /* LNN_HEARTBEAT_FSM_H */
