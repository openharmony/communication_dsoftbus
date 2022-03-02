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
    STATE_HB_UNINIT_INDEX = -1,
    STATE_HB_NONE_INDEX = 0,
    STATE_HB_NORMAL_NODE_INDEX,
    STATE_HB_MASTER_NODE_INDEX,
    STATE_HB_INDEX_MAX,
} LnnHeartbeatState;

typedef enum {
    EVENT_HB_ENTER = 0,
    EVENT_HB_START,
    EVENT_HB_ONCE_BEGIN,
    EVENT_HB_DEVICE_LOST,
    EVENT_HB_AS_MASTER_NODE,
    EVENT_HB_AS_NORMAL_NODE = 5,
    EVENT_HB_CHECK_DEV,
    EVENT_HB_REPEAT_CYCLE,
    EVENT_HB_ONCE_END,
    EVENT_HB_STOP,
    EVENT_HB_TIMEOUT = 10,
    EVENT_HB_EXIT,
    EVENT_HB_MAX,
} LnnHeartbeatEventType;

int32_t LnnPostMsgToHbFsm(int32_t eventType, void *obj);
int32_t LnnPostDelayMsgToHbFsm(int32_t eventType, void *obj, uint64_t delayMillis);
int32_t LnnRemoveHbFsmMsg(int32_t eventType, uint64_t para, void *obj);

int32_t LnnHbRelayToMaster(ConnectionAddrType type);
int32_t LnnHbCheckDevStatus(ConnectionAddrType type, uint64_t delayMillis);
int32_t LnnHbAsNormalNode(void);
int32_t LnnHbProcessDeviceLost(const char *networkId, ConnectionAddrType addrType, uint64_t delayMillis);

int32_t LnnHbFsmStart(int32_t stateIndex, uint64_t delayMillis);
int32_t LnnHbFsmStop(uint64_t delayMillis);

int32_t LnnHbFsmInit(void);
void LnnHbFsmDeinit(void);

#ifdef __cplusplus
}
#endif
#endif /* LNN_HEARTBEAT_FSM_H */
