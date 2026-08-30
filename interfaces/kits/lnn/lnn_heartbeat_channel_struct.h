/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#ifndef LNN_HEARTBEAT_CHANNEL_STRUCT_H
#define LNN_HEARTBEAT_CHANNEL_STRUCT_H

#include <stdint.h>
#include <stdbool.h>
#include "lnn_heartbeat_utils_struct.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifndef HB_MAX_CHANNEL_COUNT
#define HB_MAX_CHANNEL_COUNT 3
#endif

typedef enum {
    HEARTBEAT_CHANNEL_DEFAULT = 0,
    HEARTBEAT_CHANNEL_1,
    HEARTBEAT_CHANNEL_2,
    HEARTBEAT_CHANNEL_MAX = HB_MAX_CHANNEL_COUNT,
} LnnHeartbeatChannel;

typedef enum {
    HB_CHANNEL_STATE_DISABLED = 0,
    HB_CHANNEL_STATE_ENABLED,
    HB_CHANNEL_STATE_ACTIVE,
} LnnHeartbeatChannelState;

typedef struct {
    LnnHeartbeatChannel channel;
    LnnHeartbeatType supportTypes;
    uint16_t advMinInterval;
    uint16_t advMaxInterval;
    uint16_t scanInterval;
    uint16_t scanWindow;
    int8_t txPower;
    bool supportRelay;
    bool supportDirectOnline;
    int32_t userId;
} LnnHeartbeatChannelCapability;

typedef struct {
    LnnHeartbeatChannel channel;
    LnnHeartbeatChannelState state;
    LnnHeartbeatChannelCapability capability;
} LnnHeartbeatChannelInfo;

#ifdef __cplusplus
}
#endif
#endif /* LNN_HEARTBEAT_CHANNEL_STRUCT_H */