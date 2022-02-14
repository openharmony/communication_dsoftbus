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

#ifndef LNN_HEARTBEAT_STRATEGY_H
#define LNN_HEARTBEAT_STRATEGY_H

#include <stdbool.h>
#include "softbus_common.h"
#include "lnn_heartbeat_manager.h"

#ifdef __cplusplus
extern "C" {
#endif

#define HEARTBEAT_TIME_FACTOR (1000LL)
#define HEARTBEAT_ENABLE_DELAY_LEN (20 * HEARTBEAT_TIME_FACTOR)
#define HEARTBEAT_TOCK_TIME_LEN (10 * HEARTBEAT_TIME_FACTOR)
#define HEARTBEAT_MONITOR_DELAY_LEN (10 * HEARTBEAT_TIME_FACTOR + HEARTBEAT_TOCK_TIME_LEN)
#define HEARTBEAT_MANAGER_TIMEOUT_LEN (5 * HEARTBEAT_TIME_FACTOR + HEARTBEAT_TOCK_TIME_LEN)
#define HEARTBEAT_UPDATE_TIME_PRECISION (HEARTBEAT_ENABLE_DELAY_LEN - HEARTBEAT_TOCK_TIME_LEN)

typedef enum {
    /**< Heartbeat cycle ( in sec ). */
    HIGH_FREQ_CYCLE = 30,
    MID_FREQ_CYCLE = 60,
    LOW_FREQ_CYCLE = 5 * 60,
} ModeCycle;

typedef enum {
    /**< Heartbeat keep alive duration ( in sec ). */
    DEFAULT_DURATION = 60,
    NORMAL_DURATION = 10 * 60,
    LONG_DURATION = 30 * 60,
} ModeDuration;

typedef struct {
    ModeCycle modeCycle;
    ModeDuration modeDuration;
    bool wakeupFlag;
} GearMode;

typedef struct {
    LnnHeartbeatImplType type;
    union {
        struct BleParam {
            uint16_t advMinInterval;
            uint16_t advMaxInterval;
            uint16_t scanInterval;
            uint16_t scanWindow;
        } ble;
    } info;
} HeartbeatImplPolicy;

typedef struct {
    HeartbeatImplPolicy *implPolicy;
} HeartbeatPolicy;

int32_t ShiftLNNGear(const char *pkgName, int32_t callingUid, const char *targetNetworkId,
    GearMode mode, const HeartbeatImplPolicy *implPolicy);

int32_t LnnGetHeartbeatGearMode(GearMode *mode);
int32_t LnnGetHeartbeatImplPolicy(LnnHeartbeatImplType type, HeartbeatImplPolicy *implPolicy);
int32_t LnnOfflineTimingByHeartbeat(const char *networkId, ConnectionAddrType addrType);
int32_t LnnNotifyMasterNodeChanged(const char *masterUdid, int32_t weight);

int32_t LnnStartHeartbeatDelay(void);
void LnnStopHeartbeat(void);

int32_t LnnInitHeartbeat(void);
void LnnDeinitHeartbeat(void);

#ifdef __cplusplus
}
#endif
#endif /* LNN_HEARTBEAT_STRATEGY_H */