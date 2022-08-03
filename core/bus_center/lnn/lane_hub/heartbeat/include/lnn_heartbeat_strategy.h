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

#include "lnn_heartbeat_manager.h"
#include "softbus_common.h"

#ifdef __cplusplus
extern "C" {
#endif

#define HB_TIME_FACTOR (1000LL)
#define HB_ONE_CYCLE_LEN (10 * HB_TIME_FACTOR)
#define HB_ONE_CYCLE_TIMEOUT_LEN (5 * HB_TIME_FACTOR + HB_ONE_CYCLE_LEN)
#define HB_CHECK_DELAY_LEN (10 * HB_TIME_FACTOR + HB_ONE_CYCLE_LEN)
#define HB_ENABLE_DELAY_LEN (20 * HB_TIME_FACTOR)
#define HB_UPDATE_INTERVAL_LEN (HB_ENABLE_DELAY_LEN - HB_ONE_CYCLE_LEN)
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

int32_t LnnGetHeartbeatGearMode(GearMode *mode);
int32_t LnnGetHeartbeatImplPolicy(LnnHeartbeatImplType type, HeartbeatImplPolicy *implPolicy);
int32_t LnnOfflineTimingByHeartbeat(const char *networkId, ConnectionAddrType addrType);
int32_t LnnShiftLNNGear(const char *pkgName, const char *callerId, const char *targetNetworkId, const GearMode *mode);

int32_t LnnStartHeartbeatDelay(void);
void LnnStopHeartbeatNow(void);

int32_t LnnInitHeartbeat(void);
void LnnDeinitHeartbeat(void);

#ifdef __cplusplus
}
#endif
#endif /* LNN_HEARTBEAT_STRATEGY_H */