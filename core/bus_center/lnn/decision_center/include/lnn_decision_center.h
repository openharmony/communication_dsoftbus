/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef LNN_DECISION_CENTER_H
#define LNN_DECISION_CENTER_H

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    STATE_TYPE_BLE_SWITCH_ON = 0,
    STATE_TYPE_BLE_SWITCH_OFF,
    STATE_TYPE_BLE_DISCOVERY,
    STATE_TYPE_AR_MOVE_RIDING,
    STATE_TYPE_AR_MOVE_RUN_FAST,
    STATE_TYPE_AR_CLIMBING_MOUNT,
    STATE_TYPE_AR_MOVE_RUN_FOR_HEALTH,
    STATE_TYPE_AR_MOVE_WALK_FOR_HEALTH,
    STATE_TYPE_AR_MOVE_VEHICLE,
    STATE_TYPE_AR_MOVE_VE_TRAIN,
    STATE_TYPE_AR_MOVE_VE_UNKNOWN,
    STATE_TYPE_AR_MOVE_STATIONARY,
    STATE_TYPE_AR_VE_BUS,
    STATE_TYPE_AR_VE_CAR,
    STATE_TYPE_AR_VE_METRO,
    STATE_TYPE_AR_VE_HIGH_SPEED_RAIL,
    STATE_TYPE_AR_VE_AUTO,
    STATE_TYPE_AR_VE_RAIL,
    STATE_TYPE_AR_MOVE_ON_FOOT,
    STATE_TYPE_AR_MOVE_ELEVATOR,
    STATE_TYPE_AR_MOVE_DRIVER,
    STATE_TYPE_AR_FAST_WALK,
    STATE_TYPE_AR_STOP_VEHICLE,
    STATE_TYPE_AR_MOVE_WALK_SLOW,
    STATE_TYPE_AR_MOVE_TILT,
    STATE_TYPE_AR_MOVE_END,
    STATE_TYPE_AR_MOVE_IN_OUT_DOOR,
    STATE_TYPE_MOTION_SHAKE,
    STATE_TYPE_MOTION_TAP,
    STATE_TYPE_MOTION_TILT_LR,
    STATE_TYPE_MOTION_ROTATION,
    STATE_TYPE_MOTION_TAKE_OFF,
    STATE_TYPE_MOTION_HEAD_DOWN,
    STATE_TYPE_MOTION_PUT_DOWN,
    STATE_TYPE_MOTION_SIDE_GRIP,
    STATE_TYPE_MOTION_MOVE,
    STATE_TYPE_MAX_NUM,
} StatePacks;

typedef enum {
    DC_VERSION_1_0 = 0,
    DC_VERSION_MAX_NUM,
} DecisionCenterVersion;

typedef enum {
    DC_TARGET_ENERGY = 0x0001,
    DC_TARGET_EFFICIENCY = 0x0010,
    DC_TARGET_LATENCY = 0x0100,
    DC_TARGET_ROBUSTNESS = 0x1000
} DcTargetType;

typedef enum {
    TASK_BLE_HEARTBEAT = 0,
    TASK_BLE_LOW_LATENCY = 1,
    TASK_NUM,
} SupportTaskType;

typedef enum {
    TASK_CONVEX_SYSTEM = 0,
    TASK_RULE_SYSTEM = 1,
    TASK_ML_SYSTEM = 2,
    TASK_LOGIC_SYSTEM = 3,
    TASK_SYSTEM_NUM,
} DcSupportTaskSystem;

typedef struct {
    int32_t serviceUuid;
    uint8_t taskId;
    uint8_t taskType;
    uint8_t target;
    uint8_t preferredSystem;
    uint8_t limitType;
    int32_t limitValue; // Unit: Milliseconds/Times/None
    int32_t (*optimizeStrategy)(void *);
} DcTask;

typedef struct {
    int64_t timestamp;
    int32_t stateType;
    int32_t stateValue;
} DcEvent;

typedef enum {
    DC_LIMIT_PERSISTENT = 0,
    DC_LIMIT_TIMES = 1,
    DC_LIMIT_DURATION = 2,
    DC_LIMIT_NUM
} DcLimitType;

typedef struct {
    uint32_t type;
    union {
        struct DcBleParam {
            uint16_t advMinInterval;
            uint16_t advMaxInterval;
            uint16_t scanInterval;
            uint16_t scanWindow;
        } ble;
    } info;
    struct HeartbeatImplPolicy *next;
} BleHeartbeatConfig;

int32_t LnnInitDecisionCenter(uint32_t version);
void LnnDeinitDecisionCenter(void);
int32_t LnnDcSubscribe(DcTask *task);
int32_t LnnDcUnsubscribe(DcTask *task);
void LnnDcDispatchEvent(DcEvent *dcEvnet);

#ifdef __cplusplus
}
#endif
#endif
