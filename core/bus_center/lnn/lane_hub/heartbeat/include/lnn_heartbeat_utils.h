/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#ifndef LNN_HEARTBEAT_UTILS_H
#define LNN_HEARTBEAT_UTILS_H

#include <stdbool.h>
#include <stdint.h>

#include "softbus_common.h"

#ifdef __cplusplus
extern "C" {
#endif

#define HB_INVALID_TYPE_ID (-1)
#define HB_SHORT_UDID_HASH_LEN 8
#define HB_SHORT_UDID_HASH_HEX_LEN 16
#define HB_SHORT_ACCOUNT_HASH_LEN 2
#define HB_FSM_NAME_LEN 32

#define HB_TIME_FACTOR (1000LL)
#define HB_SEND_ONCE_LEN (10 * HB_TIME_FACTOR)
#define HB_SEND_RELAY_LEN (4 * HB_TIME_FACTOR)
#define HB_CHECK_DELAY_LEN HB_SEND_ONCE_LEN
#define HB_CHECK_OFFLINE_TOLERANCE_LEN HB_SEND_ONCE_LEN
#define HB_NOTIFY_DEV_LOST_DELAY_LEN (2 * HB_TIME_FACTOR + 2 * HB_SEND_ONCE_LEN)
#define HB_REMOVE_REPEAD_RECV_LEN HB_SEND_ONCE_LEN

#define HB_MAX_TYPE_COUNT 4

// heartbeat type
#define HEARTBEAT_TYPE_MIN              (0x1L)
#define HEARTBEAT_TYPE_UDP              HEARTBEAT_TYPE_MIN
#define HEARTBEAT_TYPE_BLE_V0           (0x1L << 1)
#define HEARTBEAT_TYPE_BLE_V1           (0x1L << 2)
#define HEARTBEAT_TYPE_TCP_FLUSH        (0x1L << 3)
#define HEARTBEAT_TYPE_MAX              (0x1L << 4)

typedef uint32_t LnnHeartbeatType;

typedef enum {
    STRATEGY_HB_SEND_SINGLE = 0,
    STRATEGY_HB_SEND_FIXED_PERIOD,
    STRATEGY_HB_SEND_ADJUSTABLE_PERIOD,
    STRATEGY_HB_RECV_SINGLE = 3,
    STRATEGY_HB_RECV_REMOVE_REPEAT,
} LnnHeartbeatStrategyType;

typedef enum {
    UPDATE_HB_INFO_MIN = 0,
    UPDATE_HB_ACCOUNT_INFO,
    UPDATE_HB_NETWORK_INFO,
    UPDATE_HB_MAX_INFO,
} LnnHeartbeatUpdateInfoType;

typedef bool (*VisitHbTypeCb)(LnnHeartbeatType *typeSet, LnnHeartbeatType eachType, void *data);
bool LnnVisitHbTypeSet(VisitHbTypeCb callback, LnnHeartbeatType *typeSet, void *data);

LnnHeartbeatType LnnConvertConnAddrTypeToHbType(ConnectionAddrType addrType);
ConnectionAddrType LnnConvertHbTypeToConnAddrType(LnnHeartbeatType type);
int32_t LnnConvertHbTypeToId(LnnHeartbeatType type);
bool LnnHasActiveConnection(const char *networkId, ConnectionAddrType addrType);
bool LnnCheckSupportedHbType(LnnHeartbeatType *srcType, LnnHeartbeatType *dstType);
int32_t LnnGenerateHexStringHash(const unsigned char *str, char *hashStr, uint32_t len);

#ifdef __cplusplus
}
#endif
#endif /* LNN_HEARTBEAT_UTILS_H */
