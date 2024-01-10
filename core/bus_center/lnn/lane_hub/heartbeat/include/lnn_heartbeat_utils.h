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
#define HB_START_DELAY_LEN (10 * HB_TIME_FACTOR)
#define HB_SEND_ONCE_LEN (10 * HB_TIME_FACTOR)
#define HB_SEND_RELAY_LEN (2 * HB_TIME_FACTOR)
#define HB_CHECK_DELAY_LEN HB_SEND_ONCE_LEN
#define HB_CHECK_OFFLINE_TOLERANCE_LEN HB_SEND_ONCE_LEN
#define HB_NOTIFY_DEV_LOST_DELAY_LEN (2 * HB_TIME_FACTOR + 2 * HB_SEND_ONCE_LEN)
#define HB_REPEAD_RECV_THRESHOLD (1 * HB_TIME_FACTOR)
#define HB_REPEAD_JOIN_LNN_THRESHOLD (2 * HB_TIME_FACTOR)
#define HB_OFFLINE_TIME (5 * 60 * HB_TIME_FACTOR + 2 * HB_SEND_ONCE_LEN)
#define HB_SCREEN_ON_COAP_TIME (3 * HB_TIME_FACTOR)
#define HB_RESTART_LEN (3 * HB_TIME_FACTOR)
#define HB_PERIOD_DUMP_LOCAL_INFO_LEN (5 * 60 * HB_TIME_FACTOR)
#define HB_OFFLINE_PERIOD 2

#define HB_SEND_EACH_SEPARATELY_LEN (2 * HB_TIME_FACTOR) // Split and send a single heartbeat
#define HB_SEND_SEPARATELY_CNT (HB_SEND_ONCE_LEN / HB_SEND_EACH_SEPARATELY_LEN)

#define HB_MAX_TYPE_COUNT 5

// heartbeat type
#define HEARTBEAT_TYPE_MIN              (0x1L)
#define HEARTBEAT_TYPE_UDP              HEARTBEAT_TYPE_MIN
#define HEARTBEAT_TYPE_BLE_V0           (0x1L << 1)
#define HEARTBEAT_TYPE_BLE_V1           (0x1L << 2)
#define HEARTBEAT_TYPE_TCP_FLUSH        (0x1L << 3)
#define HEARTBEAT_TYPE_BLE_V3           (0x1L << 4)
#define HEARTBEAT_TYPE_MAX              (0x1L << 5)

#define NORMAL_STRATEGY 1
#define HIGH_PERFORMANCE_STRATEGY 2
#define ONCE_STRATEGY 3
#define SUSPEND_STRATEGY 4
#define LOW_CONTINUOUS_ADVERTISE 7
#define ADJUST_INTERVAL_STRATEGY 8
#define REQUEST_DISABLE_BLE_DISCOVERY 100
#define REQUEST_ENABLE_BLE_DISCOVERY  101

#define MIN_DISABLE_BLE_DISCOVERY_TIME 1000
#define MAX_DISABLE_BLE_DISCOVERY_TIME 15000

#define BT_ADDR_LEN 6
#define BT_MAC_HASH_LEN 8
#define BT_MAC_HASH_STR_LEN 17

#define CHECK_TRUSTED_RELATION_TIME 5000

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
    UPDATE_SCREEN_STATE_INFO,
    UPDATE_BT_STATE_OPEN_INFO,
    UPDATE_BT_STATE_CLOSE_INFO,
    UPDATE_HB_MAX_INFO,
} LnnHeartbeatUpdateInfoType;

typedef struct {
    uint8_t capabiltiy;
    int16_t stateVersion;
} HbRespData;
#define STATE_VERSION_INVALID (-1)
#define ENABLE_COC_CAP (1 << 0)
#define P2P_GO (1 << 1)
#define P2P_GC (1 << 2)
#define ENABLE_WIFI_CAP (1 << 3)

typedef bool (*VisitHbTypeCb)(LnnHeartbeatType *typeSet, LnnHeartbeatType eachType, void *data);
bool LnnVisitHbTypeSet(VisitHbTypeCb callback, LnnHeartbeatType *typeSet, void *data);

LnnHeartbeatType LnnConvertConnAddrTypeToHbType(ConnectionAddrType addrType);
ConnectionAddrType LnnConvertHbTypeToConnAddrType(LnnHeartbeatType type);
int32_t LnnConvertHbTypeToId(LnnHeartbeatType type);
bool LnnHasActiveConnection(const char *networkId, ConnectionAddrType addrType);
bool LnnCheckSupportedHbType(LnnHeartbeatType *srcType, LnnHeartbeatType *dstType);
int32_t LnnGetShortAccountHash(uint8_t *accountHash, uint32_t len);
int32_t LnnGenerateHexStringHash(const unsigned char *str, char *hashStr, uint32_t len);
int32_t LnnGenerateBtMacHash(const char *btMac, int32_t brMacLen, char *brMacHash, int32_t hashLen);
bool LnnIsSupportBurstFeature(const char *networkId);
void LnnDumpLocalBasicInfo(void);

#ifdef __cplusplus
}
#endif
#endif /* LNN_HEARTBEAT_UTILS_H */
