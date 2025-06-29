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

#ifndef LNN_HEARTBETA_MEDIUM_MGR_STRUCT_H
#define LNN_HEARTBETA_MEDIUM_MGR_STRUCT_H

#include <stdint.h>
#include <stdbool.h>

#include "lnn_heartbeat_utils_struct.h"
#include "softbus_common.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    /** Heartbeat media type. For details, see {@link LnnHeartbeatType}. */
    LnnHeartbeatType type;
    union {
        /** Defines parameters of ble heartbeat. */
        struct BleParam {
            /** minimum time between the start of two consecutive advertising events. */
            uint16_t advMinInterval;
            /** maximum time between the start of two consecutive advertising events. */
            uint16_t advMaxInterval;
            /** Interval between the start of two consecutive scan windows. */
            uint16_t scanInterval;
            /** The duration in which the link layer scans on one channel. */
            uint16_t scanWindow;
        } ble;
    } info;
} LnnHeartbeatMediumParam;

typedef struct {
    int32_t weight;
    int32_t localMasterWeight;
} LnnHeartbeatWeight;

typedef struct {
    void (*onRelay)(const char *udidHash, ConnectionAddrType type, LnnHeartbeatType hbType);
    int32_t (*onReceive)(DeviceInfo *device, const LnnHeartbeatWeight *mediumWeight, LnnHeartbeatType hbType,
        bool isOnlineDirectly, HbRespData *hbResp);
    int32_t (*onRecvHigherWeight)(const char *udidHash, int32_t weight, ConnectionAddrType type, bool isReElect,
        bool isPeerScreenOn);
    void (*onRecvLpInfo)(const char *networkId, uint64_t nowTime);
    void (*onRecvSleInfo)(const char *networkId, SleDeviceInfo *info);
} LnnHeartbeatMediumMgrCb;

typedef struct {
    LnnHeartbeatType hbType;
    bool wakeupFlag;
    bool isRelay;
    bool isSyncData;
    bool isFirstBegin;
    bool isNeedRestart;
    bool hasScanRsp;
    bool isFast;
    bool isDirectBoardcast;
    bool isMsdpRange;
    char networkId[NETWORK_ID_BUF_LEN];
} LnnHeartbeatSendBeginData;

typedef struct {
    LnnHeartbeatType hbType;
    bool wakeupFlag;
    bool isRelay;
    bool isLastEnd;
    bool isMsdpRange;
} LnnHeartbeatSendEndData;

typedef struct {
    LnnHeartbeatType supportType;
    int32_t (*init)(const LnnHeartbeatMediumMgrCb *callback);
    int32_t (*onSendOneHbBegin)(const LnnHeartbeatSendBeginData *custData);
    int32_t (*onSendOneHbEnd)(const LnnHeartbeatSendEndData *custData);
    int32_t (*onSetMediumParam)(const LnnHeartbeatMediumParam *param);
    int32_t (*onUpdateSendInfo)(LnnHeartbeatUpdateInfoType type);
    int32_t (*onStopHbByType)(void);
    void (*deinit)(void);
} LnnHeartbeatMediumMgr;

#ifdef __cplusplus
}
#endif
#endif /*LNN_HEARTBETA_MEDIUM_MGR_STRUCT_H */