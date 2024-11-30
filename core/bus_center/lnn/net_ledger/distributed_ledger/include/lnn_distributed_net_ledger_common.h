/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef LNN_DISTRIBUTED_NET_LEDGER_COMMON_H
#define LNN_DISTRIBUTED_NET_LEDGER_COMMON_H

#include "lnn_distributed_net_ledger.h"
#include "lnn_map.h"

#ifdef __cplusplus
extern "C" {
#endif

#define TIME_THOUSANDS_FACTOR (1000)
#define BLE_ADV_LOST_TIME 5000
#define LONG_TO_STRING_MAX_LEN 21
#define LNN_COMMON_LEN_64 8
#define SOFTBUS_BUSCENTER_DUMP_REMOTEDEVICEINFO "remote_device_info"

#define AONYMIZE(log, key)                                                            \
    do {                                                                              \
        char *anonyKey = NULL;                                                        \
        Anonymize(key, &anonyKey);                                                    \
        LNN_LOGE(LNN_LEDGER, log, AnonymizeWrapper(anonyKey));                                          \
        AnonymizeFree(anonyKey);                                                      \
    } while (0)                                                                       \

#define GET_NODE(networkId, info)                                                     \
    do {                                                                              \
        (info) = LnnGetNodeInfoById((networkId), (CATEGORY_NETWORK_ID));              \
        if ((info) == NULL) {                                                         \
            AONYMIZE("get node info fail. networkId=%{public}s", networkId);          \
            return SOFTBUS_NETWORK_GET_NODE_INFO_ERR;                                 \
        }                                                                             \
    } while (0)                                                                       \

#define RETURN_IF_GET_NODE_VALID(networkId, buf, info)                                \
    do {                                                                              \
        if ((networkId) == NULL || (buf) == NULL) {                                   \
            LNN_LOGE(LNN_LEDGER, "networkId or buf is invalid");                      \
            return SOFTBUS_INVALID_PARAM;                                             \
        }                                                                             \
        GET_NODE(networkId, info);                                                    \
    } while (0)                                                                       \

#define CONNECTION_FREEZE_TIMEOUT_MILLIS (10 * 1000)

// softbus version for support initConnectFlag
#define SOFTBUS_VERSION_FOR_INITCONNECTFLAG "11.1.0.001"

typedef struct {
    Map udidMap;
    Map ipMap;
    Map macMap;
} DoubleHashMap;

typedef enum {
    DL_INIT_UNKNOWN = 0,
    DL_INIT_FAIL,
    DL_INIT_SUCCESS,
} DistributedLedgerStatus;

typedef struct {
    Map connectionCode;
} ConnectionCode;

typedef struct {
    int32_t countMax;
    DistributedLedgerStatus status;
    SoftBusMutex lock;
    ConnectionCode cnnCode;
    DoubleHashMap distributedInfo;
} DistributedNetLedger;

typedef struct {
    bool isOffline;
    bool oldWifiFlag;
    bool oldBrFlag;
    bool oldBleFlag;
    bool isChanged;
    bool isMigrateEvent;
    bool isNetworkChanged;
    bool newWifiFlag;
    bool newBleBrFlag;
} NodeInfoAbility;

NodeInfo *GetNodeInfoFromMap(const DoubleHashMap *map, const char *id);
bool IsMetaNode(NodeInfo *info);
DistributedNetLedger* LnnGetDistributedNetLedger(void);

#ifdef __cplusplus
}
#endif

#endif // LNN_DISTRIBUTED_NET_LEDGER_COMMON_H