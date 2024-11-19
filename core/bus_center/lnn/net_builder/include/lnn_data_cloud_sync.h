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

#ifndef LNN_DATA_CLOUD_SYNC_H
#define LNN_DATA_CLOUD_SYNC_H

#include <stdint.h>

#include "lnn_node_info.h"
#include "softbus_adapter_crypto.h"
#include "softbus_adapter_timer.h"

#ifdef __cplusplus
extern "C" {
#endif

#define CLOUD_SYNC_INFO_SIZE 33

typedef struct {
    char networkId[NETWORK_ID_BUF_LEN];
    char deviceName[DEVICE_NAME_BUF_LEN];
    char unifiedName[DEVICE_NAME_BUF_LEN];
    char unifiedDefaultName[DEVICE_NAME_BUF_LEN];
    char nickName[DEVICE_NAME_BUF_LEN];
    char deviceUdid[UDID_BUF_LEN];
    char uuid[UUID_BUF_LEN];
    char softBusVersion[VERSION_MAX_LEN];
    char pkgVersion[VERSION_MAX_LEN];
    char macAddr[MAC_LEN];
    unsigned char cipherKey[SESSION_KEY_LENGTH];
    unsigned char cipherIv[BROADCAST_IV_LEN];
    unsigned char publicAddress[LFINDER_MAC_ADDR_LEN];
    char remotePtk[PTK_DEFAULT_LEN];
    char osVersion[OS_VERSION_BUF_LEN];
    bool isBleP2p;
    bool distributedSwitch;
    uint16_t deviceTypeId;
    uint32_t authCapacity;
    uint32_t heartbeatCapacity;
    int32_t osType;
    int32_t stateVersion;
    char *broadcastCipherKey;
    uint64_t supportedProtocols;
    int64_t wifiVersion;
    int64_t bleVersion;
    int64_t accountId;
    uint64_t feature;
    uint64_t connSubFeature;
    uint64_t timestamp;
} CloudSyncInfo;

typedef enum {
    DB_ADD = 0,
    DB_UPDATE = 1,
    DB_DELETE = 2,
    DB_CHANGE_TYPE_MAX,
} ChangeType;

void LnnInitCloudSyncModule(void);
void LnnDeInitCloudSyncModule(void);
int32_t LnnLedgerAllDataSyncToDB(NodeInfo *info);
int32_t LnnAsyncCallLedgerAllDataSyncToDB(NodeInfo *info);
int32_t LnnLedgerDataChangeSyncToDB(const char *key, const char *value, size_t valueLength);
int32_t LnnDeleteSyncToDB(void);
int32_t LnnDeleteDevInfoSyncToDB(const char *udid, int64_t accountId);
int32_t LnnDBDataChangeSyncToCache(const char *key, const char *value, ChangeType changeType);
int32_t LnnDBDataAddChangeSyncToCache(const char **key, const char **value, int32_t keySize);
int32_t LnnDBDataChangeSyncToCacheInner(const char *key, const char *value);
int32_t LnnSetCloudAbility(const bool isEnableCloud);
#ifdef __cplusplus
}
#endif

#endif // LNN_DATA_CLOUD_SYNC_H
