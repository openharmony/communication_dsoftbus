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

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    char networkId[NETWORK_ID_BUF_LEN];
    char deviceName[DEVICE_NAME_BUF_LEN];
    char unifiedName[DEVICE_NAME_BUF_LEN];
    char unifiedDefaultName[DEVICE_NAME_BUF_LEN];
    char nickName[DEVICE_NAME_BUF_LEN];
    uint16_t deviceTypeId;
    char deviceUdid[UDID_BUF_LEN];
    char uuid[UUID_BUF_LEN];
    char softBusVersion[VERSION_MAX_LEN];
    bool isBleP2p;
    uint64_t supportedProtocols;
    char pkgVersion[VERSION_MAX_LEN];
    int64_t wifiVersion;
    int64_t bleVersion;
    char macAddr[MAC_LEN];
    int64_t accountId;
    uint64_t feature;
    uint64_t connSubFeature;
    uint32_t authCapacity;
    int32_t osType;
    char osVersion[OS_VERSION_BUF_LEN];
    int32_t stateVersion;
    char p2pMac[MAC_LEN];
    uint8_t peerIrk[LFINDER_IRK_LEN];
    unsigned char publicAddress[LFINDER_MAC_ADDR_LEN];
    char remotePtk[PTK_DEFAULT_LEN];
    char tableMain[BLE_BROADCAST_IV_LEN + 1];
    int64_t lifeTotal;
    uint64_t curBeginTime;
    uint8_t currentIndex;
    unsigned char cipherKey[SESSION_KEY_LENGTH];
    unsigned char cipherIv[BROADCAST_IV_LEN];
    bool distributedSwitch;
} CloudSyncInfo;

typedef enum {
    DB_ADD = 0,
    DB_UPDATE = 1,
    DB_DELETE = 2,
    DB_CHANGE_TYPE_MAX,
} ChangeType;

void LnnInitCloudSyncModule(void);
void LnnDeInitCloudSyncModule(void);
int32_t LnnLedgerAllDataSyncToDB(const NodeInfo *info);
int32_t LnnLedgerDataChangeSyncToDB(const char *key, const char *value, size_t valueLength);
int32_t LnnDeleteSyncToDB(void);
int32_t LnnDBDataChangeSyncToCache(const char *key, const char *value, ChangeType changeType);
int32_t LnnDBDataAddChangeSyncToCache(const char **key, const char **value, int32_t keySize);
int32_t LnnGetAccountIdFromLocalCache(int64_t *buf);
#ifdef __cplusplus
}
#endif

#endif // LNN_DATA_CLOUD_SYNC_H
