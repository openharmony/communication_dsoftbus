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

#include "lnn_data_cloud_sync.h"

#include <securec.h>
#include "stdlib.h"

#include "anonymizer.h"
#include "lnn_cipherkey_manager.h"
#include "lnn_device_info_recovery.h"
#include "lnn_distributed_net_ledger.h"
#include "lnn_heartbeat_utils.h"
#include "lnn_kv_adapter_wrapper.h"
#include "lnn_link_finder.h"
#include "lnn_log.h"
#include "lnn_node_info.h"
#include "lnn_map.h"
#include "lnn_p2p_info.h"
#include "softbus_adapter_thread.h"
#include "softbus_errcode.h"
#include "softbus_json_utils.h"
#include "softbus_utils.h"
#include "softbus_adapter_mem.h"

#define APPID "dsoftbus"
#define STOREID "dsoftbus_kv_db"

#define FIELDNAME_MAX_LEN 32
#define KEY_MAX_LEN 128
#define SPLIT_MAX_LEN 128
#define SPLIT_KEY_NUM 3
#define SPLIT_VALUE_NUM 2
#define PUT_VALUE_MAX_LEN 136
#define UDID_HASH_HEX_LEN 16
static int32_t g_dbId = 0;

static SoftBusMutex g_cloudSyncMutex;

static int32_t ConvertNameInfoInternal(CloudSyncInfo *cloudSyncInfo, const NodeInfo *nodeInfo)
{
    cloudSyncInfo->accountId = nodeInfo->accountId;
    if (strcpy_s(cloudSyncInfo->deviceName, DEVICE_NAME_BUF_LEN, nodeInfo->deviceInfo.deviceName) != EOK) {
        LNN_LOGE(LNN_BUILDER, "fail:strcpy_s devicename fail");
        return SOFTBUS_MEM_ERR;
    }
    if (strcpy_s(cloudSyncInfo->unifiedName, DEVICE_NAME_BUF_LEN, nodeInfo->deviceInfo.unifiedName) != EOK) {
        LNN_LOGE(LNN_BUILDER, "fail:strcpy_s unifiedname fail");
        return SOFTBUS_MEM_ERR;
    }
    if (strcpy_s(cloudSyncInfo->unifiedDefaultName, DEVICE_NAME_BUF_LEN, nodeInfo->deviceInfo.unifiedDefaultName) !=
        EOK) {
        LNN_LOGE(LNN_BUILDER, "fail:strcpy_s unifieddefaultname fail");
        return SOFTBUS_MEM_ERR;
    }
    if (strcpy_s(cloudSyncInfo->nickName, DEVICE_NAME_BUF_LEN, nodeInfo->deviceInfo.nickName) != EOK) {
        LNN_LOGE(LNN_BUILDER, "fail:strcpy_s nickname fail");
        return SOFTBUS_MEM_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t ConvertVersionInfoInternal(CloudSyncInfo *cloudSyncInfo, const NodeInfo *nodeInfo)
{
    if (strcpy_s(cloudSyncInfo->softBusVersion, VERSION_MAX_LEN, nodeInfo->softBusVersion) != EOK) {
        LNN_LOGE(LNN_BUILDER, "fail:strcpy_s softbusversion fail");
        return SOFTBUS_MEM_ERR;
    }
    if (strcpy_s(cloudSyncInfo->pkgVersion, VERSION_MAX_LEN, nodeInfo->pkgVersion) != EOK) {
        LNN_LOGE(LNN_BUILDER, "fail:strcpy_s pkgversion fail");
        return SOFTBUS_MEM_ERR;
    }
    if (strcpy_s(cloudSyncInfo->osVersion, OS_VERSION_BUF_LEN, nodeInfo->deviceInfo.osVersion) != EOK) {
        LNN_LOGE(LNN_BUILDER, "fail:strcpy_s osversion fail");
        return SOFTBUS_MEM_ERR;
    }
    cloudSyncInfo->wifiVersion = nodeInfo->wifiVersion;
    cloudSyncInfo->bleVersion = nodeInfo->bleVersion;
    cloudSyncInfo->osType = nodeInfo->deviceInfo.osType;
    cloudSyncInfo->stateVersion = nodeInfo->stateVersion;
    return SOFTBUS_OK;
}

static int32_t ConvertDevIdInfoInternal(CloudSyncInfo *cloudSyncInfo, const NodeInfo *nodeInfo)
{
    if (strcpy_s(cloudSyncInfo->networkId, NETWORK_ID_BUF_LEN, nodeInfo->networkId) != EOK) {
        LNN_LOGE(LNN_BUILDER, "fail:strcpy_s networkid fail");
        return SOFTBUS_MEM_ERR;
    }
    cloudSyncInfo->deviceTypeId = nodeInfo->deviceInfo.deviceTypeId;
    if (strcpy_s(cloudSyncInfo->deviceUdid, UDID_BUF_LEN, nodeInfo->deviceInfo.deviceUdid) != EOK) {
        LNN_LOGE(LNN_BUILDER, "fail:strcpy_s deviceudid fail");
        return SOFTBUS_MEM_ERR;
    }
    if (strcpy_s(cloudSyncInfo->uuid, UUID_BUF_LEN, nodeInfo->uuid) != EOK) {
        LNN_LOGE(LNN_BUILDER, "fail:strcpy_s uuid fail");
        return SOFTBUS_MEM_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t ConvertCipherInfoInternal(CloudSyncInfo *cloudSyncInfo, const NodeInfo *nodeInfo)
{
    if (memcpy_s(cloudSyncInfo->cipherKey, SESSION_KEY_LENGTH, nodeInfo->cipherInfo.key, SESSION_KEY_LENGTH) != EOK) {
        LNN_LOGE(LNN_BUILDER, "fail:memcpy_s cipherkey fail");
        return SOFTBUS_MEM_ERR;
    }
    if (memcpy_s(cloudSyncInfo->cipherIv, BROADCAST_IV_LEN, nodeInfo->cipherInfo.iv, BROADCAST_IV_LEN) != EOK) {
        LNN_LOGE(LNN_BUILDER, "fail:memcpy_s cipheriv fail");
        return SOFTBUS_MEM_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t ConvertAbilityInfoInternal(CloudSyncInfo *cloudSyncInfo, const NodeInfo *nodeInfo)
{
    cloudSyncInfo->isBleP2p = nodeInfo->isBleP2p;
    cloudSyncInfo->supportedProtocols = nodeInfo->supportedProtocols;
    cloudSyncInfo->feature = nodeInfo->feature;
    cloudSyncInfo->connSubFeature = nodeInfo->connSubFeature;
    cloudSyncInfo->authCapacity = nodeInfo->authCapacity;
    return SOFTBUS_OK;
}

static int32_t ConvertAddressInfoInternal(CloudSyncInfo *cloudSyncInfo, const NodeInfo *nodeInfo)
{
    if (strcpy_s(cloudSyncInfo->macAddr, MAC_LEN, nodeInfo->connectInfo.macAddr) != EOK) {
        LNN_LOGE(LNN_BUILDER, "fail:strcpy_s macaddr fail");
        return SOFTBUS_MEM_ERR;
    }
    if (strcpy_s(cloudSyncInfo->p2pMac, MAC_LEN, nodeInfo->p2pInfo.p2pMac) != EOK) {
        LNN_LOGE(LNN_BUILDER, "fail:strcpy_s p2pmac fail");
        return SOFTBUS_MEM_ERR;
    }
    if (memcpy_s((char *)cloudSyncInfo->peerIrk, LFINDER_IRK_LEN, (char *)nodeInfo->rpaInfo.peerIrk, LFINDER_IRK_LEN) !=
        EOK) {
        LNN_LOGE(LNN_BUILDER, "fail:memcpy_s peerirk fail");
        return SOFTBUS_MEM_ERR;
    }
    if (memcpy_s((char *)cloudSyncInfo->publicAddress, LFINDER_MAC_ADDR_LEN, (char *)nodeInfo->rpaInfo.publicAddress,
        LFINDER_MAC_ADDR_LEN) != EOK) {
        LNN_LOGE(LNN_BUILDER, "fail:memcpy_s publicaddress fail");
        return SOFTBUS_MEM_ERR;
    }
    if (strcpy_s(cloudSyncInfo->remotePtk, PTK_DEFAULT_LEN, nodeInfo->remotePtk) != EOK) {
        LNN_LOGE(LNN_BUILDER, "fail:strcpy_s remoteptk fail");
        return SOFTBUS_MEM_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t ConvertNodeInfoToCloudSyncInfo(CloudSyncInfo *cloudSyncInfo, const NodeInfo *nodeInfo)
{
    if (cloudSyncInfo == NULL || nodeInfo == NULL) {
        LNN_LOGE(LNN_BUILDER, "fail:invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    if (ConvertNameInfoInternal(cloudSyncInfo, nodeInfo) != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "fail:strcpy_s name info fail");
        return SOFTBUS_MEM_ERR;
    }
    if (ConvertVersionInfoInternal(cloudSyncInfo, nodeInfo) != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "fail:strcpy_s version info fail");
        return SOFTBUS_MEM_ERR;
    }
    if (ConvertDevIdInfoInternal(cloudSyncInfo, nodeInfo) != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "fail:strcpy_s devid info fail");
        return SOFTBUS_MEM_ERR;
    }
    if (ConvertAbilityInfoInternal(cloudSyncInfo, nodeInfo) != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "fail:strcpy_s alibity info fail");
        return SOFTBUS_MEM_ERR;
    }
    if (ConvertAddressInfoInternal(cloudSyncInfo, nodeInfo) != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "fail:strcpy_s address info fail");
        return SOFTBUS_MEM_ERR;
    }
    if (ConvertCipherInfoInternal(cloudSyncInfo, nodeInfo) != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "fail:strcpy_s cipher info fail");
        return SOFTBUS_MEM_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t DBCipherInfoSyncToCache(NodeInfo *cacheInfo, char *fieldName, const char *value, size_t valueLength)
{
    LNN_LOGI(LNN_BUILDER, "DBCipherInfoSyncToCache enter.");
    if (cacheInfo == NULL || fieldName == NULL || value == NULL) {
        LNN_LOGE(LNN_BUILDER, "fail:invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    if (strcmp(fieldName, DEVICE_INFO_BROADCAST_CIPHER_KEY) == 0 && valueLength < SESSION_KEY_LENGTH) {
        if (strcpy_s((char *)cacheInfo->cipherInfo.key, SESSION_KEY_LENGTH, value) != EOK) {
            LNN_LOGE(LNN_BUILDER, "fail:strcpy_s cipherkey fail");
            return SOFTBUS_MEM_ERR;
        }
    } else if (strcmp(fieldName, DEVICE_INFO_BROADCAST_CIPHER_IV) == 0 && valueLength < BROADCAST_IV_LEN) {
        if (strcpy_s((char *)cacheInfo->cipherInfo.iv, BROADCAST_IV_LEN, value) != EOK) {
            LNN_LOGE(LNN_BUILDER, "fail:strcpy_s cipheriv fail");
            return SOFTBUS_MEM_ERR;
        }
    } else if (strcmp(fieldName, DEVICE_INFO_JSON_KEY_TABLE_MIAN) == 0 && valueLength < BLE_BROADCAST_IV_LEN + 1) {
        LNN_LOGI(LNN_BUILDER, "cipher table mian info no need update into nodeinfo");
    } else if (strcmp(fieldName, DEVICE_INFO_JSON_KEY_TOTAL_LIFE) == 0) {
        LNN_LOGI(LNN_BUILDER, "cipher total life info no need update into nodeinfo");
    } else if (strcmp(fieldName, DEVICE_INFO_JSON_KEY_TIMESTAMP_BEGIN) == 0) {
        LNN_LOGI(LNN_BUILDER, "cipher timestamp begin info no need update into nodeinfo");
    } else if (strcmp(fieldName, DEVICE_INFO_JSON_KEY_CURRENT_INDEX) == 0) {
        LNN_LOGI(LNN_BUILDER, "cipher current index info no need update into nodeinfo");
    } else if (strcmp(fieldName, DEVICE_INFO_DISTRIBUTED_SWITCH) == 0) {
        LNN_LOGI(LNN_BUILDER, "distributed switch info no need update into nodeinfo");
    } else {
        LNN_LOGE(LNN_BUILDER, "fail:invalid fieldname or cipher info valuelength over range");
        return SOFTBUS_MEM_ERR;
    }
    LNN_LOGI(LNN_BUILDER, "DBCipherInfoSyncToCache success.");
    return SOFTBUS_OK;
}

static int32_t DBDeviceBasicInfoSyncToCache(NodeInfo *cacheInfo, char *fieldName, const char *value, size_t valueLength)
{
    LNN_LOGI(LNN_BUILDER, "DBDeviceBasicInfoSyncToCache enter.");
    if (cacheInfo == NULL || fieldName == NULL || value == NULL) {
        LNN_LOGE(LNN_BUILDER, "fail:invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    if (strcmp(fieldName, DEVICE_INFO_DEVICE_NAME) == 0 && valueLength < DEVICE_NAME_BUF_LEN) {
        if (strcpy_s(cacheInfo->deviceInfo.deviceName, DEVICE_NAME_BUF_LEN, value) != EOK) {
            LNN_LOGE(LNN_BUILDER, "fail:strcpy_s devicename fail");
            return SOFTBUS_MEM_ERR;
        }
    } else if (strcmp(fieldName, DEVICE_INFO_UNIFIED_DEVICE_NAME) == 0 && valueLength < DEVICE_NAME_BUF_LEN) {
        if (strcpy_s(cacheInfo->deviceInfo.unifiedName, DEVICE_NAME_BUF_LEN, value) != EOK) {
            LNN_LOGE(LNN_BUILDER, "fail:strcpy_s unifiedname fail");
            return SOFTBUS_MEM_ERR;
        }
    } else if (strcmp(fieldName, DEVICE_INFO_UNIFIED_DEFAULT_DEVICE_NAME) == 0 && valueLength < DEVICE_NAME_BUF_LEN) {
        if (strcpy_s(cacheInfo->deviceInfo.unifiedDefaultName, DEVICE_NAME_BUF_LEN, value) != EOK) {
            LNN_LOGE(LNN_BUILDER, "fail:strcpy_s unifieddefaultname fail");
            return SOFTBUS_MEM_ERR;
        }
    } else if (strcmp(fieldName, DEVICE_INFO_SETTINGS_NICK_NAME) == 0 && valueLength < DEVICE_NAME_BUF_LEN) {
        if (strcpy_s(cacheInfo->deviceInfo.nickName, DEVICE_NAME_BUF_LEN, value) != EOK) {
            LNN_LOGE(LNN_BUILDER, "fail:strcpy_s nickname fail");
            return SOFTBUS_MEM_ERR;
        }
    } else if (strcmp(fieldName, DEVICE_INFO_DEVICE_UDID) == 0 && valueLength < UDID_BUF_LEN) {
        if (strcpy_s(cacheInfo->deviceInfo.deviceUdid, UDID_BUF_LEN, value) != EOK) {
            LNN_LOGE(LNN_BUILDER, "fail:strcpy_s deviceUdid fail");
            return SOFTBUS_MEM_ERR;
        }
    } else if (strcmp(fieldName, DEVICE_INFO_DEVICE_TYPE) == 0) {
        cacheInfo->deviceInfo.deviceTypeId = atoi(value);
    } else if (strcmp(fieldName, DEVICE_INFO_OS_TYPE) == 0) {
        cacheInfo->deviceInfo.osType = atoi(value);
    } else if (strcmp(fieldName, DEVICE_INFO_OS_VERSION) == 0 && valueLength < OS_VERSION_BUF_LEN) {
        if (strcpy_s(cacheInfo->deviceInfo.osVersion, OS_VERSION_BUF_LEN, value) != EOK) {
            LNN_LOGE(LNN_BUILDER, "fail:strcpy_s osVersion fail");
            return SOFTBUS_MEM_ERR;
        }
    } else {
        LNN_LOGE(LNN_BUILDER, "fail:device basicinfo valuelength over range");
        return SOFTBUS_MEM_ERR;
    }
    LNN_LOGI(LNN_BUILDER, "DBDeviceBasicInfoSyncToCache success.");
    return SOFTBUS_OK;
}

static int32_t DBNumInfoSyncToCache(NodeInfo *cacheInfo, char *fieldName, const char *value)
{
    LNN_LOGI(LNN_BUILDER, "DBNumInfoSyncToCache enter.");
    if (cacheInfo == NULL || fieldName == NULL || value == NULL) {
        LNN_LOGE(LNN_BUILDER, "fail:invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    if (strcmp(fieldName, DEVICE_INFO_STATE_VERSION) == 0) {
        cacheInfo->stateVersion = atoi(value);
    } else if (strcmp(fieldName, DEVICE_INFO_TRANSPORT_PROTOCOL) == 0) {
        cacheInfo->supportedProtocols = atoll(value);
    } else if (strcmp(fieldName, DEVICE_INFO_WIFI_VERSION) == 0) {
        cacheInfo->wifiVersion = atoll(value);
    } else if (strcmp(fieldName, DEVICE_INFO_BLE_VERSION) == 0) {
        cacheInfo->bleVersion = atoll(value);
    } else if (strcmp(fieldName, DEVICE_INFO_ACCOUNT_ID) == 0) {
        cacheInfo->accountId = atoll(value);
    } else if (strcmp(fieldName, DEVICE_INFO_FEATURE) == 0) {
        cacheInfo->feature = atoll(value);
    } else if (strcmp(fieldName, DEVICE_INFO_CONN_SUB_FEATURE) == 0) {
        cacheInfo->connSubFeature = atoll(value);
    } else if (strcmp(fieldName, DEVICE_INFO_AUTH_CAP) == 0) {
        cacheInfo->authCapacity = atoi(value);
    }
    LNN_LOGI(LNN_BUILDER, "DBNumInfoSyncToCache success.");
    return SOFTBUS_OK;
}

static int32_t DBConnectInfoSyncToCache(NodeInfo *cacheInfo, char *fieldName, const char *value, size_t valueLength)
{
    LNN_LOGI(LNN_BUILDER, "DBConnectInfoSyncToCache enter.");
    if (cacheInfo == NULL || fieldName == NULL || value == NULL) {
        LNN_LOGE(LNN_BUILDER, "fail:invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    if (strcmp(fieldName, DEVICE_INFO_NETWORK_ID) == 0 && valueLength < NETWORK_ID_BUF_LEN) {
        if (strcpy_s(cacheInfo->networkId, NETWORK_ID_BUF_LEN, value) != EOK) {
            LNN_LOGE(LNN_BUILDER, "fail:strcpy_s networkid fail");
            return SOFTBUS_MEM_ERR;
        }
    } else if (strcmp(fieldName, DEVICE_INFO_PKG_VERSION) == 0 && valueLength < VERSION_MAX_LEN) {
        if (strcpy_s(cacheInfo->pkgVersion, VERSION_MAX_LEN, value) != EOK) {
            LNN_LOGE(LNN_BUILDER, "fail:strcpy_s pkgVersion fail");
            return SOFTBUS_MEM_ERR;
        }
    } else if (strcmp(fieldName, DEVICE_INFO_BT_MAC) == 0 && valueLength < MAC_LEN) {
        if (strcpy_s(cacheInfo->connectInfo.macAddr, MAC_LEN, value) != EOK) {
            LNN_LOGE(LNN_BUILDER, "fail:strcpy_s macAddress fail");
            return SOFTBUS_MEM_ERR;
        }
    } else if (strcmp(fieldName, DEVICE_INFO_P2P_MAC_ADDR) == 0 && valueLength < MAC_LEN) {
        if (strcpy_s(cacheInfo->p2pInfo.p2pMac, MAC_LEN, value) != EOK) {
            LNN_LOGE(LNN_BUILDER, "fail:strcpy_s p2pMac fail");
            return SOFTBUS_MEM_ERR;
        }
    } else if (strcmp(fieldName, DEVICE_INFO_DEVICE_IRK) == 0 && valueLength < LFINDER_IRK_LEN) {
        if (strcpy_s((char *)cacheInfo->rpaInfo.peerIrk, LFINDER_IRK_LEN, value) != EOK) {
            LNN_LOGE(LNN_BUILDER, "fail:strcpy_s peerIrk fail");
            return SOFTBUS_MEM_ERR;
        }
    } else if (strcmp(fieldName, DEVICE_INFO_DEVICE_PUB_MAC) == 0 && valueLength < LFINDER_MAC_ADDR_LEN) {
        if (strcpy_s((char *)cacheInfo->rpaInfo.publicAddress, LFINDER_MAC_ADDR_LEN, value) != EOK) {
            LNN_LOGE(LNN_BUILDER, "fail:strcpy_s publicAddress fail");
            return SOFTBUS_MEM_ERR;
        }
    } else if (strcmp(fieldName, DEVICE_INFO_PTK) == 0 && valueLength < PTK_DEFAULT_LEN) {
        if (strcpy_s(cacheInfo->remotePtk, PTK_DEFAULT_LEN, value) != EOK) {
            LNN_LOGE(LNN_BUILDER, "fail:strcpy_s remotePtk fail");
            return SOFTBUS_MEM_ERR;
        }
    } else {
        LNN_LOGE(LNN_BUILDER, "fail:connect info valuelength over range");
        return SOFTBUS_MEM_ERR;
    }
    LNN_LOGI(LNN_BUILDER, "DBConnectInfoSyncToCache success.");
    return SOFTBUS_OK;
}

static bool JudgeFieldNameIsDeviceBasicInfo(char *fieldName)
{
    if (fieldName == NULL) {
        LNN_LOGE(LNN_BUILDER, "fail:invalid param");
        return false;
    }
    if (strcmp(fieldName, DEVICE_INFO_DEVICE_NAME) == 0 || strcmp(fieldName, DEVICE_INFO_UNIFIED_DEVICE_NAME) == 0 ||
        strcmp(fieldName, DEVICE_INFO_UNIFIED_DEFAULT_DEVICE_NAME) == 0 ||
        strcmp(fieldName, DEVICE_INFO_SETTINGS_NICK_NAME) == 0 || strcmp(fieldName, DEVICE_INFO_DEVICE_UDID) == 0 ||
        strcmp(fieldName, DEVICE_INFO_DEVICE_TYPE) == 0 || strcmp(fieldName, DEVICE_INFO_OS_TYPE) == 0 ||
        strcmp(fieldName, DEVICE_INFO_OS_VERSION) == 0) {
        return true;
    }
    return false;
}

static bool JudgeFieldNameIsNumInfo(char *fieldName)
{
    if (fieldName == NULL) {
        LNN_LOGE(LNN_BUILDER, "fail:invalid param");
        return false;
    }
    if (strcmp(fieldName, DEVICE_INFO_STATE_VERSION) == 0 || strcmp(fieldName, DEVICE_INFO_TRANSPORT_PROTOCOL) == 0 ||
        strcmp(fieldName, DEVICE_INFO_WIFI_VERSION) == 0 || strcmp(fieldName, DEVICE_INFO_BLE_VERSION) == 0 ||
        strcmp(fieldName, DEVICE_INFO_ACCOUNT_ID) == 0 || strcmp(fieldName, DEVICE_INFO_FEATURE) == 0 ||
        strcmp(fieldName, DEVICE_INFO_CONN_SUB_FEATURE) == 0 || strcmp(fieldName, DEVICE_INFO_AUTH_CAP) == 0) {
        return true;
    }
    return false;
}

static bool JudgeFieldNameIsConnectInfo(char *fieldName)
{
    if (fieldName == NULL) {
        LNN_LOGE(LNN_BUILDER, "fail:invalid param");
        return false;
    }
    if (strcmp(fieldName, DEVICE_INFO_NETWORK_ID) == 0 || strcmp(fieldName, DEVICE_INFO_PKG_VERSION) == 0 ||
        strcmp(fieldName, DEVICE_INFO_BT_MAC) == 0 || strcmp(fieldName, DEVICE_INFO_P2P_MAC_ADDR) == 0 ||
        strcmp(fieldName, DEVICE_INFO_DEVICE_IRK) == 0 || strcmp(fieldName, DEVICE_INFO_DEVICE_PUB_MAC) == 0 ||
        strcmp(fieldName, DEVICE_INFO_PTK) == 0) {
        return true;
    }
    return false;
}

static bool JudgeFieldNameIsCipherInfo(char *fieldName)
{
    if (fieldName == NULL) {
        LNN_LOGE(LNN_BUILDER, "fail:invalid param");
        return false;
    }
    if (strcmp(fieldName, DEVICE_INFO_BROADCAST_CIPHER_KEY) == 0 ||
        strcmp(fieldName, DEVICE_INFO_BROADCAST_CIPHER_IV) == 0 ||
        strcmp(fieldName, DEVICE_INFO_JSON_KEY_TABLE_MIAN) == 0 ||
        strcmp(fieldName, DEVICE_INFO_JSON_KEY_TOTAL_LIFE) == 0 ||
        strcmp(fieldName, DEVICE_INFO_JSON_KEY_TIMESTAMP_BEGIN) == 0 ||
        strcmp(fieldName, DEVICE_INFO_JSON_KEY_CURRENT_INDEX) == 0 ||
        strcmp(fieldName, DEVICE_INFO_DISTRIBUTED_SWITCH) == 0) {
        return true;
    }
    return false;
}

static int32_t DBDataChangeBatchSyncToCacheInternal(NodeInfo *cacheInfo, char *fieldName, const char *value,
    size_t valueLength, const char *udid)
{
    if (cacheInfo == NULL || fieldName == NULL || value == NULL || udid == NULL || strlen(udid) > UDID_BUF_LEN - 1) {
        LNN_LOGE(LNN_BUILDER, "fail:invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    if (JudgeFieldNameIsDeviceBasicInfo(fieldName) == true) {
        if (DBDeviceBasicInfoSyncToCache(cacheInfo, fieldName, value, valueLength) != SOFTBUS_OK) {
            LNN_LOGE(LNN_BUILDER, "fail:strcpy_s device basic info to cache fail");
            return SOFTBUS_MEM_ERR;
        }
    } else if (JudgeFieldNameIsNumInfo(fieldName) == true) {
        if (DBNumInfoSyncToCache(cacheInfo, fieldName, value) != SOFTBUS_OK) {
            LNN_LOGE(LNN_BUILDER, "fail:strcpy_s device name fail");
            return SOFTBUS_MEM_ERR;
        }
    } else if (JudgeFieldNameIsConnectInfo(fieldName) == true) {
        if (DBConnectInfoSyncToCache(cacheInfo, fieldName, value, valueLength) != SOFTBUS_OK) {
            LNN_LOGE(LNN_BUILDER, "fail:strcpy_s connect info fail");
            return SOFTBUS_MEM_ERR;
        }
    } else if (JudgeFieldNameIsCipherInfo(fieldName) == true) {
        if (DBCipherInfoSyncToCache(cacheInfo, fieldName, value, valueLength) != SOFTBUS_OK) {
            LNN_LOGE(LNN_BUILDER, "fail:strcpy_s cipher info fail");
            return SOFTBUS_MEM_ERR;
        }
    } else if (strcmp(fieldName, DEVICE_INFO_DEVICE_UUID) == 0 && valueLength < UUID_BUF_LEN) {
        if (strcpy_s(cacheInfo->uuid, UUID_BUF_LEN, value) != EOK) {
            LNN_LOGE(LNN_BUILDER, "fail:strcpy_s uuid fail");
            return SOFTBUS_MEM_ERR;
        }
    } else if (strcmp(fieldName, DEVICE_INFO_SW_VERSION) == 0 && valueLength < VERSION_MAX_LEN) {
        if (strcpy_s(cacheInfo->softBusVersion, VERSION_MAX_LEN, value) != EOK) {
            LNN_LOGE(LNN_BUILDER, "fail:strcpy_s softbusVersion fail");
            return SOFTBUS_MEM_ERR;
        }
    } else if (strcmp(fieldName, DEVICE_INFO_BLE_P2P) == 0) {
        if (strcmp(value, "true") == 0) {
            cacheInfo->isBleP2p = true;
        } else {
            cacheInfo->isBleP2p = false;
        }
    } else {
        LNN_LOGE(LNN_BUILDER, "fail:invalid fieldname");
        return SOFTBUS_MEM_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t SplitKeyOrValue(const char *key, char splitKeyValue[][SPLIT_MAX_LEN])
{
    if (key == NULL || splitKeyValue == NULL) {
        LNN_LOGE(LNN_BUILDER, "key or splitKeyValue is NULL");
        return SOFTBUS_INVALID_PARAM;
    }
    int index = 0;
    char *infoStr = NULL;
    char *nextToken = NULL;
    char tmp[PUT_VALUE_MAX_LEN] = {0};
    if (strcpy_s(tmp, PUT_VALUE_MAX_LEN, key) != EOK) {
        LNN_LOGE(LNN_BUILDER, "strcpy_s key fail");
        return SOFTBUS_MEM_ERR;
    }
    infoStr = strtok_s(tmp, "#", &nextToken);
    while (infoStr != NULL) {
        if (strcpy_s(splitKeyValue[index++], SPLIT_MAX_LEN, infoStr) != EOK) {
            LNN_LOGE(LNN_BUILDER, "strcpy_s SplitKeyOrValue fail");
            return SOFTBUS_MEM_ERR;
        }
        infoStr = strtok_s(NULL, "#", &nextToken);
    }
    return SOFTBUS_OK;
}

static int32_t GetInfoFromSplitKey(char splitKey[][SPLIT_MAX_LEN], int64_t *accountId, char *deviceUdid,
    char *fieldName)
{
    if (splitKey == NULL || accountId == NULL || deviceUdid == NULL || fieldName == NULL) {
        LNN_LOGE(LNN_BUILDER, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    *accountId = atol(splitKey[0]);
    if (strcpy_s(deviceUdid, UDID_BUF_LEN, splitKey[1]) != EOK) {
        LNN_LOGE(LNN_BUILDER, "fail:strcpy_s deviceUdid fail.");
        return SOFTBUS_MEM_ERR;
    }
    if (strcpy_s(fieldName, FIELDNAME_MAX_LEN, splitKey[SPLIT_VALUE_NUM]) != EOK) {
        LNN_LOGE(LNN_BUILDER, "fail:strcpy_s fieldName fail.");
        return SOFTBUS_MEM_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t SplitString(char splitKey[][SPLIT_MAX_LEN], char splitValue[][SPLIT_MAX_LEN], const char *key,
    const char *value, int32_t *stateVersion)
{
    if (key == NULL || value == NULL || splitKey == NULL || splitValue == NULL) {
        LNN_LOGE(LNN_BUILDER, "fail:invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    if (SplitKeyOrValue(key, splitKey) != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "split key error");
        return SOFTBUS_ERR;
    }
    if (SplitKeyOrValue(value, splitValue) != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "split value error");
        return SOFTBUS_ERR;
    }
    *stateVersion = atoi(splitValue[1]);
    return SOFTBUS_OK;
}

static int32_t HandleDBAddChangeInternal(const char *key, const char *value, NodeInfo *cacheInfo)
{
    LNN_LOGI(LNN_BUILDER, "HandleDBAddChangeInternal enter.");
    if (key == NULL || value == NULL) {
        LNN_LOGE(LNN_BUILDER, "fail:invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    int64_t accountId = 0;
    char deviceUdid[UDID_BUF_LEN] = {0};
    char fieldName[FIELDNAME_MAX_LEN] = {0};
    int32_t stateVersion = 0;
    char splitKey[SPLIT_KEY_NUM][SPLIT_MAX_LEN] = {0};
    char splitValue[SPLIT_VALUE_NUM][SPLIT_MAX_LEN] = {0};
    if (SplitString(splitKey, splitValue, key, value, &stateVersion) != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "split string error");
        return SOFTBUS_ERR;
    }
    if (GetInfoFromSplitKey(splitKey, &accountId, deviceUdid, fieldName) != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "get info from splitkey error");
        return SOFTBUS_ERR;
    }
    char trueValue[SPLIT_MAX_LEN] = {0};
    if (strcpy_s(trueValue, SPLIT_MAX_LEN, splitValue[0]) != EOK) {
        LNN_LOGE(LNN_BUILDER, "fail:strcpy_s true value fail.");
        return SOFTBUS_ERR;
    }

    NodeInfo localCaheInfo = { 0 };
    if (LnnGetLocalCacheNodeInfo(&localCaheInfo) != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "get local cache node info fail");
        return SOFTBUS_ERR;
    }
    if (strcmp(deviceUdid, localCaheInfo.deviceInfo.deviceUdid) == 0) {
        return SOFTBUS_OK;
    }
    if (DBDataChangeBatchSyncToCacheInternal(cacheInfo, fieldName, trueValue, strlen(trueValue), deviceUdid) !=
        SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "fail:DB data change batch sync to cache fail");
        return SOFTBUS_MEM_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t SetDBDataToDistributedLedger(NodeInfo *cacheInfo, char *deviceUdid, size_t udidLength, char *fieldName)
{
    LNN_LOGI(LNN_BUILDER, "SetDBDataToDistributedLedger enter.");
    if (cacheInfo == NULL || deviceUdid == NULL || udidLength > UDID_BUF_LEN - 1 || fieldName == NULL) {
        LNN_LOGE(LNN_BUILDER, "fail:invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    if (strcmp(fieldName, DEVICE_INFO_BROADCAST_CIPHER_KEY) == 0) {
        if (LnnSetDLDeviceBroadcastCipherKey(deviceUdid, (char *)cacheInfo->cipherInfo.key) != true) {
            LNN_LOGE(LNN_BUILDER, "set device cipherkey to distributedLedger fail");
            return SOFTBUS_ERR;
        }
    } else if (strcmp(fieldName, DEVICE_INFO_BROADCAST_CIPHER_IV) == 0) {
        if (LnnSetDLDeviceBroadcastCipherIv(deviceUdid, (char *)cacheInfo->cipherInfo.iv) != true) {
            LNN_LOGE(LNN_BUILDER, "set device cipheriv to distributedLedger fail");
            return SOFTBUS_ERR;
        }
    } else if (strcmp(fieldName, DEVICE_INFO_NETWORK_ID) == 0) {
        if (LnnUpdateNetworkId(cacheInfo) != SOFTBUS_OK) {
            LNN_LOGE(LNN_BUILDER, "set device networkId to distributedLedger fail");
            return SOFTBUS_ERR;
        }
    } else if (strcmp(fieldName, DEVICE_INFO_STATE_VERSION) == 0) {
        if (LnnSetDLDeviceStateVersion(deviceUdid, cacheInfo->stateVersion) != SOFTBUS_OK) {
            LNN_LOGE(LNN_BUILDER, "set device stateversion to distributedLedger fail");
            return SOFTBUS_ERR;
        }
    } else if (strcmp(fieldName, DEVICE_INFO_DEVICE_NAME) == 0) {
        if (LnnSetDLDeviceInfoName(deviceUdid, cacheInfo->deviceInfo.deviceName) != true) {
            LNN_LOGE(LNN_BUILDER, "set device name to distributedLedger fail");
            return SOFTBUS_ERR;
        }
    } else if (strcmp(fieldName, DEVICE_INFO_UNIFIED_DEVICE_NAME) == 0) {
        if (LnnSetDLUnifiedDeviceName(deviceUdid, cacheInfo->deviceInfo.unifiedName) != true) {
            LNN_LOGE(LNN_BUILDER, "set device unifiedName to distributedLedger fail");
            return SOFTBUS_ERR;
        }
    } else if (strcmp(fieldName, DEVICE_INFO_UNIFIED_DEFAULT_DEVICE_NAME) == 0) {
        if (LnnSetDLUnifiedDefaultDeviceName(deviceUdid, cacheInfo->deviceInfo.unifiedDefaultName) != true) {
            LNN_LOGE(LNN_BUILDER, "set device unifiedDefaultName to distributedLedger fail");
            return SOFTBUS_ERR;
        }
    } else if (strcmp(fieldName, DEVICE_INFO_SETTINGS_NICK_NAME) == 0) {
        if (LnnSetDLDeviceNickNameByUdid(deviceUdid, cacheInfo->deviceInfo.nickName) != true) {
            LNN_LOGE(LNN_BUILDER, "set device nickName to distributedLedger fail");
            return SOFTBUS_ERR;
        }
    } else {
        LNN_LOGE(LNN_BUILDER, "fail:invalid fieldname");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

static void UpdateInfoToCacheAndLedger(NodeInfo *cacheInfo, char *deviceUdid, char *fieldName, char *value)
{
    LNN_LOGI(LNN_BUILDER, "UpdateInfoToCacheAndLedger enter");
    if (cacheInfo == NULL || deviceUdid == NULL || strlen(deviceUdid) > UDID_BUF_LEN - 1 || fieldName == NULL ||
        value == NULL) {
        LNN_LOGE(LNN_BUILDER, "fail:invalid param");
        return;
    }
    if (DBDataChangeBatchSyncToCacheInternal(cacheInfo, fieldName, value, strlen(value), deviceUdid) != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "fail:DB data change sync to cache fail");
        return;
    }
    if (SetDBDataToDistributedLedger(cacheInfo, deviceUdid, strlen(deviceUdid), fieldName) != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "set DB data to distributedLedger fail");
    }
}

static int32_t HandleDBUpdateChangeInternal(const char *key, const char *value)
{
    if (key == NULL || value == NULL) {
        LNN_LOGE(LNN_BUILDER, "fail:invalid param.");
        return SOFTBUS_INVALID_PARAM;
    }
    int64_t accountId = 0;
    char deviceUdid[UDID_BUF_LEN] = {0};
    char fieldName[FIELDNAME_MAX_LEN] = {0};
    int32_t stateVersion = 0;
    char splitKey[SPLIT_KEY_NUM][SPLIT_MAX_LEN] = {0};
    char splitValue[SPLIT_VALUE_NUM][SPLIT_MAX_LEN] = {0};
    if (SplitString(splitKey, splitValue, key, value, &stateVersion) != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "split string error");
        return SOFTBUS_ERR;
    }
    if (GetInfoFromSplitKey(splitKey, &accountId, deviceUdid, fieldName) != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "get info from splitkey error");
        return SOFTBUS_ERR;
    }
    char trueValue[SPLIT_MAX_LEN] = {0};
    if (strcpy_s(trueValue, SPLIT_MAX_LEN, splitValue[0]) != EOK) {
        LNN_LOGE(LNN_BUILDER, "fail:strcpy_s true value fail.");
        return SOFTBUS_ERR;
    }

    NodeInfo localCaheInfo = { 0 };
    if (LnnGetLocalCacheNodeInfo(&localCaheInfo) != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "get local cache node info fail");
        return SOFTBUS_ERR;
    }
    if (strcmp(deviceUdid, localCaheInfo.deviceInfo.deviceUdid) == 0) {
        return SOFTBUS_OK;
    }
    Map deviceCacheInfoMap = { 0 };
    if (LnnGetRemoteCacheNodeInfo(&deviceCacheInfoMap) != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "get remote cache node map info fail");
        return SOFTBUS_ERR;
    }
    char udidHash[UDID_HASH_HEX_LEN + 1] = {0};
    if (LnnGenerateHexStringHash((const unsigned char *)deviceUdid, udidHash, UDID_HASH_HEX_LEN) != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "Generate UDID HexStringHash fail");
        return SOFTBUS_ERR;
    }
    if (SoftBusMutexLock(&g_cloudSyncMutex) != 0) {
        LNN_LOGE(LNN_BUILDER, "lock mutex fail");
        return SOFTBUS_LOCK_ERR;
    }
    NodeInfo *cacheInfo = (NodeInfo *)LnnMapGet(&deviceCacheInfoMap, udidHash);
    if (cacheInfo == NULL) {
        LNN_LOGI(LNN_BUILDER, "no this device info in deviceCacheInfoMap, need to insert");
        NodeInfo newInfo = {0};
        if (strcpy_s(newInfo.deviceInfo.deviceUdid, UDID_BUF_LEN, deviceUdid) != EOK) {
            LNN_LOGE(LNN_BUILDER, "fail:strcpy_s deviceudid fail");
            (void)SoftBusMutexUnlock(&g_cloudSyncMutex);
            return SOFTBUS_MEM_ERR;
        }
        UpdateInfoToCacheAndLedger(&newInfo, deviceUdid, fieldName, trueValue);
        if (LnnSaveRemoteDeviceInfo(&newInfo) != SOFTBUS_OK) {
            LNN_LOGE(LNN_BUILDER, "fail:Lnn save remote device info fail");
            (void)SoftBusMutexUnlock(&g_cloudSyncMutex);
            return SOFTBUS_ERR;
        }
        (void)SoftBusMutexUnlock(&g_cloudSyncMutex);
        return SOFTBUS_OK;
    }
    if (cacheInfo->stateVersion > stateVersion && stateVersion != 1) {
        (void)SoftBusMutexUnlock(&g_cloudSyncMutex);
        return SOFTBUS_OK;
    }
    cacheInfo->stateVersion = stateVersion;
    UpdateInfoToCacheAndLedger(cacheInfo, deviceUdid, fieldName, trueValue);
    (void)LnnSaveRemoteDeviceInfo(cacheInfo);
    (void)SoftBusMutexUnlock(&g_cloudSyncMutex);
    return SOFTBUS_OK;
}

static int32_t HandleDBDeleteChangeInternal(const char *key, const char *value)
{
    LNN_LOGI(LNN_BUILDER, "HandleDBDeleteChangeInternal enter.");
    if (key == NULL) {
        LNN_LOGE(LNN_BUILDER, "fail:invalid param key");
        return SOFTBUS_INVALID_PARAM;
    }
    int64_t accountId = 0;
    char deviceUdid[UDID_BUF_LEN] = {0};
    char fieldName[FIELDNAME_MAX_LEN] = {0};
    char splitKey[SPLIT_KEY_NUM][SPLIT_MAX_LEN] = {0};
    if (SplitKeyOrValue(key, splitKey) != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "split key error");
        return SOFTBUS_ERR;
    }
    if (GetInfoFromSplitKey(splitKey, &accountId, deviceUdid, fieldName) != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "get info from splitkey error");
        return SOFTBUS_ERR;
    }
    Map deviceCacheInfoMap = { 0 };
    if (LnnGetRemoteCacheNodeInfo(&deviceCacheInfoMap) != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "get remote cache node map info fail");
        return SOFTBUS_ERR;
    }
    if (LnnMapGet(&deviceCacheInfoMap, (const char *)deviceUdid) == NULL) {
        LNN_LOGI(LNN_BUILDER, "no device info in deviceCacheInfoMap, no need to delete");
        return SOFTBUS_OK;
    }

    LnnDeleteDeviceInfo(deviceUdid);
    LnnRemoveNode(deviceUdid);
    LNN_LOGI(LNN_BUILDER, "HandleDBDeleteChangeInternal success");
    return SOFTBUS_OK;
}

int32_t LnnGetAccountIdFromLocalCache(int64_t *buf)
{
    LNN_LOGI(LNN_BUILDER, "LnnGetAccountIdFromLocalCache enter.");
    if (buf == NULL) {
        LNN_LOGE(LNN_BUILDER, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    NodeInfo localCaheInfo = { 0 };
    if (LnnGetLocalCacheNodeInfo(&localCaheInfo) != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "get local cache node info fail");
        return SOFTBUS_ERR;
    }
    *buf = localCaheInfo.accountId;
    return SOFTBUS_OK;
}

static void FreeKeyAndValue(const char **key, const char **value, int32_t keySize)
{
    for (int32_t i = 0; i < keySize; i++) {
        SoftBusFree((void *)key[i]);
        SoftBusFree((void *)value[i]);
    }
    SoftBusFree(key);
    SoftBusFree(value);
}

int32_t LnnDBDataAddChangeSyncToCache(const char **key, const char **value, int32_t keySize)
{
    LNN_LOGI(LNN_BUILDER, "LnnDBDataAddChangeSyncToCache enter.");
    if (key == NULL || value == NULL || keySize == 0) {
        LNN_LOGE(LNN_BUILDER, "invalid param or keySize is none");
        return SOFTBUS_INVALID_PARAM;
    }
    NodeInfo cacheInfo = { 0 };
    for (int32_t i = 0; i < keySize; i++) {
        if (HandleDBAddChangeInternal(key[i], value[i], &cacheInfo) != SOFTBUS_OK) {
            LNN_LOGE(LNN_BUILDER, "fail:handle db data add change internal fail");
            FreeKeyAndValue(key, value, keySize);
            return SOFTBUS_ERR;
        }
    }

    FreeKeyAndValue(key, value, keySize);
    (void)LnnSaveRemoteDeviceInfo(&cacheInfo);
    LNN_LOGI(LNN_BUILDER, "LnnDBDataAddChangeSyncToCache success.");
    if (LnnUpdateDistributedNodeInfo(&cacheInfo, cacheInfo.deviceInfo.deviceUdid) != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "fail:Cache info add sync to Ledger fail");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int32_t LnnDBDataChangeSyncToCache(const char *key, const char *value, ChangeType changeType)
{
    LNN_LOGI(LNN_BUILDER, "LnnDBDataChangeSyncToCache enter.");
    if (key == NULL) {
        LNN_LOGE(LNN_BUILDER, "fail:invalid param key.");
        return SOFTBUS_INVALID_PARAM;
    }
    int32_t ret = SOFTBUS_OK;
    switch (changeType) {
        case DB_UPDATE:
            ret = HandleDBUpdateChangeInternal(key, value);
            if (ret != SOFTBUS_OK) {
                LNN_LOGE(LNN_BUILDER, "fail:handle db data update change internal fail");
                return SOFTBUS_ERR;
            }
            break;
        case DB_DELETE:
            ret = HandleDBDeleteChangeInternal(key, value);
            if (ret != SOFTBUS_OK) {
                LNN_LOGE(LNN_BUILDER, "fail:handle db data delete change internal fail");
                return SOFTBUS_ERR;
            }
            break;
        default:
            LNN_LOGE(LNN_BUILDER, "changeType is invalid");
            return SOFTBUS_INVALID_PARAM;
    }
    LNN_LOGI(LNN_BUILDER, "LnnDBDataChangeSyncToCache success.");
    return SOFTBUS_OK;
}

int32_t LnnLedgerDataChangeSyncToDB(const char *key, const char *value, size_t valueLength)
{
    LNN_LOGI(LNN_BUILDER, "LnnLedgerDataChangeSyncToDB enter.");
    if (key == NULL || value == NULL || valueLength > KEY_MAX_LEN - 1) {
        LNN_LOGE(LNN_BUILDER, "fail:Ledger param is invalid.");
        return SOFTBUS_INVALID_PARAM;
    }
    NodeInfo localCaheInfo = { 0 };
    if (LnnGetLocalCacheNodeInfo(&localCaheInfo) != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "get local cache node info fail");
        return SOFTBUS_ERR;
    }
    char putKey[KEY_MAX_LEN] = {0};
    if (sprintf_s(putKey, KEY_MAX_LEN, "%ld#%s#%s", localCaheInfo.accountId, localCaheInfo.deviceInfo.deviceUdid,
        key) < 0) {
        LNN_LOGE(LNN_BUILDER, "sprintf_s key fail");
        return SOFTBUS_ERR;
    }
    char putValue[PUT_VALUE_MAX_LEN] = {0};
    if (sprintf_s(putValue, PUT_VALUE_MAX_LEN, "%s#%d", value, localCaheInfo.stateVersion) < 0) {
        LNN_LOGE(LNN_BUILDER, "sprintf_s value fail");
        return SOFTBUS_ERR;
    }

    int32_t dbId = g_dbId;
    int32_t ret = LnnPutDBData(dbId, putKey, strlen(putKey), putValue, strlen(putValue));
    if (ret != 0) {
        LNN_LOGE(LNN_BUILDER, "fail:data sync to DB fail, errorcode: %{public}d", ret);
        return ret;
    }
    LNN_LOGI(LNN_BUILDER, "LnnLedgerDataChangeSyncToDB success.");

    ret = LnnCloudSync(dbId);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "fail:data change cloud sync fail, errorcode:%{public}d", ret);
        return ret;
    }
    return SOFTBUS_OK;
}

int32_t LnnLedgerAllDataSyncToDB(const NodeInfo *info)
{
    LNN_LOGI(LNN_BUILDER, "LnnLedgerAllDataSyncToDB enter.");
    if (info == NULL) {
        LNN_LOGE(LNN_BUILDER, "invalid param, info is NULL");
        return SOFTBUS_INVALID_PARAM;
    }
    if (info->accountId == 0) {
        LNN_LOGE(LNN_BUILDER, "ledger accountid is null, all data no need sync to cloud");
        return SOFTBUS_ERR;
    }
    CloudSyncInfo syncInfo = { 0 };
    syncInfo.distributedSwitch = true;
    if (ConvertNodeInfoToCloudSyncInfo(&syncInfo, info) != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "fail:Ledger all data sync to cache fail.");
        return SOFTBUS_ERR;
    }
    if (LnnGetLocalBroadcastCipherInfo(&syncInfo) != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "get broadcastcipherinfo fail");
        return SOFTBUS_ERR;
    }

    int32_t dbId = g_dbId;
    int32_t ret = LnnPutDBDataBatch(dbId, &syncInfo);
    if (ret != 0) {
        LNN_LOGE(LNN_BUILDER, "fail:data batch sync to DB fail, errorcode:%{public}d", ret);
        return ret;
    }
    LNN_LOGI(LNN_BUILDER, "LnnLedgerAllDataSyncToDB success.");

    ret = LnnCloudSync(dbId);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "fail:data batch cloud sync fail, errorcode:%{public}d", ret);
        return ret;
    }
    return SOFTBUS_OK;
}

int32_t LnnDeleteSyncToDB(void)
{
    LNN_LOGI(LNN_BUILDER, "LnnDeleteSyncToDB enter");
    NodeInfo localCaheInfo = { 0 };
    if (LnnGetLocalCacheNodeInfo(&localCaheInfo) != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "get local cache node info fail");
        return SOFTBUS_ERR;
    }
    char key[KEY_MAX_LEN] = {0};
    if (sprintf_s(key, KEY_MAX_LEN, "%ld#%s", localCaheInfo.accountId, localCaheInfo.deviceInfo.deviceUdid) < 0) {
        LNN_LOGE(LNN_BUILDER, "sprintf_s key fail");
        return SOFTBUS_ERR;
    }

    int32_t dbId = g_dbId;
    int32_t ret = LnnDeleteDBDataByPrefix(dbId, key, strlen(key));
    if (ret != 0) {
        LNN_LOGE(LNN_BUILDER, "fail:data delete sync to DB fail");
        return ret;
    }
    LNN_LOGI(LNN_BUILDER, "LnnDeleteSyncToDB success.");
    ret = LnnCloudSync(dbId);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "fail:data delete cloud sync fail, errorcode:%{public}d", ret);
        return ret;
    }
    return SOFTBUS_OK;
}

void LnnInitCloudSyncModule(void)
{
    LNN_LOGI(LNN_BUILDER, "LnnInitCloudSyncModule enter.");
    int32_t dbId = 0;
    if (LnnCreateKvAdapter(&dbId, APPID, strlen(APPID), STOREID, strlen(STOREID)) != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "Lnn Init Cloud Sync Module fail");
        return;
    }
    g_dbId = dbId;
    if (SoftBusMutexInit(&g_cloudSyncMutex, NULL) != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "Lnn Init cloud Sync mutex fail");
        return;
    }
}

void LnnDeInitCloudSyncModule(void)
{
    LNN_LOGI(LNN_BUILDER, "LnnDeInitCloudSyncModule enter.");
    int32_t dbId = g_dbId;
    if (LnnDestroyKvAdapter(dbId) != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "DeInit Cloud Sync module fail");
    }
    SoftBusMutexDestroy(&g_cloudSyncMutex);
}
