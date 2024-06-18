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

#include "lnn_data_cloud_sync.h"

#include "stdlib.h"
#include <securec.h>

#include "anonymizer.h"
#include "lnn_cipherkey_manager.h"
#include "lnn_device_info_recovery.h"
#include "lnn_distributed_net_ledger.h"
#include "lnn_heartbeat_utils.h"
#include "lnn_kv_adapter_wrapper.h"
#include "lnn_link_finder.h"
#include "lnn_log.h"
#include "lnn_map.h"
#include "lnn_node_info.h"
#include "lnn_p2p_info.h"
#include "softbus_adapter_json.h"
#include "softbus_adapter_mem.h"
#include "softbus_adapter_thread.h"
#include "softbus_errcode.h"
#include "softbus_json_utils.h"
#include "softbus_utils.h"

#define APPID                "dsoftbus"
#define STOREID              "dsoftbus_kv_db"
#define FIELDNAME_MAX_LEN    32
#define KEY_MAX_LEN          128
#define SPLIT_MAX_LEN        128
#define SPLIT_KEY_NUM        3
#define SPLIT_VALUE_NUM      3
#define PUT_VALUE_MAX_LEN    156
#define UDID_HASH_HEX_LEN    16
#define SOFTBUS_STRTOLL_BASE 10

static int32_t g_dbId = 0;

typedef struct {
    int32_t stateVersion;
    uint64_t timestamp;
} CloudSyncValue;

static int32_t DBCipherInfoSyncToCache(
    NodeInfo *cacheInfo, char *fieldName, const char *value, size_t valueLength, const char *udid)
{
    if (strcmp(fieldName, DEVICE_INFO_BROADCAST_CIPHER_KEY) == 0 && valueLength < SESSION_KEY_STR_LEN) {
        if (ConvertHexStringToBytes((unsigned char *)cacheInfo->cipherInfo.key, SESSION_KEY_LENGTH, value,
            valueLength) != SOFTBUS_OK) {
            LNN_LOGE(LNN_BUILDER, "convert cipherkey to bytes fail. cipher info sync to cache fail");
            return SOFTBUS_KV_CONVERT_BYTES_FAILED;
        }
    } else if (strcmp(fieldName, DEVICE_INFO_BROADCAST_CIPHER_IV) == 0 && valueLength < BROADCAST_IV_STR_LEN) {
        if (ConvertHexStringToBytes((unsigned char *)cacheInfo->cipherInfo.iv, BROADCAST_IV_LEN, value,
            valueLength) != SOFTBUS_OK) {
            LNN_LOGE(LNN_BUILDER, "convert cipheriv to bytes fail. cipher info sync to cache fail");
            return SOFTBUS_KV_CONVERT_BYTES_FAILED;
        }
    } else if (strcmp(fieldName, DEVICE_INFO_JSON_BROADCAST_KEY_TABLE) == 0) {
        LnnSetRemoteBroadcastCipherInfo(value, udid);
    } else if (strcmp(fieldName, DEVICE_INFO_DISTRIBUTED_SWITCH) == 0) {
        LNN_LOGD(LNN_BUILDER, "distributed switch info no need update into nodeinfo");
    } else {
        LNN_LOGE(LNN_BUILDER, "fail:cipher info %{public}s valuelength over range", fieldName);
        return SOFTBUS_INVALID_PARAM;
    }
    LNN_LOGD(LNN_BUILDER, "success.");
    return SOFTBUS_OK;
}

static int32_t DBDeviceNameInfoSyncToCache(NodeInfo *cacheInfo, char *fieldName, const char *value, size_t valueLength)
{
    if (strcmp(fieldName, DEVICE_INFO_DEVICE_NAME) == 0 && valueLength < DEVICE_NAME_BUF_LEN) {
        if (strcpy_s(cacheInfo->deviceInfo.deviceName, DEVICE_NAME_BUF_LEN, value) != EOK) {
            LNN_LOGE(LNN_BUILDER, "fail:strcpy_s devicename fail");
            return SOFTBUS_STRCPY_ERR;
        }
        LNN_LOGI(LNN_BUILDER, "success. deviceName=%{public}s", cacheInfo->deviceInfo.deviceName);
    } else if (strcmp(fieldName, DEVICE_INFO_UNIFIED_DEVICE_NAME) == 0 && valueLength < DEVICE_NAME_BUF_LEN) {
        if (strcpy_s(cacheInfo->deviceInfo.unifiedName, DEVICE_NAME_BUF_LEN, value) != EOK) {
            LNN_LOGE(LNN_BUILDER, "fail:strcpy_s unifiedname fail");
            return SOFTBUS_STRCPY_ERR;
        }
    } else if (strcmp(fieldName, DEVICE_INFO_UNIFIED_DEFAULT_DEVICE_NAME) == 0 && valueLength < DEVICE_NAME_BUF_LEN) {
        if (strcpy_s(cacheInfo->deviceInfo.unifiedDefaultName, DEVICE_NAME_BUF_LEN, value) != EOK) {
            LNN_LOGE(LNN_BUILDER, "fail:strcpy_s unifieddefaultname fail");
            return SOFTBUS_STRCPY_ERR;
        }
    } else if (strcmp(fieldName, DEVICE_INFO_SETTINGS_NICK_NAME) == 0 && valueLength < DEVICE_NAME_BUF_LEN) {
        if (strcpy_s(cacheInfo->deviceInfo.nickName, DEVICE_NAME_BUF_LEN, value) != EOK) {
            LNN_LOGE(LNN_BUILDER, "fail:strcpy_s nickname fail");
            return SOFTBUS_STRCPY_ERR;
        }
    } else {
        LNN_LOGE(LNN_BUILDER, "fail:device basicinfo valuelength over range");
        return SOFTBUS_INVALID_PARAM;
    }
    return SOFTBUS_OK;
}

static int32_t DBDeviceBasicInfoSyncToCache(NodeInfo *cacheInfo, char *fieldName, const char *value, size_t valueLength)
{
    if (strcmp(fieldName, DEVICE_INFO_DEVICE_UDID) == 0 && valueLength < UDID_BUF_LEN) {
        if (strcpy_s(cacheInfo->deviceInfo.deviceUdid, UDID_BUF_LEN, value) != EOK) {
            LNN_LOGE(LNN_BUILDER, "fail:strcpy_s deviceUdid fail");
            return SOFTBUS_STRCPY_ERR;
        }
        char *anonyUdid = NULL;
        Anonymize(cacheInfo->deviceInfo.deviceUdid, &anonyUdid);
        LNN_LOGI(LNN_BUILDER, "success, udid=%{public}s", anonyUdid);
        AnonymizeFree(anonyUdid);
    } else if (strcmp(fieldName, DEVICE_INFO_DEVICE_TYPE) == 0) {
        cacheInfo->deviceInfo.deviceTypeId = atoi(value);
    } else if (strcmp(fieldName, DEVICE_INFO_OS_TYPE) == 0) {
        cacheInfo->deviceInfo.osType = atoi(value);
    } else if (strcmp(fieldName, DEVICE_INFO_OS_VERSION) == 0 && valueLength < OS_VERSION_BUF_LEN) {
        if (strcpy_s(cacheInfo->deviceInfo.osVersion, OS_VERSION_BUF_LEN, value) != EOK) {
            LNN_LOGE(LNN_BUILDER, "fail:strcpy_s osVersion fail");
            return SOFTBUS_STRCPY_ERR;
        }
    } else if (strcmp(fieldName, DEVICE_INFO_DEVICE_UUID) == 0 && valueLength < UUID_BUF_LEN) {
        if (strcpy_s(cacheInfo->uuid, UUID_BUF_LEN, value) != EOK) {
            LNN_LOGE(LNN_BUILDER, "fail:strcpy_s uuid fail");
            return SOFTBUS_STRCPY_ERR;
        }
        char *anoyUuid = NULL;
        Anonymize(cacheInfo->uuid, &anoyUuid);
        LNN_LOGI(LNN_BUILDER, "success, uuid=%{public}s", anoyUuid);
        AnonymizeFree(anoyUuid);
    } else if (DBDeviceNameInfoSyncToCache(cacheInfo, fieldName, value, valueLength) != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "fail:DB device name info sync to cache fail");
        return SOFTBUS_ERR;
    }
    LNN_LOGD(LNN_BUILDER, "success.");
    return SOFTBUS_OK;
}

static int32_t DBNumInfoSyncToCache(NodeInfo *cacheInfo, char *fieldName, const char *value)
{
    if (strcmp(fieldName, DEVICE_INFO_STATE_VERSION) == 0) {
        cacheInfo->stateVersion = atoi(value);
        LNN_LOGI(LNN_BUILDER, "success. stateVersion=%{public}d", cacheInfo->stateVersion);
    } else if (strcmp(fieldName, DEVICE_INFO_TRANSPORT_PROTOCOL) == 0) {
        cacheInfo->supportedProtocols = atoll(value);
    } else if (strcmp(fieldName, DEVICE_INFO_WIFI_VERSION) == 0) {
        cacheInfo->wifiVersion = atoll(value);
    } else if (strcmp(fieldName, DEVICE_INFO_BLE_VERSION) == 0) {
        cacheInfo->bleVersion = atoll(value);
    } else if (strcmp(fieldName, DEVICE_INFO_ACCOUNT_ID) == 0) {
        cacheInfo->accountId = atoll(value);
    } else if (strcmp(fieldName, DEVICE_INFO_FEATURE) == 0) {
        cacheInfo->feature = (uint64_t)atoll(value);
        LNN_LOGI(LNN_BUILDER, "success. feature=%{public}" PRIu64 "", cacheInfo->feature);
    } else if (strcmp(fieldName, DEVICE_INFO_CONN_SUB_FEATURE) == 0) {
        cacheInfo->connSubFeature = atoll(value);
        LNN_LOGI(LNN_BUILDER, "success. connSubFeature=%{public}" PRIu64 "", cacheInfo->connSubFeature);
    } else if (strcmp(fieldName, DEVICE_INFO_AUTH_CAP) == 0) {
        cacheInfo->authCapacity = (uint32_t)atoi(value);
        LNN_LOGI(LNN_BUILDER, "success. authCapacity=%{public}u", cacheInfo->authCapacity);
    }
    LNN_LOGD(LNN_BUILDER, "success.");
    return SOFTBUS_OK;
}

static int32_t DBConnectMacInfoSyncToCache(NodeInfo *cacheInfo, char *fieldName, const char *value, size_t valueLength)
{
    if (strcmp(fieldName, DEVICE_INFO_BT_MAC) == 0 && valueLength < MAC_LEN) {
        if (strcpy_s(cacheInfo->connectInfo.macAddr, MAC_LEN, value) != EOK) {
            LNN_LOGE(LNN_BUILDER, "fail:strcpy_s macAddress fail");
            return SOFTBUS_STRCPY_ERR;
        }
    } else if (strcmp(fieldName, DEVICE_INFO_P2P_MAC_ADDR) == 0 && valueLength < MAC_LEN) {
        if (strcpy_s(cacheInfo->p2pInfo.p2pMac, MAC_LEN, value) != EOK) {
            LNN_LOGE(LNN_BUILDER, "fail:strcpy_s p2pMac fail");
            return SOFTBUS_STRCPY_ERR;
        }
    } else if (strcmp(fieldName, DEVICE_INFO_DEVICE_IRK) == 0 && valueLength < LFINDER_IRK_STR_LEN) {
        if (ConvertHexStringToBytes((unsigned char *)cacheInfo->rpaInfo.peerIrk, LFINDER_IRK_LEN, value,
            valueLength) != SOFTBUS_OK) {
            LNN_LOGE(LNN_BUILDER, "convert peerIrk to bytes fail. rpa info sync to cache fail");
            return SOFTBUS_KV_CONVERT_BYTES_FAILED;
        }
    } else if (strcmp(fieldName, DEVICE_INFO_DEVICE_PUB_MAC) == 0 && valueLength < LFINDER_MAC_ADDR_STR_LEN) {
        if (ConvertHexStringToBytes((unsigned char *)cacheInfo->rpaInfo.publicAddress, LFINDER_MAC_ADDR_LEN, value,
            valueLength) != SOFTBUS_OK) {
            LNN_LOGE(LNN_BUILDER, "convert publicAddress to bytes fail. rpa info sync to cache fail");
            return SOFTBUS_KV_CONVERT_BYTES_FAILED;
        }
    } else {
        LNN_LOGE(LNN_BUILDER, "fail:connect info %{public}s valuelength over range", fieldName);
        return SOFTBUS_INVALID_PARAM;
    }
    return SOFTBUS_OK;
}

static int32_t DBConnectInfoSyncToCache(NodeInfo *cacheInfo, char *fieldName, const char *value, size_t valueLength)
{
    if (strcmp(fieldName, DEVICE_INFO_NETWORK_ID) == 0 && valueLength < NETWORK_ID_BUF_LEN) {
        if (strcpy_s(cacheInfo->networkId, NETWORK_ID_BUF_LEN, value) != EOK) {
            LNN_LOGE(LNN_BUILDER, "fail:strcpy_s networkid fail");
            return SOFTBUS_STRCPY_ERR;
        }
        char *anonyNetworkId = NULL;
        Anonymize(cacheInfo->networkId, &anonyNetworkId);
        LNN_LOGI(LNN_BUILDER, "success. networkId=%{public}s", anonyNetworkId);
        AnonymizeFree(anonyNetworkId);
    } else if (strcmp(fieldName, DEVICE_INFO_PKG_VERSION) == 0 && valueLength < VERSION_MAX_LEN) {
        if (strcpy_s(cacheInfo->pkgVersion, VERSION_MAX_LEN, value) != EOK) {
            LNN_LOGE(LNN_BUILDER, "fail:strcpy_s pkgVersion fail");
            return SOFTBUS_STRCPY_ERR;
        }
    } else if (strcmp(fieldName, DEVICE_INFO_PTK) == 0) {
        if (memcpy_s(cacheInfo->remotePtk, PTK_DEFAULT_LEN, value, PTK_DEFAULT_LEN) != EOK) {
            LNN_LOGE(LNN_BUILDER, "fail:memcpy_s remotePtk fail");
            return SOFTBUS_MEM_ERR;
        }
    } else if (strcmp(fieldName, DEVICE_INFO_SW_VERSION) == 0 && valueLength < VERSION_MAX_LEN) {
        if (strcpy_s(cacheInfo->softBusVersion, VERSION_MAX_LEN, value) != EOK) {
            LNN_LOGE(LNN_BUILDER, "fail:strcpy_s softbusVersion fail");
            return SOFTBUS_STRCPY_ERR;
        }
    } else if (DBConnectMacInfoSyncToCache(cacheInfo, fieldName, value, valueLength) != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "fail:DB ConnectMacInfo Sync To Cache fail");
        return SOFTBUS_ERR;
    }
    LNN_LOGD(LNN_BUILDER, "success.");
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
        strcmp(fieldName, DEVICE_INFO_OS_VERSION) == 0 || strcmp(fieldName, DEVICE_INFO_DEVICE_UUID) == 0) {
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
        strcmp(fieldName, DEVICE_INFO_PTK) == 0 || strcmp(fieldName, DEVICE_INFO_SW_VERSION) == 0) {
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
        strcmp(fieldName, DEVICE_INFO_JSON_BROADCAST_KEY_TABLE) == 0 ||
        strcmp(fieldName, DEVICE_INFO_JSON_KEY_TOTAL_LIFE) == 0 ||
        strcmp(fieldName, DEVICE_INFO_JSON_KEY_TIMESTAMP_BEGIN) == 0 ||
        strcmp(fieldName, DEVICE_INFO_JSON_KEY_CURRENT_INDEX) == 0 ||
        strcmp(fieldName, DEVICE_INFO_DISTRIBUTED_SWITCH) == 0) {
        return true;
    }
    return false;
}

static int32_t DBDataChangeBatchSyncToCacheInternal(
    NodeInfo *cacheInfo, char *fieldName, const char *value, size_t valueLength, const char *udid)
{
    if (cacheInfo == NULL || fieldName == NULL || value == NULL || udid == NULL || strlen(udid) > UDID_BUF_LEN - 1) {
        LNN_LOGE(LNN_BUILDER, "fail:invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    if (JudgeFieldNameIsDeviceBasicInfo(fieldName)) {
        if (DBDeviceBasicInfoSyncToCache(cacheInfo, fieldName, value, valueLength) != SOFTBUS_OK) {
            LNN_LOGE(LNN_BUILDER, "fail:strcpy_s device basic info to cache fail");
            return SOFTBUS_ERR;
        }
    } else if (JudgeFieldNameIsNumInfo(fieldName)) {
        if (DBNumInfoSyncToCache(cacheInfo, fieldName, value) != SOFTBUS_OK) {
            LNN_LOGE(LNN_BUILDER, "fail:strcpy_s device name fail");
            return SOFTBUS_ERR;
        }
    } else if (JudgeFieldNameIsConnectInfo(fieldName)) {
        if (DBConnectInfoSyncToCache(cacheInfo, fieldName, value, valueLength) != SOFTBUS_OK) {
            LNN_LOGE(LNN_BUILDER, "fail:strcpy_s connect info fail");
            return SOFTBUS_ERR;
        }
    } else if (JudgeFieldNameIsCipherInfo(fieldName)) {
        if (DBCipherInfoSyncToCache(cacheInfo, fieldName, value, valueLength, udid) != SOFTBUS_OK) {
            LNN_LOGE(LNN_BUILDER, "fail:strcpy_s cipher info fail");
            return SOFTBUS_ERR;
        }
    } else if (strcmp(fieldName, DEVICE_INFO_BLE_P2P) == 0) {
        if (strcmp(value, "true") == 0) {
            cacheInfo->isBleP2p = true;
        } else {
            cacheInfo->isBleP2p = false;
        }
    } else {
        LNN_LOGE(LNN_BUILDER, "fail:invalid fieldname");
        return SOFTBUS_INVALID_PARAM;
    }
    return SOFTBUS_OK;
}

static int32_t SplitKeyOrValue(const char *key, char splitKeyValue[][SPLIT_MAX_LEN], int32_t size)
{
    if (key == NULL || splitKeyValue == NULL) {
        LNN_LOGE(LNN_BUILDER, "key or splitKeyValue is NULL");
        return SOFTBUS_INVALID_PARAM;
    }
    int index = 0;
    char *infoStr = NULL;
    char *nextToken = NULL;
    char tmp[PUT_VALUE_MAX_LEN] = { 0 };
    if (strcpy_s(tmp, PUT_VALUE_MAX_LEN, key) != EOK) {
        LNN_LOGE(LNN_BUILDER, "strcpy_s key fail");
        return SOFTBUS_STRCPY_ERR;
    }
    infoStr = strtok_s(tmp, "#", &nextToken);
    while (infoStr != NULL) {
        if (index > size - 1) {
            LNN_LOGD(LNN_BUILDER, "index over range");
            break;
        }
        if (strcpy_s(splitKeyValue[index++], SPLIT_MAX_LEN, infoStr) != EOK) {
            LNN_LOGE(LNN_BUILDER, "strcpy_s SplitKeyOrValue fail");
            return SOFTBUS_STRCPY_ERR;
        }
        infoStr = strtok_s(NULL, "#", &nextToken);
    }
    return SOFTBUS_OK;
}

static int32_t GetInfoFromSplitKey(
    char splitKey[][SPLIT_MAX_LEN], int64_t *accountId, char *deviceUdid, char *fieldName)
{
    if (splitKey == NULL || accountId == NULL || deviceUdid == NULL || fieldName == NULL) {
        LNN_LOGE(LNN_BUILDER, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    *accountId = atol(splitKey[0]);
    if (strcpy_s(deviceUdid, UDID_BUF_LEN, splitKey[1]) != EOK) {
        LNN_LOGE(LNN_BUILDER, "fail:strcpy_s deviceUdid fail.");
        return SOFTBUS_STRCPY_ERR;
    }
    if (strcpy_s(fieldName, FIELDNAME_MAX_LEN, splitKey[SPLIT_VALUE_NUM - 1]) != EOK) {
        LNN_LOGE(LNN_BUILDER, "fail:strcpy_s fieldName fail.");
        return SOFTBUS_STRCPY_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t SplitString(char splitKey[SPLIT_KEY_NUM][SPLIT_MAX_LEN], char splitValue[SPLIT_VALUE_NUM][SPLIT_MAX_LEN],
    const char *key, const char *value, CloudSyncValue *parseValue)
{
    if (key == NULL || value == NULL || splitKey == NULL || splitValue == NULL || parseValue == NULL) {
        LNN_LOGE(LNN_BUILDER, "fail:invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    if (SplitKeyOrValue(key, splitKey, SPLIT_KEY_NUM) != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "split key error");
        return SOFTBUS_ERR;
    }
    if (SplitKeyOrValue(value, splitValue, SPLIT_VALUE_NUM) != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "split value error");
        return SOFTBUS_ERR;
    }
    parseValue->stateVersion = atoi(splitValue[1]);
    parseValue->timestamp = strtoull(splitValue[SPLIT_VALUE_NUM - 1], NULL, SOFTBUS_STRTOLL_BASE);
    return SOFTBUS_OK;
}

static int32_t HandleDBAddChangeInternal(const char *key, const char *value, NodeInfo *cacheInfo)
{
    LNN_LOGD(LNN_BUILDER, "enter.");
    if (key == NULL || value == NULL) {
        LNN_LOGE(LNN_BUILDER, "fail:invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    int64_t accountId = 0;
    char deviceUdid[UDID_BUF_LEN] = { 0 };
    char fieldName[FIELDNAME_MAX_LEN] = { 0 };
    CloudSyncValue parseValue = { 0 };
    char splitKey[SPLIT_KEY_NUM][SPLIT_MAX_LEN] = { 0 };
    char splitValue[SPLIT_VALUE_NUM][SPLIT_MAX_LEN] = { 0 };
    if (SplitString(splitKey, splitValue, key, value, &parseValue) != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "split string error");
        return SOFTBUS_ERR;
    }
    if (GetInfoFromSplitKey(splitKey, &accountId, deviceUdid, fieldName) != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "get info from splitkey error");
        return SOFTBUS_ERR;
    }
    char trueValue[SPLIT_MAX_LEN] = { 0 };
    if (strcpy_s(trueValue, SPLIT_MAX_LEN, splitValue[0]) != EOK) {
        LNN_LOGE(LNN_BUILDER, "fail:strcpy_s true value fail.");
        return SOFTBUS_STRCPY_ERR;
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
        return SOFTBUS_ERR;
    }
    cacheInfo->localStateVersion = localCaheInfo.stateVersion;
    cacheInfo->updateTimestamp = parseValue.timestamp;
    return SOFTBUS_OK;
}

static int32_t SetDBNameDataToDLedger(NodeInfo *cacheInfo, char *deviceUdid, char *fieldName)
{
    if (strcmp(fieldName, DEVICE_INFO_DEVICE_NAME) == 0) {
        if (!LnnSetDLDeviceInfoName(deviceUdid, cacheInfo->deviceInfo.deviceName)) {
            LNN_LOGE(LNN_BUILDER, "set device name to distributedLedger fail");
            return SOFTBUS_ERR;
        }
    } else if (strcmp(fieldName, DEVICE_INFO_UNIFIED_DEVICE_NAME) == 0) {
        if (LnnSetDLUnifiedDeviceName(deviceUdid, cacheInfo->deviceInfo.unifiedName) != SOFTBUS_OK) {
            LNN_LOGE(LNN_BUILDER, "set device unifiedName to distributedLedger fail");
            return SOFTBUS_ERR;
        }
    } else if (strcmp(fieldName, DEVICE_INFO_UNIFIED_DEFAULT_DEVICE_NAME) == 0) {
        if (LnnSetDLUnifiedDefaultDeviceName(deviceUdid, cacheInfo->deviceInfo.unifiedDefaultName) != SOFTBUS_OK) {
            LNN_LOGE(LNN_BUILDER, "set device unifiedDefaultName to distributedLedger fail");
            return SOFTBUS_ERR;
        }
    } else if (strcmp(fieldName, DEVICE_INFO_SETTINGS_NICK_NAME) == 0) {
        if (LnnSetDLDeviceNickNameByUdid(deviceUdid, cacheInfo->deviceInfo.nickName) != SOFTBUS_OK) {
            LNN_LOGE(LNN_BUILDER, "set device nickName to distributedLedger fail");
            return SOFTBUS_ERR;
        }
    } else {
        LNN_LOGD(LNN_BUILDER, "%{public}s no need update to DLedger", fieldName);
        return SOFTBUS_OK;
    }
    return SOFTBUS_OK;
}

static int32_t SetDBDataToDistributedLedger(NodeInfo *cacheInfo, char *deviceUdid, size_t udidLength, char *fieldName)
{
    if (cacheInfo == NULL || deviceUdid == NULL || udidLength > UDID_BUF_LEN - 1 || fieldName == NULL) {
        LNN_LOGE(LNN_BUILDER, "fail:invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    if (strcmp(fieldName, DEVICE_INFO_BROADCAST_CIPHER_KEY) == 0) {
        if (LnnSetDLDeviceBroadcastCipherKey(deviceUdid, cacheInfo->cipherInfo.key) != SOFTBUS_OK) {
            LNN_LOGE(LNN_BUILDER, "set device cipherkey to distributedLedger fail");
            return SOFTBUS_ERR;
        }
    } else if (strcmp(fieldName, DEVICE_INFO_BROADCAST_CIPHER_IV) == 0) {
        if (LnnSetDLDeviceBroadcastCipherIv(deviceUdid, cacheInfo->cipherInfo.iv) != SOFTBUS_OK) {
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
    } else if (SetDBNameDataToDLedger(cacheInfo, deviceUdid, fieldName) != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "set DB name data to distributedLedger fail");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

static void UpdateInfoToLedger(NodeInfo *cacheInfo, char *deviceUdid, char *fieldName, char *value)
{
    LNN_LOGI(LNN_BUILDER, "enter");
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

static bool IsIgnoreUpdate(
    int32_t oldStateVersion, uint64_t oldTimestamp, int32_t newStateVersion, uint64_t newTimestamp)
{
    bool isIgnore = oldTimestamp > newTimestamp || (oldTimestamp == 0 && oldStateVersion > newStateVersion);
    if (isIgnore) {
        LNN_LOGE(LNN_BUILDER,
            "fail: sync info is older, oldCacheInfo.stateVersion=%{public}d, oldTimestamp=%{public}" PRIu64
            ", newSyncInfo.stateVersion=%{public}d, newTimestamp=%{public}" PRIu64 "",
            oldStateVersion, oldTimestamp, newStateVersion, newTimestamp);
    }
    return isIgnore;
}

static int32_t HandleDBUpdateInternal(
    char *deviceUdid, char *fieldName, char *trueValue, const CloudSyncValue *parseValue, int32_t localStateVersion)
{
    if (deviceUdid == NULL || fieldName == NULL || trueValue == NULL) {
        LNN_LOGE(LNN_BUILDER, "fail:invalid param.");
        return SOFTBUS_INVALID_PARAM;
    }
    char udidHash[UDID_HASH_HEX_LEN + 1] = { 0 };
    if (LnnGenerateHexStringHash((const unsigned char *)deviceUdid, udidHash, UDID_HASH_HEX_LEN) != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "Generate UDID HexStringHash fail");
        return SOFTBUS_ERR;
    }
    NodeInfo cacheInfo = { 0 };
    if (LnnRetrieveDeviceInfo(udidHash, &cacheInfo) != SOFTBUS_OK) {
        LNN_LOGI(LNN_BUILDER, "no this device info in deviceCacheInfoMap, ignore update");
        return SOFTBUS_OK;
    }
    if (IsIgnoreUpdate(cacheInfo.stateVersion, cacheInfo.updateTimestamp, parseValue->stateVersion,
        parseValue->timestamp)) {
        (void)memset_s(&cacheInfo, sizeof(NodeInfo), 0, sizeof(NodeInfo));
        return SOFTBUS_OK;
    }
    LNN_LOGI(LNN_BUILDER, "update peer stateVersion=%{public}d->%{public}d, localStateVersion=%{public}d->%{public}d",
        cacheInfo.stateVersion, parseValue->stateVersion, cacheInfo.localStateVersion, localStateVersion);
    cacheInfo.stateVersion = parseValue->stateVersion;
    UpdateInfoToLedger(&cacheInfo, deviceUdid, fieldName, trueValue);
    cacheInfo.localStateVersion = localStateVersion;
    (void)LnnSaveRemoteDeviceInfo(&cacheInfo);
    (void)memset_s(&cacheInfo, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    return SOFTBUS_OK;
}

static int32_t HandleDBUpdateChangeInternal(const char *key, const char *value)
{
    if (key == NULL || value == NULL) {
        LNN_LOGE(LNN_BUILDER, "fail:invalid param.");
        return SOFTBUS_INVALID_PARAM;
    }
    int64_t accountId = 0;
    char deviceUdid[UDID_BUF_LEN] = { 0 };
    char fieldName[FIELDNAME_MAX_LEN] = { 0 };
    CloudSyncValue parseValue = { 0 };
    char splitKey[SPLIT_KEY_NUM][SPLIT_MAX_LEN] = { 0 };
    char splitValue[SPLIT_VALUE_NUM][SPLIT_MAX_LEN] = { 0 };
    if (SplitString(splitKey, splitValue, key, value, &parseValue) != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "split string error");
        return SOFTBUS_ERR;
    }
    if (GetInfoFromSplitKey(splitKey, &accountId, deviceUdid, fieldName) != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "get info from splitkey error");
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
    char trueValue[SPLIT_MAX_LEN] = { 0 };
    if (strcpy_s(trueValue, SPLIT_MAX_LEN, splitValue[0]) != EOK) {
        LNN_LOGE(LNN_BUILDER, "fail:strcpy_s true value fail.");
        return SOFTBUS_STRCPY_ERR;
    }
    if (HandleDBUpdateInternal(deviceUdid, fieldName, trueValue, &parseValue, localCaheInfo.stateVersion) !=
        SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "handle DB update change internal fail");
        (void)memset_s(trueValue, strlen(trueValue), 0, strlen(trueValue));
        return SOFTBUS_ERR;
    }
    char *anonyDeviceUdid = NULL;
    Anonymize(deviceUdid, &anonyDeviceUdid);
    char *anonyTrueValue = NULL;
    Anonymize(trueValue, &anonyTrueValue);
    LNN_LOGI(LNN_BUILDER,
        "deviceUdid=%{public}s, fieldName=%{public}s update to %{public}s success, stateVersion=%{public}d",
        anonyDeviceUdid, fieldName, anonyTrueValue, parseValue.stateVersion);
    AnonymizeFree(anonyDeviceUdid);
    AnonymizeFree(anonyTrueValue);
    (void)memset_s(trueValue, strlen(trueValue), 0, strlen(trueValue));
    return SOFTBUS_OK;
}

static int32_t HandleDBDeleteChangeInternal(const char *key, const char *value)
{
    (void)value;
    if (key == NULL) {
        LNN_LOGE(LNN_BUILDER, "fail:invalid param key");
        return SOFTBUS_INVALID_PARAM;
    }
    int64_t accountId = 0;
    char deviceUdid[UDID_BUF_LEN] = { 0 };
    char fieldName[FIELDNAME_MAX_LEN] = { 0 };
    char splitKey[SPLIT_KEY_NUM][SPLIT_MAX_LEN] = { 0 };
    if (SplitKeyOrValue(key, splitKey, SPLIT_KEY_NUM) != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "split key error");
        return SOFTBUS_ERR;
    }
    if (GetInfoFromSplitKey(splitKey, &accountId, deviceUdid, fieldName) != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "get info from splitkey error");
        return SOFTBUS_ERR;
    }
    char udidHash[UDID_HASH_HEX_LEN + 1] = { 0 };
    if (LnnGenerateHexStringHash((const unsigned char *)deviceUdid, udidHash, UDID_HASH_HEX_LEN) != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "Generate UDID HexStringHash fail");
        return SOFTBUS_ERR;
    }
    NodeInfo cacheInfo = { 0 };
    if (LnnRetrieveDeviceInfo(udidHash, &cacheInfo) != SOFTBUS_OK) {
        LNN_LOGI(LNN_BUILDER, "no device info in deviceCacheInfoMap, no need to delete");
        return SOFTBUS_OK;
    }

    LnnDeleteDeviceInfo(deviceUdid);
    LnnRemoveNode(deviceUdid);
    LNN_LOGI(LNN_BUILDER, "success");
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

static void FreeKeyOrValue(const char **object, int32_t size)
{
    for (int32_t i = 0; i < size; i++) {
        SoftBusFree((void *)object[i]);
    }
    SoftBusFree(object);
}

int32_t LnnDBDataAddChangeSyncToCache(const char **key, const char **value, int32_t keySize)
{
    if (key == NULL || value == NULL || keySize == 0) {
        LNN_LOGE(LNN_BUILDER, "invalid param or keySize is none");
        if (key == NULL && value != NULL && keySize != 0) {
            FreeKeyOrValue(value, keySize);
        } else if (key != NULL && value == NULL && keySize != 0) {
            FreeKeyOrValue(key, keySize);
        }
        return SOFTBUS_INVALID_PARAM;
    }
    NodeInfo cacheInfo = { 0 };
    for (int32_t i = 0; i < keySize; i++) {
        if (HandleDBAddChangeInternal(key[i], value[i], &cacheInfo) != SOFTBUS_OK) {
            LNN_LOGE(LNN_BUILDER, "fail:handle db data add change internal fail");
            FreeKeyAndValue(key, value, keySize);
            (void)memset_s(&cacheInfo, sizeof(NodeInfo), 0, sizeof(NodeInfo));
            return SOFTBUS_ERR;
        }
    }
    FreeKeyAndValue(key, value, keySize);
    char udidHash[UDID_HASH_HEX_LEN + 1] = { 0 };
    if (LnnGenerateHexStringHash((const unsigned char *)cacheInfo.deviceInfo.deviceUdid, udidHash, UDID_HASH_HEX_LEN) !=
        SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "Generate UDID HexStringHash fail");
        return SOFTBUS_ERR;
    }
    NodeInfo oldCacheInfo = { 0 };
    if (LnnRetrieveDeviceInfo(udidHash, &oldCacheInfo) == SOFTBUS_OK &&
        IsIgnoreUpdate(oldCacheInfo.stateVersion, oldCacheInfo.updateTimestamp, cacheInfo.stateVersion,
            cacheInfo.updateTimestamp)) {
        return SOFTBUS_ERR;
    }
    (void)LnnSaveRemoteDeviceInfo(&cacheInfo);
    char *anonyUdid = NULL;
    Anonymize(cacheInfo.deviceInfo.deviceUdid, &anonyUdid);
    LNN_LOGI(LNN_BUILDER,
        "success. udid=%{public}s, stateVersion=%{public}d, localStateVersion=%{public}d, updateTimestamp=%{public}"
        "" PRIu64, anonyUdid, cacheInfo.stateVersion, cacheInfo.localStateVersion, cacheInfo.updateTimestamp);
    AnonymizeFree(anonyUdid);
    if (LnnUpdateDistributedNodeInfo(&cacheInfo, cacheInfo.deviceInfo.deviceUdid) != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "fail:Cache info add sync to Ledger fail");
        (void)memset_s(&cacheInfo, sizeof(NodeInfo), 0, sizeof(NodeInfo));
        return SOFTBUS_ERR;
    }
    (void)memset_s(&cacheInfo, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    return SOFTBUS_OK;
}

static void PrintSyncNodeInfo(const NodeInfo *cacheInfo)
{
    if (cacheInfo == NULL) {
        LNN_LOGE(LNN_BUILDER, "invalid param");
        return;
    }
    char *anonyP2pMac = NULL;
    Anonymize(cacheInfo->p2pInfo.p2pMac, &anonyP2pMac);
    char *anonyMacAddr = NULL;
    Anonymize(cacheInfo->connectInfo.macAddr, &anonyMacAddr);
    char *anonyUdid = NULL;
    Anonymize(cacheInfo->deviceInfo.deviceUdid, &anonyUdid);
    char *anonyUuid = NULL;
    Anonymize(cacheInfo->uuid, &anonyUuid);
    char *anonyNetworkId = NULL;
    Anonymize(cacheInfo->networkId, &anonyNetworkId);
    char *anonyPublicAddress = NULL;
    Anonymize((char *)cacheInfo->rpaInfo.publicAddress, &anonyPublicAddress);
    LNN_LOGD(LNN_BUILDER,
        "Sync NodeInfo: WIFI_VERSION=%{public}" PRId64 ", BLE_VERSION=%{public}" PRId64
        ", ACCOUNT_ID=%{public}" PRId64 ", TRANSPORT_PROTOCOL=%{public}" PRIu64 ", FEATURE=%{public}" PRIu64
        ", CONN_SUB_FEATURE=%{public}" PRIu64 ", TIMESTAMP=%{public}" PRIu64 ", "
        "P2P_MAC_ADDR=%{public}s, PKG_VERSION=%{public}s, DEVICE_NAME=%{public}s, "
        "UNIFIED_DEFAULT_DEVICE_NAME=%{public}s, UNIFIED_DEVICE_NAME=%{public}s, SETTINGS_NICK_NAME=%{public}s, "
        "AUTH_CAP=%{public}u, OS_TYPE=%{public}d, OS_VERSION=%{public}s, BLE_P2P=%{public}d, BT_MAC=%{public}s, "
        "DEVICE_TYPE=%{public}d, SW_VERSION=%{public}s, DEVICE_UDID=%{public}s, DEVICE_UUID=%{public}s, "
        "NETWORK_ID=%{public}s, STATE_VERSION=%{public}d, BROADCAST_CIPHER_KEY=%{public}02x, "
        "BROADCAST_CIPHER_IV=%{public}02x, IRK=%{public}02x, PUB_MAC=%{public}s, PTK=%{public}02x",
        cacheInfo->wifiVersion, cacheInfo->bleVersion, cacheInfo->accountId, cacheInfo->supportedProtocols,
        cacheInfo->feature, cacheInfo->connSubFeature, cacheInfo->updateTimestamp, anonyP2pMac, cacheInfo->pkgVersion,
        cacheInfo->deviceInfo.deviceName, cacheInfo->deviceInfo.unifiedDefaultName, cacheInfo->deviceInfo.unifiedName,
        cacheInfo->deviceInfo.nickName, cacheInfo->authCapacity, cacheInfo->deviceInfo.osType,
        cacheInfo->deviceInfo.osVersion, cacheInfo->isBleP2p, anonyMacAddr, cacheInfo->deviceInfo.deviceTypeId,
        cacheInfo->softBusVersion, anonyUdid, anonyUuid, anonyNetworkId, cacheInfo->stateVersion,
        *cacheInfo->cipherInfo.key, *cacheInfo->cipherInfo.iv, *cacheInfo->rpaInfo.peerIrk,
        anonyPublicAddress, *cacheInfo->remotePtk);
    AnonymizeFree(anonyP2pMac);
    AnonymizeFree(anonyMacAddr);
    AnonymizeFree(anonyUdid);
    AnonymizeFree(anonyUuid);
    AnonymizeFree(anonyNetworkId);
    AnonymizeFree(anonyPublicAddress);
}

int32_t LnnDBDataChangeSyncToCacheInner(const char *key, const char *value)
{
    if (key == NULL || value == NULL) {
        LNN_LOGE(LNN_BUILDER, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    cJSON *json = cJSON_Parse(value);
    if (json == NULL) {
        LNN_LOGE(LNN_BUILDER, "parse json fail");
        return SOFTBUS_ERR;
    }
    NodeInfo cacheInfo = { 0 };
    if (LnnUnPackCloudSyncDeviceInfo(json, &cacheInfo) != SOFTBUS_OK) {
        cJSON_Delete(json);
        return SOFTBUS_ERR;
    }
    cJSON_Delete(json);
    PrintSyncNodeInfo(&cacheInfo);
    char udidHash[UDID_HASH_HEX_LEN + 1] = { 0 };
    if (LnnGenerateHexStringHash((const unsigned char *)cacheInfo.deviceInfo.deviceUdid, udidHash, UDID_HASH_HEX_LEN) !=
        SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "Generate UDID HexStringHash fail");
        return SOFTBUS_ERR;
    }
    NodeInfo oldCacheInfo = { 0 };
    if (LnnRetrieveDeviceInfo(udidHash, &oldCacheInfo) == SOFTBUS_OK &&
        IsIgnoreUpdate(oldCacheInfo.stateVersion, oldCacheInfo.updateTimestamp, cacheInfo.stateVersion,
            cacheInfo.updateTimestamp)) {
        return SOFTBUS_ERR;
    }
    NodeInfo localCacheInfo = { 0 };
    int32_t ret = LnnGetLocalCacheNodeInfo(&localCacheInfo);
    if (ret != SOFTBUS_OK) {
        return ret;
    }
    cacheInfo.localStateVersion = localCacheInfo.stateVersion;
    (void)LnnSaveRemoteDeviceInfo(&cacheInfo);
    char *anonyUdid = NULL;
    Anonymize(cacheInfo.deviceInfo.deviceUdid, &anonyUdid);
    LNN_LOGI(LNN_BUILDER,
        "success. udid=%{public}s, stateVersion=%{public}d, localStateVersion=%{public}d, updateTimestamp=%{public}"
        "" PRIu64, anonyUdid, cacheInfo.stateVersion, cacheInfo.localStateVersion, cacheInfo.updateTimestamp);
    AnonymizeFree(anonyUdid);
    if (LnnUpdateDistributedNodeInfo(&cacheInfo, cacheInfo.deviceInfo.deviceUdid) != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "fail:Cache info sync to Ledger fail");
        (void)memset_s(&cacheInfo, sizeof(NodeInfo), 0, sizeof(NodeInfo));
        return SOFTBUS_ERR;
    }
    (void)memset_s(&cacheInfo, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    return SOFTBUS_OK;
}

int32_t LnnDBDataChangeSyncToCache(const char *key, const char *value, ChangeType changeType)
{
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
    LNN_LOGD(LNN_BUILDER, "success.");
    return SOFTBUS_OK;
}

int32_t LnnLedgerDataChangeSyncToDB(const char *key, const char *value, size_t valueLength)
{
    if (key == NULL || value == NULL || valueLength > KEY_MAX_LEN - 1) {
        LNN_LOGE(LNN_BUILDER, "fail:Ledger param is invalid.");
        return SOFTBUS_INVALID_PARAM;
    }
    NodeInfo localCaheInfo = { 0 };
    if (LnnGetLocalCacheNodeInfo(&localCaheInfo) != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "get local cache node info fail");
        return SOFTBUS_ERR;
    }
    if (localCaheInfo.accountId == 0) {
        LNN_LOGI(LNN_LEDGER, "no account info. no need sync to DB");
        return SOFTBUS_OK;
    }
    uint64_t nowTime = SoftBusGetSysTimeMs();
    char putKey[KEY_MAX_LEN] = { 0 };
    if (sprintf_s(putKey, KEY_MAX_LEN, "%ld#%s#%s", localCaheInfo.accountId, localCaheInfo.deviceInfo.deviceUdid, key) <
        0) {
        LNN_LOGE(LNN_BUILDER, "sprintf_s key fail");
        return SOFTBUS_ERR;
    }
    char putValue[PUT_VALUE_MAX_LEN] = { 0 };
    if (sprintf_s(putValue, PUT_VALUE_MAX_LEN, "%s#%d#%llu", value, localCaheInfo.stateVersion, nowTime) < 0) {
        LNN_LOGE(LNN_BUILDER, "sprintf_s value fail");
        return SOFTBUS_ERR;
    }

    int32_t dbId = g_dbId;
    int32_t ret = LnnPutDBData(dbId, putKey, strlen(putKey), putValue, strlen(putValue));
    if (ret != 0) {
        LNN_LOGE(LNN_BUILDER, "fail:data sync to DB fail, errorcode=%{public}d", ret);
        return ret;
    }
    LNN_LOGI(LNN_BUILDER, "Lnn ledger %{public}s change sync to DB success. stateVersion=%{public}d", key,
        localCaheInfo.stateVersion);

    ret = LnnCloudSync(dbId);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "fail:data change cloud sync fail, errorcode=%{public}d", ret);
        return ret;
    }
    return SOFTBUS_OK;
}

int32_t LnnLedgerAllDataSyncToDB(NodeInfo *info)
{
    if (info == NULL) {
        LNN_LOGE(LNN_BUILDER, "invalid param, info is NULL");
        return SOFTBUS_INVALID_PARAM;
    }
    if (info->accountId == 0) {
        LNN_LOGI(LNN_BUILDER, "ledger accountid is null, all data no need sync to cloud");
        return SOFTBUS_OK;
    }
    char putKey[KEY_MAX_LEN] = { 0 };
    if (sprintf_s(putKey, KEY_MAX_LEN, "%ld#%s", info->accountId, info->deviceInfo.deviceUdid) < 0) {
        return SOFTBUS_ERR;
    }
    info->updateTimestamp = SoftBusGetSysTimeMs();
    CloudSyncInfo syncInfo = { 0 };
    if (LnnGetLocalBroadcastCipherInfo(&syncInfo) != SOFTBUS_OK) {
        return SOFTBUS_ERR;
    }
    cJSON *json = cJSON_CreateObject();
    if (json == NULL) {
        JSON_Free(syncInfo.broadcastCipherKey);
        return SOFTBUS_ERR;
    }
    if (LnnPackCloudSyncDeviceInfo(json, info) != SOFTBUS_OK) {
        cJSON_Delete(json);
        JSON_Free(syncInfo.broadcastCipherKey);
        return SOFTBUS_ERR;
    }
    if (!AddStringToJsonObject(json, DEVICE_INFO_JSON_BROADCAST_KEY_TABLE, syncInfo.broadcastCipherKey)) {
        cJSON_Delete(json);
        JSON_Free(syncInfo.broadcastCipherKey);
        return SOFTBUS_ERR;
    }
    char *putValue = cJSON_PrintUnformatted(json);
    cJSON_Delete(json);
    int32_t dbId = g_dbId;
    int32_t ret = LnnPutDBData(dbId, putKey, strlen(putKey), putValue, strlen(putValue));
    JSON_Free(syncInfo.broadcastCipherKey);
    if (ret != 0) {
        LNN_LOGE(LNN_BUILDER, "fail:data batch sync to DB fail, errorcode=%{public}d", ret);
        return ret;
    }
    LNN_LOGI(LNN_BUILDER, "sync all data to db success. stateVersion=%{public}d", info->stateVersion);
    ret = LnnCloudSync(dbId);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "fail:data batch cloud sync fail, errorcode=%{public}d", ret);
        return ret;
    }
    return SOFTBUS_OK;
}

int32_t LnnDeleteSyncToDB(void)
{
    NodeInfo localCaheInfo = { 0 };
    if (LnnGetLocalCacheNodeInfo(&localCaheInfo) != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "get local cache node info fail");
        return SOFTBUS_ERR;
    }
    char key[KEY_MAX_LEN] = { 0 };
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
    LNN_LOGI(LNN_BUILDER, "success.");
    ret = LnnCloudSync(dbId);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "fail:data delete cloud sync fail, errorcode=%{public}d", ret);
        return ret;
    }
    return SOFTBUS_OK;
}

void LnnInitCloudSyncModule(void)
{
    LNN_LOGI(LNN_BUILDER, "enter.");
    int32_t dbId = 0;
    if (LnnCreateKvAdapter(&dbId, APPID, strlen(APPID), STOREID, strlen(STOREID)) != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "Lnn Init Cloud Sync Module fail");
        return;
    }
    LnnRegisterDataChangeListener(dbId, APPID, strlen(APPID), STOREID, strlen(STOREID));
    g_dbId = dbId;
}

void LnnDeInitCloudSyncModule(void)
{
    LNN_LOGI(LNN_BUILDER, "enter.");
    int32_t dbId = g_dbId;
    LnnUnRegisterDataChangeListener(dbId);
    if (LnnDestroyKvAdapter(dbId) != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "DeInit Cloud Sync module fail");
    }
    g_dbId = 0;
}
