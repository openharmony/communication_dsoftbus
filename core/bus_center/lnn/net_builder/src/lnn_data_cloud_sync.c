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
#include "lnn_async_callback_utils.h"
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
#include "softbus_error_code.h"
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
        char *anonyDeviceName = NULL;
        Anonymize(cacheInfo->deviceInfo.deviceName, &anonyDeviceName);
        LNN_LOGI(LNN_BUILDER, "success. deviceName=%{public}s", AnonymizeWrapper(anonyDeviceName));
        AnonymizeFree(anonyDeviceName);
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
    int32_t ret = SOFTBUS_OK;
    if (strcmp(fieldName, DEVICE_INFO_DEVICE_UDID) == 0 && valueLength < UDID_BUF_LEN) {
        if (strcpy_s(cacheInfo->deviceInfo.deviceUdid, UDID_BUF_LEN, value) != EOK) {
            LNN_LOGE(LNN_BUILDER, "fail:strcpy_s deviceUdid fail");
            return SOFTBUS_STRCPY_ERR;
        }
        char *anonyUdid = NULL;
        Anonymize(cacheInfo->deviceInfo.deviceUdid, &anonyUdid);
        LNN_LOGI(LNN_BUILDER, "success, udid=%{public}s", AnonymizeWrapper(anonyUdid));
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
        LNN_LOGI(LNN_BUILDER, "success, uuid=%{public}s", AnonymizeWrapper(anoyUuid));
        AnonymizeFree(anoyUuid);
    } else if ((ret = DBDeviceNameInfoSyncToCache(cacheInfo, fieldName, value, valueLength)) != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "fail:DB device name info sync to cache fail");
        return ret;
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
    } else if (strcmp(fieldName, DEVICE_INFO_HB_CAP) == 0) {
        cacheInfo->heartbeatCapacity = (uint32_t)atoi(value);
        LNN_LOGI(LNN_BUILDER, "success. heartbeatCapacity=%{public}u", cacheInfo->heartbeatCapacity);
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
    int32_t ret = SOFTBUS_OK;
    if (strcmp(fieldName, DEVICE_INFO_NETWORK_ID) == 0 && valueLength < NETWORK_ID_BUF_LEN) {
        if (strcpy_s(cacheInfo->networkId, NETWORK_ID_BUF_LEN, value) != EOK) {
            LNN_LOGE(LNN_BUILDER, "fail:strcpy_s networkid fail");
            return SOFTBUS_STRCPY_ERR;
        }
        char *anonyNetworkId = NULL;
        Anonymize(cacheInfo->networkId, &anonyNetworkId);
        LNN_LOGI(LNN_BUILDER, "success. networkId=%{public}s", AnonymizeWrapper(anonyNetworkId));
        AnonymizeFree(anonyNetworkId);
    } else if (strcmp(fieldName, DEVICE_INFO_PKG_VERSION) == 0 && valueLength < VERSION_MAX_LEN) {
        if (strcpy_s(cacheInfo->pkgVersion, VERSION_MAX_LEN, value) != EOK) {
            LNN_LOGE(LNN_BUILDER, "fail:strcpy_s pkgVersion fail");
            return SOFTBUS_STRCPY_ERR;
        }
    } else if (strcmp(fieldName, DEVICE_INFO_SW_VERSION) == 0 && valueLength < VERSION_MAX_LEN) {
        if (strcpy_s(cacheInfo->softBusVersion, VERSION_MAX_LEN, value) != EOK) {
            LNN_LOGE(LNN_BUILDER, "fail:strcpy_s softbusVersion fail");
            return SOFTBUS_STRCPY_ERR;
        }
    } else if ((ret = DBConnectMacInfoSyncToCache(cacheInfo, fieldName, value, valueLength)) != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "fail:DB ConnectMacInfo Sync To Cache fail");
        return ret;
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
    int32_t ret = SOFTBUS_OK;
    if (JudgeFieldNameIsDeviceBasicInfo(fieldName)) {
        ret = DBDeviceBasicInfoSyncToCache(cacheInfo, fieldName, value, valueLength);
        if (ret != SOFTBUS_OK) {
            LNN_LOGE(LNN_BUILDER, "fail:strcpy_s device basic info to cache fail");
            return ret;
        }
    } else if (JudgeFieldNameIsNumInfo(fieldName)) {
        ret = DBNumInfoSyncToCache(cacheInfo, fieldName, value);
        if (ret != SOFTBUS_OK) {
            LNN_LOGE(LNN_BUILDER, "fail:strcpy_s device name fail");
            return ret;
        }
    } else if (JudgeFieldNameIsConnectInfo(fieldName)) {
        ret = DBConnectInfoSyncToCache(cacheInfo, fieldName, value, valueLength);
        if (ret != SOFTBUS_OK) {
            LNN_LOGE(LNN_BUILDER, "fail:strcpy_s connect info fail");
            return ret;
        }
    } else if (JudgeFieldNameIsCipherInfo(fieldName)) {
        ret = DBCipherInfoSyncToCache(cacheInfo, fieldName, value, valueLength, udid);
        if (ret != SOFTBUS_OK) {
            LNN_LOGE(LNN_BUILDER, "fail:strcpy_s cipher info fail");
            return ret;
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
    int32_t ret = SplitKeyOrValue(key, splitKey, SPLIT_KEY_NUM);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "split key error");
        return ret;
    }
    ret = SplitKeyOrValue(value, splitValue, SPLIT_VALUE_NUM);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "split value error");
        return ret;
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
    int32_t ret = SOFTBUS_OK;
    int64_t accountId = 0;
    char deviceUdid[UDID_BUF_LEN] = { 0 };
    char fieldName[FIELDNAME_MAX_LEN] = { 0 };
    CloudSyncValue parseValue = { 0 };
    char splitKey[SPLIT_KEY_NUM][SPLIT_MAX_LEN] = { 0 };
    char splitValue[SPLIT_VALUE_NUM][SPLIT_MAX_LEN] = { 0 };
    ret = SplitString(splitKey, splitValue, key, value, &parseValue);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "split string error");
        return ret;
    }
    ret = GetInfoFromSplitKey(splitKey, &accountId, deviceUdid, fieldName);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "get info from splitkey error");
        return ret;
    }
    char trueValue[SPLIT_MAX_LEN] = { 0 };
    if (strcpy_s(trueValue, SPLIT_MAX_LEN, splitValue[0]) != EOK) {
        LNN_LOGE(LNN_BUILDER, "fail:strcpy_s true value fail.");
        return SOFTBUS_STRCPY_ERR;
    }
    NodeInfo localCacheInfo = { 0 };
    ret = LnnGetLocalCacheNodeInfo(&localCacheInfo);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "get local cache node info fail");
        return ret;
    }
    if (strcmp(deviceUdid, localCacheInfo.deviceInfo.deviceUdid) == 0) {
        return SOFTBUS_OK;
    }
    ret = DBDataChangeBatchSyncToCacheInternal(cacheInfo, fieldName, trueValue, strlen(trueValue), deviceUdid);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "fail:DB data change batch sync to cache fail");
        return ret;
    }
    cacheInfo->localStateVersion = localCacheInfo.stateVersion;
    cacheInfo->updateTimestamp = parseValue.timestamp;
    return SOFTBUS_OK;
}

static int32_t SetDBNameDataToDLedger(NodeInfo *cacheInfo, char *deviceUdid, char *fieldName)
{
    if (strcmp(fieldName, DEVICE_INFO_DEVICE_NAME) == 0) {
        if (!LnnSetDLDeviceInfoName(deviceUdid, cacheInfo->deviceInfo.deviceName)) {
            LNN_LOGE(LNN_BUILDER, "set device name to distributedLedger fail");
            return SOFTBUS_NETWORK_SET_LEDGER_INFO_ERR;
        }
    } else if (strcmp(fieldName, DEVICE_INFO_UNIFIED_DEVICE_NAME) == 0) {
        if (LnnSetDLUnifiedDeviceName(deviceUdid, cacheInfo->deviceInfo.unifiedName) != SOFTBUS_OK) {
            LNN_LOGE(LNN_BUILDER, "set device unifiedName to distributedLedger fail");
            return SOFTBUS_NETWORK_SET_LEDGER_INFO_ERR;
        }
    } else if (strcmp(fieldName, DEVICE_INFO_UNIFIED_DEFAULT_DEVICE_NAME) == 0) {
        if (LnnSetDLUnifiedDefaultDeviceName(deviceUdid, cacheInfo->deviceInfo.unifiedDefaultName) != SOFTBUS_OK) {
            LNN_LOGE(LNN_BUILDER, "set device unifiedDefaultName to distributedLedger fail");
            return SOFTBUS_NETWORK_SET_LEDGER_INFO_ERR;
        }
    } else if (strcmp(fieldName, DEVICE_INFO_SETTINGS_NICK_NAME) == 0) {
        if (LnnSetDLDeviceNickNameByUdid(deviceUdid, cacheInfo->deviceInfo.nickName) != SOFTBUS_OK) {
            LNN_LOGE(LNN_BUILDER, "set device nickName to distributedLedger fail");
            return SOFTBUS_NETWORK_SET_LEDGER_INFO_ERR;
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
    int32_t ret = SOFTBUS_OK;
    if (strcmp(fieldName, DEVICE_INFO_BROADCAST_CIPHER_KEY) == 0) {
        ret = LnnSetDLDeviceBroadcastCipherKey(deviceUdid, cacheInfo->cipherInfo.key);
        if (ret != SOFTBUS_OK) {
            LNN_LOGE(LNN_BUILDER, "set device cipherkey to distributedLedger fail");
            return ret;
        }
    } else if (strcmp(fieldName, DEVICE_INFO_BROADCAST_CIPHER_IV) == 0) {
        ret = LnnSetDLDeviceBroadcastCipherIv(deviceUdid, cacheInfo->cipherInfo.iv);
        if (ret != SOFTBUS_OK) {
            LNN_LOGE(LNN_BUILDER, "set device cipheriv to distributedLedger fail");
            return ret;
        }
    } else if (strcmp(fieldName, DEVICE_INFO_NETWORK_ID) == 0) {
        ret = LnnUpdateNetworkId(cacheInfo);
        if (ret != SOFTBUS_OK) {
            LNN_LOGE(LNN_BUILDER, "set device networkId to distributedLedger fail");
            return ret;
        }
    } else if (strcmp(fieldName, DEVICE_INFO_STATE_VERSION) == 0) {
        ret = LnnSetDLDeviceStateVersion(deviceUdid, cacheInfo->stateVersion);
        if (ret != SOFTBUS_OK) {
            LNN_LOGE(LNN_BUILDER, "set device stateversion to distributedLedger fail");
            return ret;
        }
    } else if ((ret = SetDBNameDataToDLedger(cacheInfo, deviceUdid, fieldName)) != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "set DB name data to distributedLedger fail");
        return ret;
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
        return SOFTBUS_NETWORK_GENERATE_STR_HASH_ERR;
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

static void PrintDeviceUdidAndTrueValue(char *deviceUdid, char *fieldName, char *trueValue, int32_t stateVersion)
{
    char *anonyDeviceUdid = NULL;
    Anonymize(deviceUdid, &anonyDeviceUdid);
    char *anonyTrueValue = NULL;
    Anonymize(trueValue, &anonyTrueValue);
    LNN_LOGI(LNN_BUILDER,
        "deviceUdid=%{public}s, fieldName=%{public}s update to %{public}s success, stateVersion=%{public}d",
        AnonymizeWrapper(anonyDeviceUdid), fieldName, AnonymizeWrapper(anonyTrueValue), stateVersion);
    AnonymizeFree(anonyDeviceUdid);
    AnonymizeFree(anonyTrueValue);
}

static int32_t HandleDBUpdateChangeInternal(const char *key, const char *value)
{
    if (key == NULL || value == NULL) {
        LNN_LOGE(LNN_BUILDER, "fail:invalid param.");
        return SOFTBUS_INVALID_PARAM;
    }
    int32_t ret = SOFTBUS_OK;
    int64_t accountId = 0;
    char deviceUdid[UDID_BUF_LEN] = { 0 };
    char fieldName[FIELDNAME_MAX_LEN] = { 0 };
    CloudSyncValue parseValue = { 0 };
    char splitKey[SPLIT_KEY_NUM][SPLIT_MAX_LEN] = { 0 };
    char splitValue[SPLIT_VALUE_NUM][SPLIT_MAX_LEN] = { 0 };
    if (SplitString(splitKey, splitValue, key, value, &parseValue) != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "split string error");
        return SOFTBUS_SPLIT_STRING_FAIL;
    }
    ret = GetInfoFromSplitKey(splitKey, &accountId, deviceUdid, fieldName);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "get info from splitkey error");
        return ret;
    }
    NodeInfo localCacheInfo = { 0 };
    ret = LnnGetLocalCacheNodeInfo(&localCacheInfo);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "get local cache node info fail");
        return ret;
    }
    if (strcmp(deviceUdid, localCacheInfo.deviceInfo.deviceUdid) == 0) {
        return SOFTBUS_OK;
    }
    char trueValue[SPLIT_MAX_LEN] = { 0 };
    if (strcpy_s(trueValue, SPLIT_MAX_LEN, splitValue[0]) != EOK) {
        LNN_LOGE(LNN_BUILDER, "fail:strcpy_s true value fail.");
        return SOFTBUS_STRCPY_ERR;
    }
    ret = HandleDBUpdateInternal(deviceUdid, fieldName, trueValue, &parseValue, localCacheInfo.stateVersion);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "handle DB update change internal fail");
        (void)memset_s(trueValue, strlen(trueValue), 0, strlen(trueValue));
        return ret;
    }
    PrintDeviceUdidAndTrueValue(deviceUdid, fieldName, trueValue, parseValue.stateVersion);
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
    int32_t ret = SplitKeyOrValue(key, splitKey, SPLIT_KEY_NUM);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "split key error");
        return ret;
    }
    ret = GetInfoFromSplitKey(splitKey, &accountId, deviceUdid, fieldName);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "get info from splitkey error");
        return ret;
    }
    char udidHash[UDID_HASH_HEX_LEN + 1] = { 0 };
    if (LnnGenerateHexStringHash((const unsigned char *)deviceUdid, udidHash, UDID_HASH_HEX_LEN) != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "Generate UDID HexStringHash fail");
        return SOFTBUS_NETWORK_GENERATE_STR_HASH_ERR;
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

static int32_t CheckParamValidity(const char **key, const char **value, int32_t keySize)
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
    return SOFTBUS_OK;
}

int32_t LnnDBDataAddChangeSyncToCache(const char **key, const char **value, int32_t keySize)
{
    int32_t ret = CheckParamValidity(key, value, keySize);
    if (ret != SOFTBUS_OK) {
        return ret;
    }
    NodeInfo cacheInfo = { 0 };
    for (int32_t i = 0; i < keySize; i++) {
        ret = HandleDBAddChangeInternal(key[i], value[i], &cacheInfo);
        if (ret != SOFTBUS_OK) {
            LNN_LOGE(LNN_BUILDER, "fail:handle db data add change internal fail");
            FreeKeyAndValue(key, value, keySize);
            (void)memset_s(&cacheInfo, sizeof(NodeInfo), 0, sizeof(NodeInfo));
            return ret;
        }
    }
    FreeKeyAndValue(key, value, keySize);
    char udidHash[UDID_HASH_HEX_LEN + 1] = { 0 };
    if (LnnGenerateHexStringHash((const unsigned char *)cacheInfo.deviceInfo.deviceUdid, udidHash, UDID_HASH_HEX_LEN) !=
        SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "Generate UDID HexStringHash fail");
        return SOFTBUS_NETWORK_GENERATE_STR_HASH_ERR;
    }
    NodeInfo oldCacheInfo = { 0 };
    if (LnnRetrieveDeviceInfo(udidHash, &oldCacheInfo) == SOFTBUS_OK &&
        IsIgnoreUpdate(oldCacheInfo.stateVersion, oldCacheInfo.updateTimestamp, cacheInfo.stateVersion,
            cacheInfo.updateTimestamp)) {
        return SOFTBUS_KV_IGNORE_OLD_DEVICE_INFO;
    }
    (void)LnnSaveRemoteDeviceInfo(&cacheInfo);
    char *anonyUdid = NULL;
    Anonymize(cacheInfo.deviceInfo.deviceUdid, &anonyUdid);
    LNN_LOGI(LNN_BUILDER,
        "success. udid=%{public}s, stateVersion=%{public}d, localStateVersion=%{public}d, updateTimestamp=%{public}"
        "" PRIu64, AnonymizeWrapper(anonyUdid), cacheInfo.stateVersion, cacheInfo.localStateVersion,
        cacheInfo.updateTimestamp);
    AnonymizeFree(anonyUdid);
    ret = LnnUpdateDistributedNodeInfo(&cacheInfo, cacheInfo.deviceInfo.deviceUdid);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "fail:Cache info add sync to Ledger fail");
        (void)memset_s(&cacheInfo, sizeof(NodeInfo), 0, sizeof(NodeInfo));
        return ret;
    }
    (void)memset_s(&cacheInfo, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    return SOFTBUS_OK;
}

static void PrintSyncNodeInfo(const NodeInfo *cacheInfo)
{
    LNN_CHECK_AND_RETURN_LOGE(cacheInfo != NULL, LNN_BUILDER, "invalid param");
    char accountId[INT64_TO_STR_MAX_LEN] = {0};
    if (!Int64ToString(cacheInfo->accountId, accountId, INT64_TO_STR_MAX_LEN)) {
        LNN_LOGE(LNN_BUILDER, "accountId to str fail");
    }
    char *anonyAccountId = NULL;
    Anonymize(accountId, &anonyAccountId);
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
    char *anonyDeviceVersion = NULL;
    Anonymize(cacheInfo->deviceInfo.deviceVersion, &anonyDeviceVersion);
    char *anonyDeviceName = NULL;
    Anonymize(cacheInfo->deviceInfo.deviceName, &anonyDeviceName);
    LNN_LOGI(LNN_BUILDER,
        "Sync NodeInfo: WIFI_VERSION=%{public}" PRId64 ", BLE_VERSION=%{public}" PRId64
        ", ACCOUNT_ID=%{public}s, TRANSPORT_PROTOCOL=%{public}" PRIu64 ", FEATURE=%{public}" PRIu64
        ", CONN_SUB_FEATURE=%{public}" PRIu64 ", TIMESTAMP=%{public}" PRIu64 ", "
        "P2P_MAC_ADDR=%{public}s, PKG_VERSION=%{public}s, DEVICE_NAME=%{public}s, AUTH_CAP=%{public}u, "
        "HB_CAP=%{public}u, OS_TYPE=%{public}d, OS_VERSION=%{public}s, BLE_P2P=%{public}d, BT_MAC=%{public}s, "
        "DEVICE_TYPE=%{public}d, SW_VERSION=%{public}s, DEVICE_UDID=%{public}s, DEVICE_UUID=%{public}s, "
        "NETWORK_ID=%{public}s, STATE_VERSION=%{public}d, BROADCAST_CIPHER_KEY=%{public}02x, "
        "BROADCAST_CIPHER_IV=%{public}02x, IRK=%{public}02x, PUB_MAC=%{public}02x, PTK=%{public}02x, "
        "DEVICE_VERSION=%{public}s",
        cacheInfo->wifiVersion, cacheInfo->bleVersion, AnonymizeWrapper(anonyAccountId), cacheInfo->supportedProtocols,
        cacheInfo->feature, cacheInfo->connSubFeature, cacheInfo->updateTimestamp, AnonymizeWrapper(anonyP2pMac),
        cacheInfo->pkgVersion, AnonymizeWrapper(anonyDeviceName), cacheInfo->authCapacity,
        cacheInfo->heartbeatCapacity, cacheInfo->deviceInfo.osType, cacheInfo->deviceInfo.osVersion,
        cacheInfo->isBleP2p, AnonymizeWrapper(anonyMacAddr), cacheInfo->deviceInfo.deviceTypeId,
        cacheInfo->softBusVersion, AnonymizeWrapper(anonyUdid), AnonymizeWrapper(anonyUuid),
        AnonymizeWrapper(anonyNetworkId), cacheInfo->stateVersion, *cacheInfo->cipherInfo.key,
        *cacheInfo->cipherInfo.iv, *cacheInfo->rpaInfo.peerIrk, *cacheInfo->rpaInfo.publicAddress,
        *cacheInfo->remotePtk, AnonymizeWrapper(anonyDeviceVersion));
    AnonymizeFree(anonyAccountId);
    AnonymizeFree(anonyP2pMac);
    AnonymizeFree(anonyMacAddr);
    AnonymizeFree(anonyUdid);
    AnonymizeFree(anonyUuid);
    AnonymizeFree(anonyNetworkId);
    AnonymizeFree(anonyDeviceVersion);
    AnonymizeFree(anonyDeviceName);
}

static void UpdateDevBasicInfoToCache(const NodeInfo *newInfo, NodeInfo *oldInfo)
{
    if (strcpy_s(oldInfo->deviceInfo.deviceName, DEVICE_NAME_BUF_LEN, newInfo->deviceInfo.deviceName) != EOK) {
        LNN_LOGE(LNN_LEDGER, "strcpy_s deviceName to cache info fail");
    }
    if (strcpy_s(oldInfo->deviceInfo.unifiedName, DEVICE_NAME_BUF_LEN, newInfo->deviceInfo.unifiedName) != EOK) {
        LNN_LOGE(LNN_LEDGER, "strcpy_s unifiedName to cache info fail");
    }
    if (strcpy_s(oldInfo->deviceInfo.unifiedDefaultName, DEVICE_NAME_BUF_LEN, newInfo->deviceInfo.unifiedDefaultName) !=
        EOK) {
        LNN_LOGE(LNN_LEDGER, "strcpy_s unifiedDefaultName to cache info fail");
    }
    if (strcpy_s(oldInfo->deviceInfo.nickName, DEVICE_NAME_BUF_LEN, newInfo->deviceInfo.nickName) != EOK) {
        LNN_LOGE(LNN_LEDGER, "strcpy_s nickName to cache info fail");
    }
    if (strcpy_s(oldInfo->deviceInfo.deviceUdid, UDID_BUF_LEN, newInfo->deviceInfo.deviceUdid) != EOK) {
        LNN_LOGE(LNN_LEDGER, "strcpy_s deviceUdid to cache info fail");
    }
    if (strcpy_s(oldInfo->deviceInfo.deviceVersion, DEVICE_VERSION_SIZE_MAX, newInfo->deviceInfo.deviceVersion) !=
        EOK) {
        LNN_LOGE(LNN_LEDGER, "strcpy_s deviceVersion to cache info fail");
    }
    if (strcpy_s(oldInfo->uuid, UUID_BUF_LEN, newInfo->uuid) != EOK) {
        LNN_LOGE(LNN_LEDGER, "strcpy_s uuid to cache info fail");
    }
    if (strcpy_s(oldInfo->networkId, NETWORK_ID_BUF_LEN, newInfo->networkId) != EOK) {
        LNN_LOGE(LNN_LEDGER, "strcpy_s networkid to cache info fail");
    }
    oldInfo->deviceInfo.deviceTypeId = newInfo->deviceInfo.deviceTypeId;
    oldInfo->isBleP2p = newInfo->isBleP2p;
    oldInfo->supportedProtocols = newInfo->supportedProtocols;
    oldInfo->wifiVersion = newInfo->wifiVersion;
    oldInfo->bleVersion = newInfo->bleVersion;
    oldInfo->accountId = newInfo->accountId;
    oldInfo->feature = newInfo->feature;
    oldInfo->connSubFeature = newInfo->connSubFeature;
    oldInfo->authCapacity = newInfo->authCapacity;
    oldInfo->deviceInfo.osType = newInfo->deviceInfo.osType;
    oldInfo->stateVersion = newInfo->stateVersion;
    oldInfo->updateTimestamp = newInfo->updateTimestamp;
    oldInfo->deviceSecurityLevel = newInfo->deviceSecurityLevel;
    oldInfo->localStateVersion = newInfo->localStateVersion;
    oldInfo->heartbeatCapacity = newInfo->heartbeatCapacity;
}

static int32_t LnnUpdateOldCacheInfo(const NodeInfo *newInfo, NodeInfo *oldInfo)
{
    if (newInfo == NULL || oldInfo == NULL) {
        LNN_LOGE(LNN_LEDGER, "param error");
        return SOFTBUS_INVALID_PARAM;
    }
    if (strcpy_s(oldInfo->softBusVersion, VERSION_MAX_LEN, newInfo->softBusVersion) != EOK) {
        LNN_LOGE(LNN_LEDGER, "strcpy_s softBusVersion to cache info fail");
    }
    if (strcpy_s(oldInfo->pkgVersion, VERSION_MAX_LEN, newInfo->pkgVersion) != EOK) {
        LNN_LOGE(LNN_LEDGER, "strcpy_s pkgVersion to cache info fail");
    }
    if (strcpy_s(oldInfo->connectInfo.macAddr, MAC_LEN, newInfo->connectInfo.macAddr) != EOK) {
        LNN_LOGE(LNN_LEDGER, "strcpy_s macAddr to cache info fail");
    }
    if (strcpy_s(oldInfo->deviceInfo.osVersion, OS_VERSION_BUF_LEN, newInfo->deviceInfo.osVersion) != EOK) {
        LNN_LOGE(LNN_LEDGER, "strcpy_s osVersion to cache info fail");
    }
    if (strcpy_s(oldInfo->p2pInfo.p2pMac, MAC_LEN, newInfo->p2pInfo.p2pMac) != EOK) {
        LNN_LOGE(LNN_LEDGER, "strcpy_s p2pMac to cache info fail");
    }
    if (memcpy_s((char *)oldInfo->rpaInfo.peerIrk, LFINDER_IRK_LEN, (char *)newInfo->rpaInfo.peerIrk,
        LFINDER_IRK_LEN) != EOK) {
        LNN_LOGE(LNN_LEDGER, "memcpy_s peerIrk to cache info fail");
    }
    if (memcpy_s((char *)oldInfo->rpaInfo.publicAddress, LFINDER_MAC_ADDR_LEN, (char *)newInfo->rpaInfo.publicAddress,
        LFINDER_MAC_ADDR_LEN) != EOK) {
        LNN_LOGE(LNN_LEDGER, "memcpy_s publicAddress to cache info fail");
    }
    if (memcpy_s((char *)oldInfo->cipherInfo.key, SESSION_KEY_LENGTH, newInfo->cipherInfo.key, SESSION_KEY_LENGTH) !=
        EOK) {
        LNN_LOGE(LNN_LEDGER, "memcpy_s cipherInfo key to cache info fail");
    }
    if (memcpy_s((char *)oldInfo->cipherInfo.iv, BROADCAST_IV_LEN, newInfo->cipherInfo.iv, BROADCAST_IV_LEN) != EOK) {
        LNN_LOGE(LNN_LEDGER, "memcpy_s cipherInfo iv to cache info fail");
    }
    if (memcpy_s(oldInfo->remotePtk, PTK_DEFAULT_LEN, newInfo->remotePtk, PTK_DEFAULT_LEN) != EOK) {
        LNN_LOGE(LNN_LEDGER, "memcpy_s remotePtk to cache info fail");
    }
    UpdateDevBasicInfoToCache(newInfo, oldInfo);
    return SOFTBUS_OK;
}

static int32_t LnnSaveAndUpdateDistributedNode(NodeInfo *cacheInfo, NodeInfo *oldCacheInfo)
{
    if (cacheInfo == NULL || oldCacheInfo == NULL) {
        LNN_LOGE(LNN_BUILDER, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    NodeInfo localCacheInfo = { 0 };
    int32_t ret = LnnGetLocalCacheNodeInfo(&localCacheInfo);
    if (ret != SOFTBUS_OK || cacheInfo->accountId != localCacheInfo.accountId) {
        char accountId[INT64_TO_STR_MAX_LEN] = {0};
        char localAccountId[INT64_TO_STR_MAX_LEN] = {0};
        if (!Int64ToString(cacheInfo->accountId, accountId, INT64_TO_STR_MAX_LEN)) {
            LNN_LOGE(LNN_BUILDER, "accountId to str fail");
        }
        if (!Int64ToString(localCacheInfo.accountId, localAccountId, INT64_TO_STR_MAX_LEN)) {
            LNN_LOGE(LNN_BUILDER, "local accountId to str fail");
        }
        char *anonyAccountId = NULL;
        char *anonyLocalAccountId = NULL;
        Anonymize(accountId, &anonyAccountId);
        Anonymize(localAccountId, &anonyLocalAccountId);
        LNN_LOGE(LNN_BUILDER, "don't set, ret=%{public}d, accountId=%{public}s, local accountId=%{public}s",
            ret, AnonymizeWrapper(anonyAccountId), AnonymizeWrapper(anonyLocalAccountId));
        AnonymizeFree(anonyAccountId);
        AnonymizeFree(anonyLocalAccountId);
        return ret;
    }
    cacheInfo->localStateVersion = localCacheInfo.stateVersion;
    if (LnnUpdateOldCacheInfo(cacheInfo, oldCacheInfo) != SOFTBUS_OK ||
        LnnSaveRemoteDeviceInfo(oldCacheInfo) != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "update cache info fail, use cloud sync data");
        (void)LnnSaveRemoteDeviceInfo(cacheInfo);
    }
    char *anonyUdid = NULL;
    Anonymize(cacheInfo->deviceInfo.deviceUdid, &anonyUdid);
    LNN_LOGI(LNN_BUILDER,
        "success. udid=%{public}s, stateVersion=%{public}d, localStateVersion=%{public}d, updateTimestamp=%{public}"
        "" PRIu64, AnonymizeWrapper(anonyUdid), cacheInfo->stateVersion,
        cacheInfo->localStateVersion, cacheInfo->updateTimestamp);
    AnonymizeFree(anonyUdid);
    if (LnnUpdateDistributedNodeInfo(cacheInfo, cacheInfo->deviceInfo.deviceUdid) != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "fail:Cache info sync to Ledger fail");
        return SOFTBUS_MEM_ERR;
    }
    return SOFTBUS_OK;
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
        return SOFTBUS_PARSE_JSON_ERR;
    }
    NodeInfo cacheInfo = { 0 };
    int32_t ret = LnnUnPackCloudSyncDeviceInfo(json, &cacheInfo);
    if (ret != SOFTBUS_OK) {
        cJSON_Delete(json);
        return ret;
    }
    cJSON_Delete(json);
    PrintSyncNodeInfo(&cacheInfo);
    char udidHash[UDID_HASH_HEX_LEN + 1] = { 0 };
    if (LnnGenerateHexStringHash((const unsigned char *)cacheInfo.deviceInfo.deviceUdid, udidHash, UDID_HASH_HEX_LEN) !=
        SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "Generate UDID HexStringHash fail");
        return SOFTBUS_NETWORK_GENERATE_STR_HASH_ERR;
    }
    NodeInfo oldCacheInfo = { 0 };
    if (LnnRetrieveDeviceInfo(udidHash, &oldCacheInfo) == SOFTBUS_OK &&
        IsIgnoreUpdate(oldCacheInfo.stateVersion, oldCacheInfo.updateTimestamp, cacheInfo.stateVersion,
            cacheInfo.updateTimestamp)) {
        return SOFTBUS_KV_IGNORE_OLD_DEVICE_INFO;
    }
    ret = LnnSaveAndUpdateDistributedNode(&cacheInfo, &oldCacheInfo);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "save and update distribute node info fail");
        (void)memset_s(&cacheInfo, sizeof(NodeInfo), 0, sizeof(NodeInfo));
        return ret;
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
                return ret;
            }
            break;
        case DB_DELETE:
            ret = HandleDBDeleteChangeInternal(key, value);
            if (ret != SOFTBUS_OK) {
                LNN_LOGE(LNN_BUILDER, "fail:handle db data delete change internal fail");
                return ret;
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
    NodeInfo localCacheInfo = { 0 };
    int32_t ret = LnnGetLocalCacheNodeInfo(&localCacheInfo);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "get local cache node info fail");
        return ret;
    }
    if (localCacheInfo.accountId == 0) {
        LNN_LOGI(LNN_LEDGER, "no account info. no need sync to DB");
        return SOFTBUS_OK;
    }
    uint64_t nowTime = SoftBusGetSysTimeMs();
    char putKey[KEY_MAX_LEN] = { 0 };
    if (sprintf_s(putKey, KEY_MAX_LEN, "%ld#%s#%s", localCacheInfo.accountId, localCacheInfo.deviceInfo.deviceUdid,
        key) < 0) {
        LNN_LOGE(LNN_BUILDER, "sprintf_s key fail");
        return SOFTBUS_SPRINTF_ERR;
    }
    char putValue[PUT_VALUE_MAX_LEN] = { 0 };
    if (sprintf_s(putValue, PUT_VALUE_MAX_LEN, "%s#%d#%llu", value, localCacheInfo.stateVersion, nowTime) < 0) {
        LNN_LOGE(LNN_BUILDER, "sprintf_s value fail");
        return SOFTBUS_SPRINTF_ERR;
    }

    int32_t dbId = g_dbId;
    ret = LnnPutDBData(dbId, putKey, strlen(putKey), putValue, strlen(putValue));
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "fail:data sync to DB fail, errorcode=%{public}d", ret);
        return ret;
    }
    LNN_LOGI(LNN_BUILDER, "Lnn ledger %{public}s change sync to DB success. stateVersion=%{public}d", key,
        localCacheInfo.stateVersion);

    ret = LnnCloudSync(dbId);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "fail:data change cloud sync fail, errorcode=%{public}d", ret);
        return ret;
    }
    return SOFTBUS_OK;
}

static int32_t PackBroadcastCipherKeyInner(cJSON *json, NodeInfo *info)
{
    if (LnnPackCloudSyncDeviceInfo(json, info) != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "pack cloud sync info fail");
        return SOFTBUS_KV_CLOUD_SYNC_FAIL;
    }
    CloudSyncInfo syncInfo = { 0 };
    if (LnnGetLocalBroadcastCipherInfo(&syncInfo) != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "get local cipher info fail");
        return SOFTBUS_KV_CLOUD_SYNC_FAIL;
    }
    if (!AddStringToJsonObject(json, DEVICE_INFO_JSON_BROADCAST_KEY_TABLE, syncInfo.broadcastCipherKey)) {
        JSON_Free(syncInfo.broadcastCipherKey);
        LNN_LOGE(LNN_BUILDER, "add string info fail");
        return SOFTBUS_KV_CLOUD_SYNC_FAIL;
    }
    JSON_Free(syncInfo.broadcastCipherKey);
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
        return SOFTBUS_KV_CLOUD_DISABLED;
    }
    char putKey[KEY_MAX_LEN] = { 0 };
    if (sprintf_s(putKey, KEY_MAX_LEN, "%ld#%s", info->accountId, info->deviceInfo.deviceUdid) < 0) {
        return SOFTBUS_MEM_ERR;
    }
    info->updateTimestamp = SoftBusGetSysTimeMs();
    cJSON *json = cJSON_CreateObject();
    if (json == NULL) {
        return SOFTBUS_CREATE_JSON_ERR;
    }
    int32_t ret = PackBroadcastCipherKeyInner(json, info);
    if (ret != SOFTBUS_OK) {
        cJSON_Delete(json);
        return ret;
    }
    char *putValue = cJSON_PrintUnformatted(json);
    if (putValue == NULL) {
        LNN_LOGE(LNN_BUILDER, "cJSON_PrintUnformatted fail");
        cJSON_Delete(json);
        return SOFTBUS_CREATE_JSON_ERR;
    }
    cJSON_Delete(json);
    int32_t dbId = g_dbId;
    LnnSetCloudAbility(true);
    ret = LnnPutDBData(dbId, putKey, strlen(putKey), putValue, strlen(putValue));
    cJSON_free(putValue);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "fail:data batch sync to DB fail, errorcode=%{public}d", ret);
        return SOFTBUS_KV_PUT_DB_FAIL;
    }
    LNN_LOGI(LNN_BUILDER, "sync all data to db success. stateVersion=%{public}d", info->stateVersion);
    ret = LnnCloudSync(dbId);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "fail:data batch cloud sync fail, errorcode=%{public}d", ret);
    }
    return ret;
}

static void ProcessSyncToDB(void *para)
{
    NodeInfo *info = (NodeInfo *)para;
    (void)LnnLedgerAllDataSyncToDB(info);
    SoftBusFree(info);
}

int32_t LnnAsyncCallLedgerAllDataSyncToDB(NodeInfo *info)
{
    if (info == NULL) {
        LNN_LOGE(LNN_LANE, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    NodeInfo *data = (NodeInfo *)SoftBusCalloc(sizeof(NodeInfo));
    if (data == NULL) {
        LNN_LOGE(LNN_LANE, "calloc mem fail!");
        return SOFTBUS_MALLOC_ERR;
    }
    *data = *info;
    int32_t rc = LnnAsyncCallbackHelper(GetLooper(LOOP_TYPE_LNN), ProcessSyncToDB, data);
    if (rc != SOFTBUS_OK) {
        SoftBusFree(data);
        return rc;
    }
    return rc;
}

int32_t LnnDeleteSyncToDB(void)
{
    NodeInfo localCacheInfo = { 0 };
    int32_t ret = LnnGetLocalCacheNodeInfo(&localCacheInfo);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "get local cache node info fail");
        return ret;
    }
    char key[KEY_MAX_LEN] = { 0 };
    if (sprintf_s(key, KEY_MAX_LEN, "%ld#%s", localCacheInfo.accountId, localCacheInfo.deviceInfo.deviceUdid) < 0) {
        LNN_LOGE(LNN_BUILDER, "sprintf_s key fail");
        return SOFTBUS_SPRINTF_ERR;
    }

    int32_t dbId = g_dbId;
    ret = LnnDeleteDBDataByPrefix(dbId, key, strlen(key));
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

int32_t LnnDeleteDevInfoSyncToDB(const char *udid, int64_t accountId)
{
    if (udid == NULL) {
        LNN_LOGE(LNN_LANE, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    char key[KEY_MAX_LEN] = { 0 };
    if (sprintf_s(key, KEY_MAX_LEN, "%ld#%s", accountId, udid) < 0) {
        LNN_LOGE(LNN_BUILDER, "sprintf_s key fail");
        return SOFTBUS_SPRINTF_ERR;
    }
    int32_t dbId = g_dbId;
    int32_t ret = LnnDeleteDBDataByPrefix(dbId, key, strlen(key));
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "fail:data delete sync to DB fail");
        return ret;
    }
    ret = LnnCloudSync(dbId);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "fail:data delete cloud sync fail, errorcode=%{public}d", ret);
        return ret;
    }
    char *anonyUdid = NULL;
    Anonymize(udid, &anonyUdid);
    LNN_LOGI(LNN_BUILDER, "delete udid=%{public}s success.", AnonymizeWrapper(anonyUdid));
    AnonymizeFree(anonyUdid);
    return SOFTBUS_OK;
}

int32_t LnnSetCloudAbility(const bool isEnableCloud)
{
    LNN_LOGI(LNN_BUILDER, "enter.");
    int32_t dbId = 0;
    dbId = g_dbId;
    int32_t ret = LnnSetCloudAbilityInner(dbId, isEnableCloud);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "set cloud ability fail");
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
