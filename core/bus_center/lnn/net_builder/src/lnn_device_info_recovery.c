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

#include "lnn_device_info_recovery.h"

#include "stdlib.h"
#include <securec.h>

#include "lnn_node_info.h"
#include "lnn_map.h"
#include "lnn_secure_storage.h"
#include "softbus_adapter_thread.h"
#include "softbus_errcode.h"
#include "softbus_json_utils.h"
#include "softbus_log.h"
#include "softbus_adapter_mem.h"

#define DEVICE_INFO_P2P_MAC_ADDR "P2P_MAC_ADDR"
#define DEVICE_INFO_DEVICE_NAME "DEVICE_NAME"
#define DEVICE_INFO_SETTINGS_NICK_NAME "SETTINGS_NICK_NAME"
#define UNIFIED_DEFAULT_DEVICE_NAME "UNIFIED_DEFAULT_DEVICE_NAME"
#define UNIFIED_DEVICE_NAME "UNIFIED_DEVICE_NAME"
#define DEVICE_INFO_DEVICE_TYPE "DEVICE_TYPE"
#define DEVICE_INFO_VERSION_TYPE "VERSION_TYPE"
#define DEVICE_INFO_SW_VERSION "SW_VERSION"
#define DEVICE_INFO_PKG_VERSION "PKG_VERSION"
#define DEVICE_INFO_DEVICE_UDID "DEVICE_UDID"
#define DEVICE_INFO_DEVICE_UUID "DEVICE_UUID"
#define DEVICE_INFO_WIFI_VERSION "WIFI_VERSION"
#define DEVICE_INFO_BLE_VERSION "BLE_VERSION"
#define DEVICE_INFO_CONNECT_INFO "CONNECT_INFO"
#define DEVICE_INFO_BT_MAC "BT_MAC"
#define DEVICE_INFO_BR_MAC_ADDR "BR_MAC_ADDR"
#define DEVICE_INFO_HML_MAC "HML_MAC"
#define DEVICE_INFO_REMAIN_POWER "REMAIN_POWER"
#define DEVICE_INFO_IS_CHARGING "IS_CHARGING"
#define DEVICE_INFO_IS_SCREENON "IS_SCREENON"
#define DEVICE_INFO_IP_MAC "IP_MAC"
#define DEVICE_INFO_P2P_ROLE "P2P_ROLE"
#define DEVICE_INFO_NETWORK_ID "NETWORK_ID"
#define DEVICE_INFO_NODE_WEIGHT "NODE_WEIGHT"
#define DEVICE_INFO_ACCOUNT_ID "ACCOUNT_ID"
#define DEVICE_INFO_DISTRIBUTED_SWITCH "DISTRIBUTED_SWITCH"
#define DEVICE_INFO_TRANSPORT_PROTOCOL "TRANSPORT_PROTOCOL"
#define DEVICE_INFO_TRANS_FLAGS "TRANS_FLAGS"
#define DEVICE_INFO_BLE_P2P "BLE_P2P"
#define DEVICE_INFO_BLE_TIMESTAMP "BLE_TIMESTAMP"
#define DEVICE_INFO_WIFI_BUFF_SIZE "WIFI_BUFF_SIZE"
#define DEVICE_INFO_BR_BUFF_SIZE "BR_BUFF_SIZE"
#define DEVICE_INFO_FEATURE "FEATURE"
#define DEVICE_INFO_META_INFO_JSON_TAG "MetaNodeInfoOfEar"
#define DEVICE_INFO_CONN_CAP "CONN_CAP"
#define DEVICE_INFO_NEW_CONN_CAP "NEW_CONN_CAP"
#define DEVICE_INFO_EXTDATA "EXTDATA"
#define DEVICE_INFO_STATE_VERSION "STATE_VERSION"
#define DEVICE_INFO_LOCAL_STATE_VERSION "LOCAL_STATE_VERSION"
#define DEVICE_INFO_BD_KEY "BD_KEY"
#define DEVICE_INFO_BDKEY_TIME "BDKEY_TIME"
#define DEVICE_INFO_IV "IV"
#define DEVICE_INFO_IV_TIME "IV_TIME"
#define DEVICE_INFO_NETWORK_ID_TIMESTAMP "NETWORK_ID_TIMESTAMP"

#define INT64_TO_STR_MAX_LEN 21
#define STRTOLL_BASE 10

static Map g_deviceInfoMap;
static SoftBusMutex g_deviceInfoMutex;
static bool g_isInit = false;
static NodeInfo g_localNodeInfo;

static bool DeviceInfoRecoveryInit(void)
{
    if (SoftBusMutexInit(&g_deviceInfoMutex, NULL) != SOFTBUS_OK) {
        LLOGE("deviceKey mutex init fail");
        return false;
    }
    LnnMapInit(&g_deviceInfoMap);
    g_isInit = true;
    return true;
}

static int32_t DeviceMapLock(void)
{
    if (!g_isInit) {
        if (!DeviceInfoRecoveryInit()) {
            return SOFTBUS_ERR;
        }
    }
    return SoftBusMutexLock(&g_deviceInfoMutex);
}

static void DeviceMapUnLock(void)
{
    if (!g_isInit) {
        (void)DeviceInfoRecoveryInit();
        return;
    }
    (void)SoftBusMutexUnlock(&g_deviceInfoMutex);
}

static bool ConvertInt64ToStr(int64_t src, char *buf, uint32_t bufLen)
{
    if (buf == NULL) {
        return false;
    }
    if (sprintf_s(buf, bufLen, "%" PRId64 "", src) < 0) {
        LLOGE("convert int64 to string fail");
        return false;
    }
    return true;
}

static void AddInt64ToJsonByStringFormat(cJSON *json, const char *key, int64_t num)
{
    char buff[INT64_TO_STR_MAX_LEN] = {0};
    if (!ConvertInt64ToStr(num, buff, INT64_TO_STR_MAX_LEN)) {
        return;
    }
    if (buff[INT64_TO_STR_MAX_LEN - 1] != '\0') {
        LLOGE("string id invalid");
        return;
    }
    if (!AddStringToJsonObject(json, key, buff)) {
        LLOGE("add int64Item to json fail, key:%s", key);
        return;
    }
}

static bool PackDeviceInfoItemInt64(cJSON *json, const NodeInfo *deviceInfo)
{
    AddInt64ToJsonByStringFormat(json, DEVICE_INFO_WIFI_VERSION, deviceInfo->wifiVersion);
    AddInt64ToJsonByStringFormat(json, DEVICE_INFO_BLE_VERSION, deviceInfo->bleVersion);
    AddInt64ToJsonByStringFormat(json, DEVICE_INFO_ACCOUNT_ID, deviceInfo->accountId);
    AddInt64ToJsonByStringFormat(json, DEVICE_INFO_TRANSPORT_PROTOCOL, deviceInfo->supportedProtocols);
    AddInt64ToJsonByStringFormat(json, DEVICE_INFO_BLE_TIMESTAMP, deviceInfo->bleStartTimestamp);
    AddInt64ToJsonByStringFormat(json, DEVICE_INFO_FEATURE, deviceInfo->feature);
    return true;
}

static int32_t PackDeviceInfo(cJSON *json, const NodeInfo *deviceInfo)
{
    if (!PackDeviceInfoItemInt64(json, deviceInfo)) {
        LLOGE("pack int64Item fail");
        return SOFTBUS_ERR;
    }
    (void)AddNumberToJsonObject(json, DEVICE_INFO_REMAIN_POWER, deviceInfo->batteryInfo.batteryLevel);
    (void)AddBoolToJsonObject(json, DEVICE_INFO_IS_CHARGING, deviceInfo->batteryInfo.isCharging);
    (void)AddBoolToJsonObject(json, DEVICE_INFO_IS_SCREENON, deviceInfo->isScreenOn);
    (void)AddBoolToJsonObject(json, DEVICE_INFO_DISTRIBUTED_SWITCH, true);
    (void)AddNumberToJsonObject(json, DEVICE_INFO_WIFI_BUFF_SIZE, deviceInfo->wifiBuffSize);
    (void)AddNumberToJsonObject(json, DEVICE_INFO_BR_BUFF_SIZE, deviceInfo->brBuffSize);
    (void)AddStringToJsonObject(json, DEVICE_INFO_P2P_MAC_ADDR, deviceInfo->p2pInfo.p2pMac);
    (void)AddStringToJsonObject(json, DEVICE_INFO_PKG_VERSION, deviceInfo->pkgVersion);
    (void)AddStringToJsonObject(json, DEVICE_INFO_SETTINGS_NICK_NAME, deviceInfo->deviceInfo.nickName);
    (void)AddStringToJsonObject(json, UNIFIED_DEFAULT_DEVICE_NAME, deviceInfo->deviceInfo.unifiedDefaultName);
    (void)AddStringToJsonObject(json, UNIFIED_DEVICE_NAME, deviceInfo->deviceInfo.unifiedName);
    if (!AddStringToJsonObject(json, DEVICE_INFO_DEVICE_NAME, deviceInfo->deviceInfo.deviceName) ||
        !AddStringToJsonObject(json, DEVICE_INFO_DEVICE_TYPE,
            LnnConvertIdToDeviceType(deviceInfo->deviceInfo.deviceTypeId)) ||
        !AddStringToJsonObject(json, DEVICE_INFO_VERSION_TYPE, deviceInfo->versionType) ||
        !AddStringToJsonObject(json, DEVICE_INFO_SW_VERSION, deviceInfo->softBusVersion) ||
        !AddStringToJsonObject(json, DEVICE_INFO_DEVICE_UDID, deviceInfo->deviceInfo.deviceUdid) ||
        !AddStringToJsonObject(json, DEVICE_INFO_DEVICE_UUID, deviceInfo->uuid) ||
        !AddStringToJsonObject(json, DEVICE_INFO_BT_MAC, deviceInfo->connectInfo.macAddr) ||
        !AddStringToJsonObject(json, DEVICE_INFO_HML_MAC, deviceInfo->wifiDirectAddr) ||
        !AddStringToJsonObject(json, DEVICE_INFO_IP_MAC, deviceInfo->connectInfo.deviceIp) ||
        !AddNumberToJsonObject(json, DEVICE_INFO_P2P_ROLE, deviceInfo->p2pInfo.p2pRole) ||
        !AddStringToJsonObject(json, DEVICE_INFO_NETWORK_ID, deviceInfo->networkId) ||
        !AddNumberToJsonObject(json, DEVICE_INFO_NODE_WEIGHT, deviceInfo->masterWeight) ||
        !AddBoolToJsonObject(json, DEVICE_INFO_BLE_P2P, deviceInfo->isBleP2p) ||
        !AddNumberToJsonObject(json, DEVICE_INFO_NEW_CONN_CAP, deviceInfo->netCapacity) ||
        !AddNumberToJsonObject(json, DEVICE_INFO_CONN_CAP, deviceInfo->netCapacity) ||
        !AddStringToJsonObject(json, DEVICE_INFO_EXTDATA, deviceInfo->extData) ||
        !AddNumberToJsonObject(json, DEVICE_INFO_STATE_VERSION, deviceInfo->stateVersion) ||
        !AddNumberToJsonObject(json, DEVICE_INFO_LOCAL_STATE_VERSION, deviceInfo->localStateVersion)) {
        LLOGE("pack device info fail");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

static bool GetInt64FromJsonByStringFormat(cJSON *json, const char *key, int64_t *dst)
{
    char buff[INT64_TO_STR_MAX_LEN] = {0};
    if (!GetJsonObjectStringItem(json, key, buff, INT64_TO_STR_MAX_LEN)) {
        LLOGE("get string fail, key:%s", key);
        return false;
    }
    if (buff[INT64_TO_STR_MAX_LEN - 1] != '\0') {
        LLOGE("buffer is corrupted");
        return false;
    }
    *dst = (int64_t)strtoll(buff, NULL, STRTOLL_BASE);
    return true;
}

static bool UnpackDeviceInfoItemInt64(cJSON *json, NodeInfo *deviceInfo)
{
    (void)GetInt64FromJsonByStringFormat(json, DEVICE_INFO_WIFI_VERSION, &deviceInfo->wifiVersion);
    (void)GetInt64FromJsonByStringFormat(json, DEVICE_INFO_BLE_VERSION, &deviceInfo->bleVersion);
    (void)GetInt64FromJsonByStringFormat(json, DEVICE_INFO_ACCOUNT_ID, &deviceInfo->accountId);
    (void)GetInt64FromJsonByStringFormat(json, DEVICE_INFO_TRANSPORT_PROTOCOL,
        (int64_t *)&deviceInfo->supportedProtocols);
    (void)GetInt64FromJsonByStringFormat(json, DEVICE_INFO_BLE_TIMESTAMP, &deviceInfo->bleStartTimestamp);
    (void)GetInt64FromJsonByStringFormat(json, DEVICE_INFO_FEATURE, (int64_t *)&deviceInfo->feature);
    if (!GetInt64FromJsonByStringFormat(json, DEVICE_INFO_NETWORK_ID_TIMESTAMP,
        (int64_t *)&deviceInfo->networkIdTimestamp)) {
            deviceInfo->networkIdTimestamp = 0;
            LLOGI("newworkIdTimestamp reset fpr upgrade");
    }
    return true;
}

static int32_t UnpackDeviceInfo(cJSON *json, NodeInfo *deviceInfo)
{
    if (json == NULL || deviceInfo == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    char deviceType[DEVICE_TYPE_BUF_LEN] = {0};
    if (GetJsonObjectStringItem(json, DEVICE_INFO_DEVICE_TYPE, deviceType, DEVICE_TYPE_BUF_LEN)) {
        (void)LnnConvertDeviceTypeToId(deviceType, &(deviceInfo->deviceInfo.deviceTypeId));
    }
    if (!UnpackDeviceInfoItemInt64(json, deviceInfo)) {
        LLOGE("unpack device info int64Item fail");
        return SOFTBUS_ERR;
    }
    (void)GetJsonObjectInt32Item(json, DEVICE_INFO_REMAIN_POWER, &deviceInfo->batteryInfo.batteryLevel);
    (void)GetJsonObjectBoolItem(json, DEVICE_INFO_IS_CHARGING, &deviceInfo->batteryInfo.isCharging);
    (void)GetJsonObjectBoolItem(json, DEVICE_INFO_IS_SCREENON, &deviceInfo->isScreenOn);
    (void)GetJsonObjectBoolItem(json, DEVICE_INFO_BLE_P2P, &deviceInfo->isBleP2p);
    (void)GetJsonObjectInt32Item(json, DEVICE_INFO_WIFI_BUFF_SIZE, &deviceInfo->wifiBuffSize);
    (void)GetJsonObjectInt32Item(json, DEVICE_INFO_BR_BUFF_SIZE, &deviceInfo->brBuffSize);
    (void)GetJsonObjectStringItem(json, DEVICE_INFO_P2P_MAC_ADDR, deviceInfo->p2pInfo.p2pMac, MAC_LEN);
    (void)GetJsonObjectStringItem(json, DEVICE_INFO_PKG_VERSION, deviceInfo->pkgVersion, VERSION_MAX_LEN);
    if (!GetJsonObjectStringItem(json, DEVICE_INFO_DEVICE_UDID, deviceInfo->deviceInfo.deviceUdid, UDID_BUF_LEN) ||
        !GetJsonObjectStringItem(json, DEVICE_INFO_DEVICE_UUID, deviceInfo->uuid, UUID_BUF_LEN) ||
        !GetJsonObjectStringItem(json, DEVICE_INFO_DEVICE_NAME,
            deviceInfo->deviceInfo.deviceName, DEVICE_NAME_BUF_LEN) ||
        !GetJsonObjectStringItem(json, DEVICE_INFO_VERSION_TYPE, deviceInfo->versionType, VERSION_MAX_LEN) ||
        !GetJsonObjectStringItem(json, DEVICE_INFO_BT_MAC, deviceInfo->connectInfo.macAddr, MAC_LEN) ||
        !GetJsonObjectStringItem(json, DEVICE_INFO_HML_MAC, deviceInfo->wifiDirectAddr, MAC_LEN) ||
        !GetJsonObjectStringItem(json, DEVICE_INFO_SW_VERSION, deviceInfo->softBusVersion, VERSION_MAX_LEN) ||
        !GetJsonObjectStringItem(json, DEVICE_INFO_IP_MAC, deviceInfo->connectInfo.deviceIp, MAX_ADDR_LEN) ||
        !GetJsonObjectStringItem(json, DEVICE_INFO_EXTDATA, deviceInfo->extData, EXTDATA_LEN) ||
        !GetJsonObjectInt32Item(json, DEVICE_INFO_P2P_ROLE, &deviceInfo->p2pInfo.p2pRole) ||
        !GetJsonObjectInt32Item(json, DEVICE_INFO_NODE_WEIGHT, &deviceInfo->masterWeight) ||
        !GetJsonObjectInt32Item(json, DEVICE_INFO_CONN_CAP, (int32_t *)&deviceInfo->netCapacity) ||
        !GetJsonObjectInt32Item(json, DEVICE_INFO_NEW_CONN_CAP, (int32_t *)&deviceInfo->netCapacity) ||
        !GetJsonObjectInt32Item(json, DEVICE_INFO_STATE_VERSION, &deviceInfo->stateVersion) ||
        !GetJsonObjectInt32Item(json, DEVICE_INFO_LOCAL_STATE_VERSION, &deviceInfo->localStateVersion)) {
        LLOGE("unpack device info fail");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

static char *PackAllDeviceInfo(void)
{
    cJSON *jsonArray = cJSON_CreateArray();
    if (jsonArray == NULL) {
        LLOGE("jsonArray is null");
        return NULL;
    }
    if (DeviceMapLock() != SOFTBUS_OK) {
        cJSON_Delete(jsonArray);
        return NULL;
    }
    MapIterator *it = LnnMapInitIterator(&g_deviceInfoMap);
    if (it == NULL) {
        LLOGE("map is empty");
        DeviceMapUnLock();
        cJSON_Delete(jsonArray);
        return NULL;
    }
    while (LnnMapHasNext(it)) {
        it = LnnMapNext(it);
        if (it == NULL || it->node->value == NULL) {
            break;
        }
        NodeInfo *nodeInfo = (NodeInfo *)it->node->value;
        if (nodeInfo == NULL) {
            LLOGE("device info is nullptr");
            continue;
        }
        cJSON *obj = cJSON_CreateObject();
        if (obj == NULL) {
            LLOGE("jsonObj creat fail");
            continue;
        }
        (void)PackDeviceInfo(obj, nodeInfo);
        cJSON_AddItemToArray(jsonArray, obj);
    }
    LnnMapDeinitIterator(it);
    char *msg = cJSON_PrintUnformatted(jsonArray);
    DeviceMapUnLock();
    cJSON_Delete(jsonArray);
    return msg;
}

static char *PackLocalDeviceInfo(const NodeInfo *deviceInfo)
{
    cJSON *json = cJSON_CreateObject();
    if (json == NULL) {
        LLOGE("crate jsonObj fail");
        return NULL;
    }
    int32_t ret = PackDeviceInfo(json, deviceInfo);
    if (ret != SOFTBUS_OK) {
        cJSON_Delete(json);
        return NULL;
    }
    char *pkg = cJSON_PrintUnformatted(json);
    cJSON_Delete(json);
    return pkg;
}

int32_t LnnSaveLocalDeviceInfo(const NodeInfo *deviceInfo)
{
    if (deviceInfo == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    if (DeviceMapLock() != SOFTBUS_OK) {
        return SOFTBUS_LOCK_ERR;
    }
    if (LnnMapSet(&g_deviceInfoMap, (const char *)deviceInfo->deviceInfo.deviceUdid,
        (const void *)deviceInfo, sizeof(NodeInfo)) != SOFTBUS_OK) {
        LLOGE("save data to map");
        DeviceMapUnLock();
        return SOFTBUS_ERR;
    }
    LLOGD("save data networkId = %s, stateVersion = %d", AnonymizesNetworkID(deviceInfo->networkId),
        deviceInfo->stateVersion);
    if (memcpy_s(&g_localNodeInfo, sizeof(NodeInfo), deviceInfo, sizeof(NodeInfo)) != EOK) {
        LLOGE("memcpy fail");
        DeviceMapUnLock();
        return SOFTBUS_MEM_ERR;
    }
    DeviceMapUnLock();
    char *pkg = PackLocalDeviceInfo(deviceInfo);
    if (pkg == NULL) {
        return SOFTBUS_ERR;
    }
    int32_t ret = LnnSaveDeviceData(pkg, LNN_DATA_TYPE_LOCAL_DEVINFO);
    cJSON_free(pkg);
    if (ret != SOFTBUS_OK) {
        LLOGI("save local device info fail:%d", ret);
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int32_t LnnGetLocalDevInfo(NodeInfo *deviceInfo)
{
    if (deviceInfo == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    if (DeviceMapLock() != SOFTBUS_OK) {
        return SOFTBUS_LOCK_ERR;
    }
    if (memcpy_s(deviceInfo, sizeof(NodeInfo), &g_localNodeInfo, sizeof(g_localNodeInfo)) != EOK) {
        DeviceMapUnLock();
        return SOFTBUS_MEM_ERR;
    }
    DeviceMapUnLock();
    return SOFTBUS_OK;
}

int32_t LnnLoadLocalDeviceInfo(void)
{
    char *data = NULL;
    uint32_t dataLen = 0;
    if (LnnRetrieveDeviceData(LNN_DATA_TYPE_LOCAL_DEVINFO, &data, &dataLen) != SOFTBUS_OK) {
        LLOGE("load local device ingo fail");
        return SOFTBUS_ERR;
    }
    if (data == NULL) {
        return SOFTBUS_ERR;
    }
    if (dataLen == 0) {
        SoftBusFree(data);
        return SOFTBUS_ERR;
    }
    cJSON *json = cJSON_Parse(data);
    if (json == NULL) {
        LLOGE("parse json fail");
        SoftBusFree(data);
        return SOFTBUS_ERR;
    }
    NodeInfo localDeviceInfo = {0};
    if (UnpackDeviceInfo(json, &localDeviceInfo) != SOFTBUS_OK) {
        cJSON_Delete(json);
        SoftBusFree(data);
        return SOFTBUS_ERR;
    }
    cJSON_Delete(json);
    SoftBusFree(data);
    if (DeviceMapLock() != SOFTBUS_OK) {
        return SOFTBUS_LOCK_ERR;
    }
    if (memcpy_s(&g_localNodeInfo, sizeof(g_localNodeInfo), &localDeviceInfo, sizeof(localDeviceInfo)) != EOK) {
        DeviceMapUnLock();
        return SOFTBUS_MEM_ERR;
    }
    DeviceMapUnLock();
    return SOFTBUS_OK;
}

static void InsertToDeviceInfoMap(const NodeInfo *deviceInfo)
{
    if (DeviceMapLock() != SOFTBUS_OK) {
        return;
    }
    if (LnnMapSet(&g_deviceInfoMap, (const char *)deviceInfo->deviceInfo.deviceUdid,
        (const void *)deviceInfo, sizeof(NodeInfo)) != SOFTBUS_OK) {
        LLOGE("save deviceInfo fail");
        DeviceMapUnLock();
        return;
    }
    DeviceMapUnLock();
}

static void SaveDeviceInfoToSecureStorage(void)
{
    char *dataStr = PackAllDeviceInfo();
    if (dataStr == NULL) {
        LLOGE("pack all deviceInfo fail");
        return;
    }
    if (LnnSaveDeviceData((const char *)dataStr, LNN_DATA_TYPE_REMOTE_DEVINFO) != SOFTBUS_OK) {
        LLOGE("save remote devInfo fail");
        cJSON_free(dataStr);
        return;
    }
    cJSON_free(dataStr);
}

int32_t LnnSaveRemoteDeviceInfo(const NodeInfo *deviceInfo)
{
    LLOGD("save remote devInfo");
    if (deviceInfo == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    InsertToDeviceInfoMap(deviceInfo);
    SaveDeviceInfoToSecureStorage();
    return SOFTBUS_OK;
}

int32_t LnnUpdateRemoteDeviceInfo(const NodeInfo *deviceInfo)
{
    LLOGD("update remote devInfo");
    return LnnSaveRemoteDeviceInfo(deviceInfo);
}

static bool ParseRemoteDeviceInfo(const char *devInfo)
{
    cJSON *json = cJSON_Parse(devInfo);
    if (json == NULL) {
        LLOGE("parse json fail");
        return false;
    }
    int32_t arraySize = cJSON_GetArraySize(json);
    if (arraySize <= 0) {
        LLOGE("not valid devinfo");
        cJSON_Delete(json);
        return false;
    }
    LLOGD("jsonArray size:%d", arraySize);
    NodeInfo oldDevInfo = {0};
    for (int32_t i = 0; i < arraySize; i++) {
        cJSON *item = cJSON_GetArrayItem(json, i);
        (void)memset_s(&oldDevInfo, sizeof(NodeInfo), 0, sizeof(NodeInfo));
        if (UnpackDeviceInfo(item, &oldDevInfo) != SOFTBUS_OK) {
            continue;
        }
    }
    cJSON_Delete(json);
    return true;
}

int32_t LnnLoadRemoteDeviceInfo(void)
{
    char *devInfo = NULL;
    uint32_t devInfoLen = 0;
    if (LnnRetrieveDeviceData(LNN_DATA_TYPE_REMOTE_DEVINFO, &devInfo, &devInfoLen) != SOFTBUS_OK) {
        LLOGW("load remote devInfo fail, maybe no device has ever gone online.");
        return SOFTBUS_ERR;
    }
    if (devInfo == NULL) {
        LLOGE("load devInfo fail, devInfo is nullptr");
        return SOFTBUS_ERR;
    }
    if (devInfoLen == 0 || strlen(devInfo) != devInfoLen) {
        LLOGE("devInfoLen is invalid");
        SoftBusFree(devInfo);
        return SOFTBUS_ERR;
    }
    if (!ParseRemoteDeviceInfo(devInfo)) {
        LLOGE("parse devInfo fail");
    }
    SoftBusFree(devInfo);
    return SOFTBUS_OK;
}

int32_t LnnRetrieveDeviceInfo(const char *udid, NodeInfo *deviceInfo)
{
    if (udid == NULL || deviceInfo == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    if (DeviceMapLock() != SOFTBUS_OK) {
        return SOFTBUS_ERR;
    }
    NodeInfo *data = (NodeInfo *)LnnMapGet(&g_deviceInfoMap, (const char *)udid);
    if (data == NULL) {
        LLOGE("data not found");
        DeviceMapUnLock();
        return SOFTBUS_ERR;
    }
    if (memcpy_s(deviceInfo, sizeof(NodeInfo), data, sizeof(NodeInfo)) != EOK) {
        DeviceMapUnLock();
        return SOFTBUS_MEM_ERR;
    }
    DeviceMapUnLock();
    return SOFTBUS_OK;
}

void LnnDeleteDeviceInfo(const char *udid)
{
    if (udid == NULL) {
        return;
    }
    if (DeviceMapLock() != SOFTBUS_OK) {
        LLOGE("lock fail");
        return;
    }
    int32_t ret = LnnMapErase(&g_deviceInfoMap, (const char *)udid);
    if (ret != SOFTBUS_OK) {
        LLOGE("delete item fail, ret:%d", ret);
        DeviceMapUnLock();
        return;
    }
    DeviceMapUnLock();
    SaveDeviceInfoToSecureStorage();
}

void ClearDeviceInfo(void)
{
    LnnMapDelete(&g_deviceInfoMap);
}
