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

#include "lnn_distributed_net_ledger_common.h"

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <securec.h>

#include "anonymizer.h"
#include "lnn_node_info.h"
#include "lnn_device_info_recovery.h"
#include "lnn_feature_capability.h"
#include "lnn_heartbeat_utils.h"
#include "lnn_log.h"
#include "softbus_error_code.h"
#include "softbus_utils.h"
#include "bus_center_manager.h"

static uint64_t GetCurrentTime(void)
{
    SoftBusSysTime now = { 0 };
    if (SoftBusGetTime(&now) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "GetCurrentTime fail.");
        return 0;
    }
    return (uint64_t)now.sec * TIME_THOUSANDS_FACTOR + (uint64_t)now.usec / TIME_THOUSANDS_FACTOR;
}

static int32_t DlGetDeviceUuid(const char *networkId, bool checkOnline, void *buf, uint32_t len)
{
    (void)checkOnline;
    NodeInfo *info = NULL;
    RETURN_IF_GET_NODE_VALID(networkId, buf, info);
    if (strncpy_s((char*)buf, len, info->uuid, strlen(info->uuid)) != EOK) {
        LNN_LOGE(LNN_LEDGER, "STR COPY ERROR!");
        return SOFTBUS_MEM_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t DlGetDeviceOfflineCode(const char *networkId, bool checkOnline, void *buf, uint32_t len)
{
    (void)checkOnline;
    NodeInfo *info = NULL;
    RETURN_IF_GET_NODE_VALID(networkId, buf, info);
    if (memcpy_s(buf, len, info->offlineCode, OFFLINE_CODE_BYTE_SIZE) != EOK) {
        LNN_LOGE(LNN_LEDGER, "memcpy_s offlinecode ERROR!");
        return SOFTBUS_MEM_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t DlGetDeviceUdid(const char *networkId, bool checkOnline, void *buf, uint32_t len)
{
    (void)checkOnline;
    const char *udid = NULL;
    NodeInfo *info = NULL;
    RETURN_IF_GET_NODE_VALID(networkId, buf, info);
    udid = LnnGetDeviceUdid(info);
    if (udid == NULL) {
        LNN_LOGE(LNN_LEDGER, "get device udid fail");
        return SOFTBUS_NETWORK_GET_DEVICE_INFO_ERR;
    }
    if (strncpy_s((char*)buf, len, udid, strlen(udid)) != EOK) {
        LNN_LOGE(LNN_LEDGER, "STR COPY ERROR!");
        return SOFTBUS_MEM_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t DlGetNodeSoftBusVersion(const char *networkId, bool checkOnline, void *buf, uint32_t len)
{
    (void)checkOnline;
    NodeInfo *info = NULL;
    RETURN_IF_GET_NODE_VALID(networkId, buf, info);
    if (strncpy_s((char*)buf, len, info->softBusVersion, strlen(info->softBusVersion)) != EOK) {
        LNN_LOGE(LNN_LEDGER, "STR COPY ERROR!");
        return SOFTBUS_MEM_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t DlGetDeviceType(const char *networkId, bool checkOnline, void *buf, uint32_t len)
{
    (void)checkOnline;
    NodeInfo *info = NULL;
    char *deviceType = NULL;
    RETURN_IF_GET_NODE_VALID(networkId, buf, info);
    deviceType = LnnConvertIdToDeviceType(info->deviceInfo.deviceTypeId);
    if (deviceType == NULL) {
        LNN_LOGE(LNN_LEDGER, "deviceType fail.");
        return SOFTBUS_NETWORK_GET_DEVICE_INFO_ERR;
    }
    if (strncpy_s((char*)buf, len, deviceType, strlen(deviceType)) != EOK) {
        LNN_LOGE(LNN_LEDGER, "MEM COPY ERROR!");
        return SOFTBUS_MEM_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t DlGetDeviceTypeId(const char *networkId, bool checkOnline, void *buf, uint32_t len)
{
    (void)checkOnline;
    (void)len;
    NodeInfo *info = NULL;
    RETURN_IF_GET_NODE_VALID(networkId, buf, info);
    *((int32_t *)buf) = info->deviceInfo.deviceTypeId;
    return SOFTBUS_OK;
}

static int32_t DlGetAuthType(const char *networkId, bool checkOnline, void *buf, uint32_t len)
{
    (void)checkOnline;
    NodeInfo *info = NULL;
    RETURN_IF_GET_NODE_VALID(networkId, buf, info);
    *((uint32_t *)buf) = info->AuthTypeValue;
    return SOFTBUS_OK;
}

static int32_t DlGetDeviceName(const char *networkId, bool checkOnline, void *buf, uint32_t len)
{
    (void)checkOnline;
    NodeInfo *info = NULL;
    const char *deviceName = NULL;
    RETURN_IF_GET_NODE_VALID(networkId, buf, info);
    deviceName = LnnGetDeviceName(&info->deviceInfo);
    if (deviceName == NULL) {
        LNN_LOGE(LNN_LEDGER, "get device name fail.");
        return SOFTBUS_NETWORK_GET_DEVICE_INFO_ERR;
    }
    if (strncpy_s((char*)buf, len, deviceName, strlen(deviceName)) != EOK) {
        LNN_LOGE(LNN_LEDGER, "STR COPY ERROR!");
        return SOFTBUS_MEM_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t DlGetBtMac(const char *networkId, bool checkOnline, void *buf, uint32_t len)
{
    (void)checkOnline;
    NodeInfo *info = NULL;
    const char *mac = NULL;
    RETURN_IF_GET_NODE_VALID(networkId, buf, info);
    mac = LnnGetBtMac(info);
    if (mac == NULL) {
        LNN_LOGE(LNN_LEDGER, "get bt mac fail.");
        return SOFTBUS_NETWORK_GET_DEVICE_INFO_ERR;
    }
    if (strncpy_s((char*)buf, len, mac, strlen(mac)) != EOK) {
        LNN_LOGE(LNN_LEDGER, "STR COPY ERROR!");
        return SOFTBUS_MEM_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t DlGetWlanIp(const char *networkId, bool checkOnline, void *buf, uint32_t len)
{
    (void)checkOnline;
    NodeInfo *info = NULL;
    const char *ip = NULL;
    RETURN_IF_GET_NODE_VALID(networkId, buf, info);
    ip = LnnGetWiFiIp(info);
    if (ip == NULL) {
        LNN_LOGE(LNN_LEDGER, "get wifi ip fail.");
        return SOFTBUS_NETWORK_GET_DEVICE_INFO_ERR;
    }
    if (strncpy_s((char*)buf, len, ip, strlen(ip)) != EOK) {
        LNN_LOGE(LNN_LEDGER, "STR COPY ERROR!");
        return SOFTBUS_MEM_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t DlGetMasterUdid(const char *networkId, bool checkOnline, void *buf, uint32_t len)
{
    (void)checkOnline;
    NodeInfo *info = NULL;
    const char *masterUdid = NULL;

    RETURN_IF_GET_NODE_VALID(networkId, buf, info);
    if (!LnnIsNodeOnline(info)) {
        return SOFTBUS_NETWORK_NODE_OFFLINE;
    }
    masterUdid = LnnGetMasterUdid(info);
    if (masterUdid == NULL) {
        LNN_LOGE(LNN_LEDGER, "get master uiid fail");
        return SOFTBUS_NETWORK_GET_DEVICE_INFO_ERR;
    }
    if (strncpy_s((char*)buf, len, masterUdid, strlen(masterUdid)) != EOK) {
        LNN_LOGE(LNN_LEDGER, "copy master udid to buf fail");
        return SOFTBUS_MEM_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t DlGetRemotePtk(const char *networkId, bool checkOnline, void *buf, uint32_t len)
{
    (void)checkOnline;
    if (len != PTK_DEFAULT_LEN) {
        LNN_LOGE(LNN_LEDGER, "length error");
        return SOFTBUS_INVALID_PARAM;
    }
    NodeInfo *info = NULL;
    RETURN_IF_GET_NODE_VALID(networkId, buf, info);
    if (memcpy_s(buf, len, info->remotePtk, PTK_DEFAULT_LEN) != EOK) {
        LNN_LOGE(LNN_LEDGER, "memcpy remote ptk err");
        return SOFTBUS_MEM_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t DlGetStaticCapLen(const char *networkId, bool checkOnline, void *buf, uint32_t len)
{
    (void)checkOnline;
    NodeInfo *info = NULL;
    if (len != LNN_COMMON_LEN) {
        LNN_LOGE(LNN_LEDGER, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    RETURN_IF_GET_NODE_VALID(networkId, buf, info);
    if (!LnnIsNodeOnline(info)) {
        LNN_LOGE(LNN_LEDGER, "device is offline");
        return SOFTBUS_NETWORK_NODE_OFFLINE;
    }
    *((int32_t *)buf) = info->staticCapLen;
    return SOFTBUS_OK;
}

static int32_t DlGetDeviceSecurityLevel(const char *networkId, bool checkOnline, void *buf, uint32_t len)
{
    (void)checkOnline;
    NodeInfo *info = NULL;
    if (len != LNN_COMMON_LEN) {
        LNN_LOGE(LNN_LEDGER, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    RETURN_IF_GET_NODE_VALID(networkId, buf, info);
    *((int32_t *)buf) = info->deviceSecurityLevel;
    return SOFTBUS_OK;
}

static int32_t DlGetStaticCap(const char *networkId, bool checkOnline, void *buf, uint32_t len)
{
    (void)checkOnline;
    if (len > STATIC_CAP_LEN) {
        LNN_LOGE(LNN_LEDGER, "length error");
        return SOFTBUS_INVALID_PARAM;
    }
    NodeInfo *info = NULL;
    RETURN_IF_GET_NODE_VALID(networkId, buf, info);
    if (memcpy_s(buf, len, info->staticCapability, STATIC_CAP_LEN) != EOK) {
        LNN_LOGE(LNN_LEDGER, "memcpy static cap err");
        return SOFTBUS_MEM_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t DlGetNodeBleMac(const char *networkId, bool checkOnline, void *buf, uint32_t len)
{
    (void)checkOnline;
    NodeInfo *info = NULL;

    RETURN_IF_GET_NODE_VALID(networkId, buf, info);
    if (strlen(info->connectInfo.bleMacAddr) == 0) {
        LNN_LOGE(LNN_LEDGER, "ble mac is invalid.");
        return SOFTBUS_INVALID_PARAM;
    }
    if (info->bleMacRefreshSwitch != 0) {
        uint64_t currentTimeMs = GetCurrentTime();
        LNN_CHECK_AND_RETURN_RET_LOGE(info->connectInfo.latestTime + BLE_ADV_LOST_TIME >= currentTimeMs,
            SOFTBUS_NETWORK_GET_BLE_MAC_TIMEOUT, LNN_LEDGER,
            "ble mac out date, lastAdvTime=%{public}" PRIu64 ", now=%{public}" PRIu64, info->connectInfo.latestTime,
            currentTimeMs);
    }
    if (strcpy_s((char *)buf, len, info->connectInfo.bleMacAddr) != EOK) {
        return SOFTBUS_MEM_ERR;
    }
    return SOFTBUS_OK;
}

void LnnUpdateNodeBleMac(const char *networkId, char *bleMac, uint32_t len)
{
    if ((networkId == NULL) || (bleMac == NULL) || (len != MAC_LEN)) {
        LNN_LOGE(LNN_LEDGER, "invalid arg");
        return;
    }
    if (SoftBusMutexLock(&(LnnGetDistributedNetLedger()->lock)) != 0) {
        LNN_LOGE(LNN_LEDGER, "lock mutex fail!");
        return;
    }
    NodeInfo *info = LnnGetNodeInfoById(networkId, CATEGORY_NETWORK_ID);
    if (info == NULL) {
        LNN_LOGE(LNN_LEDGER, "get node info fail.");
        SoftBusMutexUnlock(&(LnnGetDistributedNetLedger()->lock));
        return;
    }
    if (memcpy_s(info->connectInfo.bleMacAddr, MAC_LEN, bleMac, len) != EOK) {
        LNN_LOGE(LNN_LEDGER, "memcpy fail.");
        SoftBusMutexUnlock(&(LnnGetDistributedNetLedger()->lock));
        return;
    }
    info->connectInfo.latestTime = GetCurrentTime();

    SoftBusMutexUnlock(&(LnnGetDistributedNetLedger()->lock));
}

int32_t IsNodeInfoScreenStatusSupport(const NodeInfo *info)
{
    if (!LnnIsSupportHeartbeatCap(info->heartbeatCapacity, BIT_SUPPORT_SCREEN_STATUS)) {
        return SOFTBUS_NETWORK_NOT_SUPPORT;
    }
    return SOFTBUS_OK;
}

bool LnnSetRemoteScreenStatusInfo(const char *networkId, bool isScreenOn)
{
    if (networkId == NULL) {
        LNN_LOGE(LNN_LEDGER, "invalid arg");
        return false;
    }
    if (SoftBusMutexLock(&(LnnGetDistributedNetLedger()->lock)) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "lock mutex fail!");
        return false;
    }
    char *anonyNetworkId = NULL;
    Anonymize(networkId, &anonyNetworkId);
    NodeInfo *info = LnnGetNodeInfoById(networkId, CATEGORY_NETWORK_ID);
    if (info == NULL) {
        LNN_LOGE(LNN_LEDGER, "networkId=%{public}s, get node info fail.", AnonymizeWrapper(anonyNetworkId));
        SoftBusMutexUnlock(&(LnnGetDistributedNetLedger()->lock));
        AnonymizeFree(anonyNetworkId);
        return false;
    }
    if (IsNodeInfoScreenStatusSupport(info) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "networkId=%{public}s, node screen status is not supported",
            AnonymizeWrapper(anonyNetworkId));
        SoftBusMutexUnlock(&(LnnGetDistributedNetLedger()->lock));
        AnonymizeFree(anonyNetworkId);
        return false;
    }
    
    info->isScreenOn = isScreenOn;
    LNN_LOGI(LNN_LEDGER, "set %{public}s screen status to %{public}s",
        AnonymizeWrapper(anonyNetworkId), isScreenOn ? "on" : "off");
    SoftBusMutexUnlock(&LnnGetDistributedNetLedger()->lock);
    AnonymizeFree(anonyNetworkId);
    return true;
}

static int32_t DlGetAuthPort(const char *networkId, bool checkOnline, void *buf, uint32_t len)
{
    (void)checkOnline;
    NodeInfo *info = NULL;
    if (len != LNN_COMMON_LEN) {
        return SOFTBUS_INVALID_PARAM;
    }
    RETURN_IF_GET_NODE_VALID(networkId, buf, info);
    *((int32_t *)buf) = LnnGetAuthPort(info);
    return SOFTBUS_OK;
}

static int32_t DlGetSessionPort(const char *networkId, bool checkOnline, void *buf, uint32_t len)
{
    (void)checkOnline;
    NodeInfo *info = NULL;
    if (len != LNN_COMMON_LEN) {
        return SOFTBUS_INVALID_PARAM;
    }
    RETURN_IF_GET_NODE_VALID(networkId, buf, info);
    *((int32_t *)buf) = LnnGetSessionPort(info);
    return SOFTBUS_OK;
}

static int32_t DlGetProxyPort(const char *networkId, bool checkOnline, void *buf, uint32_t len)
{
    (void)checkOnline;
    NodeInfo *info = NULL;
    if (len != LNN_COMMON_LEN) {
        return SOFTBUS_INVALID_PARAM;
    }
    RETURN_IF_GET_NODE_VALID(networkId, buf, info);
    *((int32_t *)buf) = LnnGetProxyPort(info);
    return SOFTBUS_OK;
}

static int32_t DlGetNetCap(const char *networkId, bool checkOnline, void *buf, uint32_t len)
{
    (void)checkOnline;
    NodeInfo *info = NULL;
    if (len != LNN_COMMON_LEN) {
        return SOFTBUS_INVALID_PARAM;
    }
    RETURN_IF_GET_NODE_VALID(networkId, buf, info);
    *((uint32_t *)buf) = info->netCapacity;
    return SOFTBUS_OK;
}

static int32_t DlGetFeatureCap(const char *networkId, bool checkOnline, void *buf, uint32_t len)
{
    (void)checkOnline;
    NodeInfo *info = NULL;
    if (len != LNN_COMMON_LEN_64) {
        return SOFTBUS_INVALID_PARAM;
    }
    RETURN_IF_GET_NODE_VALID(networkId, buf, info);
    *((uint64_t *)buf) = info->feature;
    return SOFTBUS_OK;
}

static int32_t DlGetConnSubFeatureCap(const char *networkId, bool checkOnline, void *buf, uint32_t len)
{
    (void)checkOnline;
    NodeInfo *info = NULL;
    if (len != LNN_COMMON_LEN_64) {
        return SOFTBUS_INVALID_PARAM;
    }
    RETURN_IF_GET_NODE_VALID(networkId, buf, info);
    *((uint64_t *)buf) = info->connSubFeature;
    return SOFTBUS_OK;
}

static int32_t DlGetNetType(const char *networkId, bool checkOnline, void *buf, uint32_t len)
{
    (void)checkOnline;
    NodeInfo *info = NULL;
    if (len != LNN_COMMON_LEN) {
        return SOFTBUS_INVALID_PARAM;
    }
    RETURN_IF_GET_NODE_VALID(networkId, buf, info);
    *((int32_t *)buf) = (int32_t)info->discoveryType;
    return SOFTBUS_OK;
}

static int32_t DlGetMasterWeight(const char *networkId, bool checkOnline, void *buf, uint32_t len)
{
    (void)checkOnline;
    NodeInfo *info = NULL;

    if (len != LNN_COMMON_LEN) {
        return SOFTBUS_INVALID_PARAM;
    }
    RETURN_IF_GET_NODE_VALID(networkId, buf, info);
    *((int32_t *)buf) = info->masterWeight;
    return SOFTBUS_OK;
}

static int32_t DlGetP2pMac(const char *networkId, bool checkOnline, void *buf, uint32_t len)
{
    (void)checkOnline;
    NodeInfo *info = NULL;
    const char *mac = NULL;

    RETURN_IF_GET_NODE_VALID(networkId, buf, info);
    if ((!LnnIsNodeOnline(info)) && (!info->metaInfo.isMetaNode)) {
        LNN_LOGE(LNN_LEDGER, "node is offline");
        return SOFTBUS_NETWORK_NODE_OFFLINE;
    }
    mac = LnnGetP2pMac(info);
    if (mac == NULL) {
        LNN_LOGE(LNN_LEDGER, "get p2p mac fail");
        return SOFTBUS_NETWORK_GET_DEVICE_INFO_ERR;
    }
    if (strcpy_s((char*)buf, len, mac) != EOK) {
        LNN_LOGE(LNN_LEDGER, "copy p2p mac to buf fail");
        return SOFTBUS_MEM_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t DlGetWifiDirectAddr(const char *networkId, bool checkOnline, void *buf, uint32_t len)
{
    (void)checkOnline;
    NodeInfo *info = NULL;
    const char *wifiDirectAddr = NULL;

    RETURN_IF_GET_NODE_VALID(networkId, buf, info);
    if ((!LnnIsNodeOnline(info)) && (!info->metaInfo.isMetaNode)) {
        LNN_LOGE(LNN_LEDGER, "node is offline");
        return SOFTBUS_NETWORK_NODE_OFFLINE;
    }
    wifiDirectAddr = LnnGetWifiDirectAddr(info);
    if (wifiDirectAddr == NULL) {
        LNN_LOGE(LNN_LEDGER, "get wifidirect addr fail");
        return SOFTBUS_NETWORK_GET_DEVICE_INFO_ERR;
    }
    if (strcpy_s((char*)buf, len, wifiDirectAddr) != EOK) {
        LNN_LOGE(LNN_LEDGER, "copy wifidirect addr to buf fail");
        return SOFTBUS_MEM_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t DlGetNodeAddr(const char *networkId, bool checkOnline, void *buf, uint32_t len)
{
    (void)checkOnline;
    NodeInfo *info = NULL;
    RETURN_IF_GET_NODE_VALID(networkId, buf, info);
    if (!LnnIsNodeOnline(info)) {
        LNN_LOGE(LNN_LEDGER, "node is offline");
        return SOFTBUS_NETWORK_NODE_OFFLINE;
    }
    if (strcpy_s((char*)buf, len, info->nodeAddress) != EOK) {
        LNN_LOGE(LNN_LEDGER, "copy node addr to buf fail");
        return SOFTBUS_MEM_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t DlGetP2pGoMac(const char *networkId, bool checkOnline, void *buf, uint32_t len)
{
    (void)checkOnline;
    NodeInfo *info = NULL;
    const char *mac = NULL;

    RETURN_IF_GET_NODE_VALID(networkId, buf, info);
    if ((!LnnIsNodeOnline(info)) && (!info->metaInfo.isMetaNode)) {
        LNN_LOGE(LNN_LEDGER, "node is offline");
        return SOFTBUS_NETWORK_NODE_OFFLINE;
    }
    mac = LnnGetP2pGoMac(info);
    if (mac == NULL) {
        LNN_LOGE(LNN_LEDGER, "get p2p go mac fail");
        return SOFTBUS_NETWORK_GET_DEVICE_INFO_ERR;
    }
    if (strcpy_s((char*)buf, len, mac) != EOK) {
        LNN_LOGE(LNN_LEDGER, "copy p2p go mac to buf fail");
        return SOFTBUS_MEM_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t DlGetWifiCfg(const char *networkId, bool checkOnline, void *buf, uint32_t len)
{
    (void)checkOnline;
    NodeInfo *info = NULL;
    const char *wifiCfg = NULL;

    RETURN_IF_GET_NODE_VALID(networkId, buf, info);
    if ((!LnnIsNodeOnline(info)) && (!info->metaInfo.isMetaNode)) {
        LNN_LOGE(LNN_LEDGER, "node is offline");
        return SOFTBUS_NETWORK_NODE_OFFLINE;
    }
    wifiCfg = LnnGetWifiCfg(info);
    if (wifiCfg == NULL) {
        LNN_LOGE(LNN_LEDGER, "get wifi cfg fail");
        return SOFTBUS_NETWORK_GET_DEVICE_INFO_ERR;
    }
    if (strcpy_s((char*)buf, len, wifiCfg) != EOK) {
        LNN_LOGE(LNN_LEDGER, "copy wifi cfg to buf fail");
        return SOFTBUS_MEM_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t DlGetChanList5g(const char *networkId, bool checkOnline, void *buf, uint32_t len)
{
    (void)checkOnline;
    NodeInfo *info = NULL;
    const char *chanList5g = NULL;

    RETURN_IF_GET_NODE_VALID(networkId, buf, info);
    if ((!LnnIsNodeOnline(info)) && (!info->metaInfo.isMetaNode)) {
        LNN_LOGE(LNN_LEDGER, "node is offline");
        return SOFTBUS_NETWORK_NODE_OFFLINE;
    }
    chanList5g = LnnGetChanList5g(info);
    if (chanList5g == NULL) {
        LNN_LOGE(LNN_LEDGER, "get chan list 5g fail");
        return SOFTBUS_NETWORK_GET_DEVICE_INFO_ERR;
    }
    if (strcpy_s((char*)buf, len, chanList5g) != EOK) {
        LNN_LOGE(LNN_LEDGER, "copy chan list 5g to buf fail");
        return SOFTBUS_MEM_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t DlGetP2pRole(const char *networkId, bool checkOnline, void *buf, uint32_t len)
{
    (void)checkOnline;
    NodeInfo *info = NULL;

    if (len != LNN_COMMON_LEN) {
        return SOFTBUS_INVALID_PARAM;
    }
    RETURN_IF_GET_NODE_VALID(networkId, buf, info);
    if ((!LnnIsNodeOnline(info)) && (!info->metaInfo.isMetaNode)) {
        LNN_LOGE(LNN_LEDGER, "node is offline");
        return SOFTBUS_NETWORK_NODE_OFFLINE;
    }
    *((int32_t *)buf) = LnnGetP2pRole(info);
    return SOFTBUS_OK;
}

static int32_t DlGetStateVersion(const char *networkId, bool checkOnline, void *buf, uint32_t len)
{
    (void)checkOnline;
    NodeInfo *info = NULL;

    if (len != LNN_COMMON_LEN) {
        return SOFTBUS_INVALID_PARAM;
    }
    RETURN_IF_GET_NODE_VALID(networkId, buf, info);
    if (!LnnIsNodeOnline(info)) {
        LNN_LOGE(LNN_LEDGER, "node is offline");
        return SOFTBUS_NETWORK_NODE_OFFLINE;
    }
    *((int32_t *)buf) = info->stateVersion;
    return SOFTBUS_OK;
}

static int32_t DlGetStaFrequency(const char *networkId, bool checkOnline, void *buf, uint32_t len)
{
    (void)checkOnline;
    NodeInfo *info = NULL;

    if (len != LNN_COMMON_LEN) {
        return SOFTBUS_INVALID_PARAM;
    }
    RETURN_IF_GET_NODE_VALID(networkId, buf, info);
    if ((!LnnIsNodeOnline(info)) && (!info->metaInfo.isMetaNode)) {
        LNN_LOGE(LNN_LEDGER, "node is offline");
        return SOFTBUS_NETWORK_NODE_OFFLINE;
    }
    *((int32_t *)buf) = LnnGetStaFrequency(info);
    return SOFTBUS_OK;
}

static int32_t DlGetNodeDataChangeFlag(const char *networkId, bool checkOnline, void *buf, uint32_t len)
{
    (void)checkOnline;
    NodeInfo *info = NULL;

    if (len != DATA_CHANGE_FLAG_BUF_LEN) {
        return SOFTBUS_INVALID_PARAM;
    }
    RETURN_IF_GET_NODE_VALID(networkId, buf, info);
    if (!LnnIsNodeOnline(info)) {
        LNN_LOGE(LNN_LEDGER, "node is offline");
        return SOFTBUS_NETWORK_NODE_OFFLINE;
    }
    *((int16_t *)buf) = (int16_t)LnnGetDataChangeFlag(info);
    return SOFTBUS_OK;
}

static int32_t DlGetNodeTlvNegoFlag(const char *networkId, bool checkOnline, void *buf, uint32_t len)
{
    NodeInfo *info = NULL;
    if (len != sizeof(bool)) {
        return SOFTBUS_INVALID_PARAM;
    }
    RETURN_IF_GET_NODE_VALID(networkId, buf, info);
    if (checkOnline && !LnnIsNodeOnline(info) && !IsMetaNode(info)) {
        LNN_LOGE(LNN_LEDGER, "node is offline");
        return SOFTBUS_NETWORK_NODE_OFFLINE;
    }
    *((bool *)buf) = IsFeatureSupport(info->feature, BIT_WIFI_DIRECT_TLV_NEGOTIATION);
    return SOFTBUS_OK;
}

static int32_t DlGetNodeScreenOnFlag(const char *networkId, bool checkOnline, void *buf, uint32_t len)
{
    NodeInfo *info = NULL;
    if (len != sizeof(bool)) {
        return SOFTBUS_INVALID_PARAM;
    }
    RETURN_IF_GET_NODE_VALID(networkId, buf, info);
    char *anonyNetworkId = NULL;
    Anonymize(networkId, &anonyNetworkId);
    int32_t ret = IsNodeInfoScreenStatusSupport(info);
    if (ret != SOFTBUS_OK) {
        LNN_LOGI(LNN_LEDGER, "%{public}s get node screen not support", AnonymizeWrapper(anonyNetworkId));
        AnonymizeFree(anonyNetworkId);
        return ret;
    }
    if (checkOnline && !LnnIsNodeOnline(info) && !IsMetaNode(info)) {
        LNN_LOGE(LNN_LEDGER, "%{public}s node is offline", AnonymizeWrapper(anonyNetworkId));
        AnonymizeFree(anonyNetworkId);
        return SOFTBUS_NETWORK_NODE_OFFLINE;
    }
    AnonymizeFree(anonyNetworkId);
    *((bool *)buf) = info->isScreenOn;
    return SOFTBUS_OK;
}

static int32_t DlGetAccountHash(const char *networkId, bool checkOnline, void *buf, uint32_t len)
{
    (void)checkOnline;
    NodeInfo *info = NULL;
    if (len != SHA_256_HASH_LEN) {
        return SOFTBUS_INVALID_PARAM;
    }
    RETURN_IF_GET_NODE_VALID(networkId, buf, info);
    if (!LnnIsNodeOnline(info)) {
        LNN_LOGE(LNN_LEDGER, "node is offline");
        return SOFTBUS_NETWORK_NODE_OFFLINE;
    }
    if (memcpy_s(buf, len, info->accountHash, SHA_256_HASH_LEN) != EOK) {
        LNN_LOGE(LNN_LEDGER, "memcpy account hash fail");
        return SOFTBUS_MEM_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t DlGetDeviceIrk(const char *networkId, bool checkOnline, void *buf, uint32_t len)
{
    (void)checkOnline;
    NodeInfo *info = NULL;
    RETURN_IF_GET_NODE_VALID(networkId, buf, info);
    if (memcpy_s(buf, len, info->rpaInfo.peerIrk, LFINDER_IRK_LEN) != EOK) {
        LNN_LOGE(LNN_LEDGER, "memcpy peerIrk fail");
        return SOFTBUS_MEM_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t DlGetDevicePubMac(const char *networkId, bool checkOnline, void *buf, uint32_t len)
{
    (void)checkOnline;
    NodeInfo *info = NULL;
    RETURN_IF_GET_NODE_VALID(networkId, buf, info);
    if (memcpy_s(buf, len, info->rpaInfo.publicAddress, LFINDER_MAC_ADDR_LEN) != EOK) {
        LNN_LOGE(LNN_LEDGER, "memcpy publicAddress fail");
        return SOFTBUS_MEM_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t DlGetDeviceCipherInfoKey(const char *networkId, bool checkOnline, void *buf, uint32_t len)
{
    (void)checkOnline;
    NodeInfo *info = NULL;
    RETURN_IF_GET_NODE_VALID(networkId, buf, info);
    if (memcpy_s(buf, len, info->cipherInfo.key, SESSION_KEY_LENGTH) != EOK) {
        LNN_LOGE(LNN_LEDGER, "memcpy cipher key fail");
        return SOFTBUS_MEM_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t DlGetDeviceCipherInfoIv(const char *networkId, bool checkOnline, void *buf, uint32_t len)
{
    (void)checkOnline;
    NodeInfo *info = NULL;
    RETURN_IF_GET_NODE_VALID(networkId, buf, info);
    if (memcpy_s(buf, len, info->cipherInfo.iv, BROADCAST_IV_LEN) != EOK) {
        LNN_LOGE(LNN_LEDGER, "memcpy cipher iv fail");
        return SOFTBUS_MEM_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t DlGetNodeP2pIp(const char *networkId, bool checkOnline, void *buf, uint32_t len)
{
    (void)checkOnline;
    NodeInfo *info = NULL;
    RETURN_IF_GET_NODE_VALID(networkId, buf, info);
    if (strcpy_s((char *)buf, len, info->p2pInfo.p2pIp) != EOK) {
        LNN_LOGE(LNN_LEDGER, "copy p2pIp to buf fail");
        return SOFTBUS_MEM_ERR;
    }
    return SOFTBUS_OK;
}

static DistributedLedgerKey g_dlKeyTable[] = {
    {STRING_KEY_HICE_VERSION, DlGetNodeSoftBusVersion},
    {STRING_KEY_DEV_UDID, DlGetDeviceUdid},
    {STRING_KEY_UUID, DlGetDeviceUuid},
    {STRING_KEY_DEV_TYPE, DlGetDeviceType},
    {STRING_KEY_DEV_NAME, DlGetDeviceName},
    {STRING_KEY_BT_MAC, DlGetBtMac},
    {STRING_KEY_WLAN_IP, DlGetWlanIp},
    {STRING_KEY_MASTER_NODE_UDID, DlGetMasterUdid},
    {STRING_KEY_P2P_MAC, DlGetP2pMac},
    {STRING_KEY_WIFI_CFG, DlGetWifiCfg},
    {STRING_KEY_CHAN_LIST_5G, DlGetChanList5g},
    {STRING_KEY_P2P_GO_MAC, DlGetP2pGoMac},
    {STRING_KEY_NODE_ADDR, DlGetNodeAddr},
    {STRING_KEY_OFFLINE_CODE, DlGetDeviceOfflineCode},
    {STRING_KEY_BLE_MAC, DlGetNodeBleMac},
    {STRING_KEY_WIFIDIRECT_ADDR, DlGetWifiDirectAddr},
    {STRING_KEY_P2P_IP, DlGetNodeP2pIp},
    {NUM_KEY_META_NODE, DlGetAuthType},
    {NUM_KEY_SESSION_PORT, DlGetSessionPort},
    {NUM_KEY_AUTH_PORT, DlGetAuthPort},
    {NUM_KEY_PROXY_PORT, DlGetProxyPort},
    {NUM_KEY_NET_CAP, DlGetNetCap},
    {NUM_KEY_FEATURE_CAPA, DlGetFeatureCap},
    {NUM_KEY_DISCOVERY_TYPE, DlGetNetType},
    {NUM_KEY_MASTER_NODE_WEIGHT, DlGetMasterWeight},
    {NUM_KEY_STA_FREQUENCY, DlGetStaFrequency},
    {NUM_KEY_P2P_ROLE, DlGetP2pRole},
    {NUM_KEY_STATE_VERSION, DlGetStateVersion},
    {NUM_KEY_DATA_CHANGE_FLAG, DlGetNodeDataChangeFlag},
    {NUM_KEY_DEV_TYPE_ID, DlGetDeviceTypeId},
    {NUM_KEY_STATIC_CAP_LEN, DlGetStaticCapLen},
    {NUM_KEY_DEVICE_SECURITY_LEVEL, DlGetDeviceSecurityLevel},
    {NUM_KEY_CONN_SUB_FEATURE_CAPA, DlGetConnSubFeatureCap},
    {BOOL_KEY_TLV_NEGOTIATION, DlGetNodeTlvNegoFlag},
    {BOOL_KEY_SCREEN_STATUS, DlGetNodeScreenOnFlag},
    {BYTE_KEY_ACCOUNT_HASH, DlGetAccountHash},
    {BYTE_KEY_IRK, DlGetDeviceIrk},
    {BYTE_KEY_PUB_MAC, DlGetDevicePubMac},
    {BYTE_KEY_BROADCAST_CIPHER_KEY, DlGetDeviceCipherInfoKey},
    {BYTE_KEY_BROADCAST_CIPHER_IV, DlGetDeviceCipherInfoIv},
    {BYTE_KEY_REMOTE_PTK, DlGetRemotePtk},
    {BYTE_KEY_STATIC_CAPABILITY, DlGetStaticCap}
};

bool LnnSetDLDeviceInfoName(const char *udid, const char *name)
{
    DoubleHashMap *map = &(LnnGetDistributedNetLedger()->distributedInfo);
    NodeInfo *info = NULL;
    if (udid == NULL || name == NULL) {
        LNN_LOGE(LNN_LEDGER, "para error");
        return false;
    }
    if (SoftBusMutexLock(&(LnnGetDistributedNetLedger()->lock)) != 0) {
        LNN_LOGE(LNN_LEDGER, "lock mutex fail");
        return false;
    }
    info = GetNodeInfoFromMap(map, udid);
    if (info == NULL) {
        LNN_LOGE(LNN_LEDGER, "udid not exist");
        goto EXIT;
    }
    if (strcmp(LnnGetDeviceName(&info->deviceInfo), name) == 0) {
        LNN_LOGI(LNN_LEDGER, "devicename not change");
        SoftBusMutexUnlock(&(LnnGetDistributedNetLedger()->lock));
        return true;
    }
    if (LnnSetDeviceName(&info->deviceInfo, name) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "set device name error");
        goto EXIT;
    }
    SoftBusMutexUnlock(&(LnnGetDistributedNetLedger()->lock));
    return true;
EXIT:
    SoftBusMutexUnlock(&(LnnGetDistributedNetLedger()->lock));
    return false;
}

bool LnnSetDLDeviceNickName(const char *networkId, const char *name)
{
    NodeInfo *node = NULL;
    if (networkId == NULL || name == NULL) {
        LNN_LOGE(LNN_LEDGER, "invalid param");
        return false;
    }
    if (SoftBusMutexLock(&(LnnGetDistributedNetLedger()->lock)) != 0) {
        LNN_LOGE(LNN_LEDGER, "lock mutex fail");
        return false;
    }
    node = LnnGetNodeInfoById(networkId, CATEGORY_NETWORK_ID);
    if (node == NULL) {
        LNN_LOGE(LNN_LEDGER, "networkId not found");
        goto EXIT;
    }
    if (strcpy_s(node->deviceInfo.nickName, DEVICE_NAME_BUF_LEN, name) != EOK) {
        goto EXIT;
    }
    (void)SoftBusMutexUnlock(&(LnnGetDistributedNetLedger()->lock));
    return true;
EXIT:
    (void)SoftBusMutexUnlock(&(LnnGetDistributedNetLedger()->lock));
    return false;
}

int32_t LnnSetDLUnifiedDeviceName(const char *udid, const char *name)
{
    DoubleHashMap *map = &(LnnGetDistributedNetLedger()->distributedInfo);
    NodeInfo *info = NULL;
    if (udid == NULL || name == NULL) {
        LNN_LOGE(LNN_LEDGER, "param error");
        return SOFTBUS_INVALID_PARAM;
    }
    if (SoftBusMutexLock(&(LnnGetDistributedNetLedger()->lock)) != 0) {
        LNN_LOGE(LNN_LEDGER, "lock mutex fail");
        return SOFTBUS_LOCK_ERR;
    }
    info = GetNodeInfoFromMap(map, udid);
    if (info == NULL) {
        LNN_LOGE(LNN_LEDGER, "udid not exist");
        goto EXIT;
    }
    if (strcmp(info->deviceInfo.unifiedName, name) == 0) {
        LNN_LOGI(LNN_LEDGER, "deviceunifiedname not change");
        SoftBusMutexUnlock(&(LnnGetDistributedNetLedger()->lock));
        return SOFTBUS_OK;
    }
    if (strncpy_s(info->deviceInfo.unifiedName, DEVICE_NAME_BUF_LEN, name, strlen(name)) != EOK) {
        LNN_LOGE(LNN_LEDGER, "set deviceunifiedname error");
        SoftBusMutexUnlock(&(LnnGetDistributedNetLedger()->lock));
        return SOFTBUS_STRCPY_ERR;
    }
    SoftBusMutexUnlock(&(LnnGetDistributedNetLedger()->lock));
    return SOFTBUS_OK;
EXIT:
    SoftBusMutexUnlock(&(LnnGetDistributedNetLedger()->lock));
    return SOFTBUS_NOT_FIND;
}

int32_t LnnSetDLUnifiedDefaultDeviceName(const char *udid, const char *name)
{
    DoubleHashMap *map = &(LnnGetDistributedNetLedger()->distributedInfo);
    NodeInfo *info = NULL;
    if (udid == NULL || name == NULL) {
        LNN_LOGE(LNN_LEDGER, "param error");
        return SOFTBUS_INVALID_PARAM;
    }
    if (SoftBusMutexLock(&(LnnGetDistributedNetLedger()->lock)) != 0) {
        LNN_LOGE(LNN_LEDGER, "lock mutex fail");
        return SOFTBUS_LOCK_ERR;
    }
    info = GetNodeInfoFromMap(map, udid);
    if (info == NULL) {
        LNN_LOGE(LNN_LEDGER, "udid not exist");
        goto EXIT;
    }
    if (strcmp(info->deviceInfo.unifiedDefaultName, name) == 0) {
        LNN_LOGI(LNN_LEDGER, "deviceunifiedDefaultName not change");
        SoftBusMutexUnlock(&(LnnGetDistributedNetLedger()->lock));
        return SOFTBUS_OK;
    }
    if (strncpy_s(info->deviceInfo.unifiedDefaultName, DEVICE_NAME_BUF_LEN, name, strlen(name)) != EOK) {
        LNN_LOGE(LNN_LEDGER, "set deviceunifiedDefaultName error");
        SoftBusMutexUnlock(&(LnnGetDistributedNetLedger()->lock));
        return SOFTBUS_STRCPY_ERR;
    }
    SoftBusMutexUnlock(&(LnnGetDistributedNetLedger()->lock));
    return SOFTBUS_OK;
EXIT:
    SoftBusMutexUnlock(&(LnnGetDistributedNetLedger()->lock));
    return SOFTBUS_NOT_FIND;
}

int32_t LnnSetDLDeviceNickNameByUdid(const char *udid, const char *name)
{
    DoubleHashMap *map = &(LnnGetDistributedNetLedger()->distributedInfo);
    NodeInfo *info = NULL;
    if (udid == NULL || name == NULL) {
        LNN_LOGE(LNN_LEDGER, "param error");
        return SOFTBUS_INVALID_PARAM;
    }
    if (SoftBusMutexLock(&(LnnGetDistributedNetLedger()->lock)) != 0) {
        LNN_LOGE(LNN_LEDGER, "lock mutex fail");
        return SOFTBUS_LOCK_ERR;
    }
    info = GetNodeInfoFromMap(map, udid);
    if (info == NULL) {
        LNN_LOGE(LNN_LEDGER, "udid not exist");
        goto EXIT;
    }
    if (strcmp(info->deviceInfo.nickName, name) == 0) {
        LNN_LOGI(LNN_LEDGER, "devicenickName not change");
        SoftBusMutexUnlock(&(LnnGetDistributedNetLedger()->lock));
        return SOFTBUS_OK;
    }
    if (strncpy_s(info->deviceInfo.nickName, DEVICE_NAME_BUF_LEN, name, strlen(name)) != EOK) {
        LNN_LOGE(LNN_LEDGER, "set devicenickName error");
        SoftBusMutexUnlock(&(LnnGetDistributedNetLedger()->lock));
        return SOFTBUS_STRCPY_ERR;
    }
    SoftBusMutexUnlock(&(LnnGetDistributedNetLedger()->lock));
    return SOFTBUS_OK;
EXIT:
    SoftBusMutexUnlock(&(LnnGetDistributedNetLedger()->lock));
    return SOFTBUS_NOT_FIND;
}

int32_t LnnSetDLDeviceStateVersion(const char *udid, int32_t stateVersion)
{
    DoubleHashMap *map = &(LnnGetDistributedNetLedger()->distributedInfo);
    NodeInfo *info = NULL;
    if (udid == NULL) {
        LNN_LOGE(LNN_LEDGER, "param error");
        return SOFTBUS_INVALID_PARAM;
    }
    if (SoftBusMutexLock(&(LnnGetDistributedNetLedger()->lock)) != 0) {
        LNN_LOGE(LNN_LEDGER, "lock mutex fail");
        return SOFTBUS_LOCK_ERR;
    }
    info = GetNodeInfoFromMap(map, udid);
    if (info == NULL) {
        LNN_LOGE(LNN_LEDGER, "udid not exist");
        goto EXIT;
    }
    if (info->stateVersion == stateVersion) {
        LNN_LOGI(LNN_LEDGER, "device stateversion not change");
        SoftBusMutexUnlock(&(LnnGetDistributedNetLedger()->lock));
        return SOFTBUS_OK;
    }
    info->stateVersion = stateVersion;
    SoftBusMutexUnlock(&(LnnGetDistributedNetLedger()->lock));
    return SOFTBUS_OK;
EXIT:
    SoftBusMutexUnlock(&(LnnGetDistributedNetLedger()->lock));
    return SOFTBUS_NOT_FIND;
}

int32_t LnnSetDLDeviceBroadcastCipherKey(const char *udid, const void *cipherKey)
{
    DoubleHashMap *map = &(LnnGetDistributedNetLedger()->distributedInfo);
    NodeInfo *info = NULL;
    if (udid == NULL) {
        LNN_LOGE(LNN_LEDGER, "param error");
        return SOFTBUS_INVALID_PARAM;
    }
    if (SoftBusMutexLock(&(LnnGetDistributedNetLedger()->lock)) != 0) {
        LNN_LOGE(LNN_LEDGER, "lock mutex fail");
        return SOFTBUS_LOCK_ERR;
    }
    info = GetNodeInfoFromMap(map, udid);
    if (info == NULL) {
        LNN_LOGE(LNN_LEDGER, "udid not exist");
        goto EXIT;
    }
    if (memcpy_s((char *)info->cipherInfo.key, SESSION_KEY_LENGTH, cipherKey, SESSION_KEY_LENGTH) != EOK) {
        LNN_LOGE(LNN_LEDGER, "set BroadcastcipherKey error");
        SoftBusMutexUnlock(&(LnnGetDistributedNetLedger()->lock));
        return SOFTBUS_MEM_ERR;
    }
    SoftBusMutexUnlock(&(LnnGetDistributedNetLedger()->lock));
    return SOFTBUS_OK;
EXIT:
    SoftBusMutexUnlock(&(LnnGetDistributedNetLedger()->lock));
    return SOFTBUS_NOT_FIND;
}

int32_t LnnSetDLDeviceBroadcastCipherIv(const char *udid, const void *cipherIv)
{
    DoubleHashMap *map = &(LnnGetDistributedNetLedger()->distributedInfo);
    NodeInfo *info = NULL;
    if (udid == NULL) {
        LNN_LOGE(LNN_LEDGER, "param error");
        return SOFTBUS_INVALID_PARAM;
    }
    if (SoftBusMutexLock(&(LnnGetDistributedNetLedger()->lock)) != 0) {
        LNN_LOGE(LNN_LEDGER, "lock mutex fail");
        return SOFTBUS_LOCK_ERR;
    }
    info = GetNodeInfoFromMap(map, udid);
    if (info == NULL) {
        LNN_LOGE(LNN_LEDGER, "udid not exist");
        goto EXIT;
    }
    if (memcpy_s((char *)info->cipherInfo.iv, BROADCAST_IV_LEN, cipherIv, BROADCAST_IV_LEN) != EOK) {
        LNN_LOGE(LNN_LEDGER, "set BroadcastcipherKey error");
        SoftBusMutexUnlock(&(LnnGetDistributedNetLedger()->lock));
        return SOFTBUS_MEM_ERR;
    }
    SoftBusMutexUnlock(&(LnnGetDistributedNetLedger()->lock));
    return SOFTBUS_OK;
EXIT:
    SoftBusMutexUnlock(&(LnnGetDistributedNetLedger()->lock));
    return SOFTBUS_NOT_FIND;
}

bool LnnSetDLP2pInfo(const char *networkId, const P2pInfo *info)
{
    NodeInfo *node = NULL;
    if (networkId == NULL || info == NULL) {
        LNN_LOGE(LNN_LEDGER, "invalid param");
        return false;
    }
    if (SoftBusMutexLock(&(LnnGetDistributedNetLedger()->lock)) != 0) {
        LNN_LOGE(LNN_LEDGER, "lock mutex fail");
        return false;
    }
    node = LnnGetNodeInfoById(networkId, CATEGORY_NETWORK_ID);
    if (node == NULL) {
        LNN_LOGE(LNN_LEDGER, "udid not found");
        goto EXIT;
    }
    if (LnnSetP2pRole(node, info->p2pRole) != SOFTBUS_OK ||
        LnnSetP2pMac(node, info->p2pMac) != SOFTBUS_OK ||
        LnnSetP2pGoMac(node, info->goMac) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "set p2p info fail");
        goto EXIT;
    }
    SoftBusMutexUnlock(&(LnnGetDistributedNetLedger()->lock));
    return true;
EXIT:
    SoftBusMutexUnlock(&(LnnGetDistributedNetLedger()->lock));
    return false;
}

bool LnnSetDlPtk(const char *networkId, const char *remotePtk)
{
    NodeInfo *node = NULL;
    if (networkId == NULL || remotePtk == NULL) {
        LNN_LOGE(LNN_LEDGER, "invalid param");
        return false;
    }
    if (SoftBusMutexLock(&(LnnGetDistributedNetLedger()->lock)) != 0) {
        LNN_LOGE(LNN_LEDGER, "lock mutex fail");
        return false;
    }
    node = LnnGetNodeInfoById(networkId, CATEGORY_NETWORK_ID);
    if (node == NULL) {
        SoftBusMutexUnlock(&(LnnGetDistributedNetLedger()->lock));
        LNN_LOGE(LNN_LEDGER, "get node info fail");
        return false;
    }
    LnnDumpRemotePtk(node->remotePtk, remotePtk, "set remote ptk");
    if (LnnSetPtk(node, remotePtk) != SOFTBUS_OK) {
        SoftBusMutexUnlock(&(LnnGetDistributedNetLedger()->lock));
        LNN_LOGE(LNN_LEDGER, "set ptk fail");
        return false;
    }
    char udidHash[SHORT_UDID_HASH_HEX_LEN + 1] = { 0 };
    if (LnnGenerateHexStringHash(
        (const unsigned char *)node->deviceInfo.deviceUdid, udidHash, SHORT_UDID_HASH_HEX_LEN) != SOFTBUS_OK) {
        SoftBusMutexUnlock(&(LnnGetDistributedNetLedger()->lock));
        LNN_LOGE(LNN_LEDGER, "Generate UDID HexStringHash fail");
        return false;
    }
    SoftBusMutexUnlock(&(LnnGetDistributedNetLedger()->lock));
    NodeInfo cacheInfo;
    (void)memset_s(&cacheInfo, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    if (LnnRetrieveDeviceInfo(udidHash, &cacheInfo) != SOFTBUS_OK) {
        LNN_LOGD(LNN_LEDGER, "no this device info in deviceCacheInfoMap, ignore update");
        return true;
    }
    if (memcmp(cacheInfo.remotePtk, remotePtk, PTK_DEFAULT_LEN) == 0) {
        LNN_LOGD(LNN_LEDGER, "ptk is same, ignore update");
        return true;
    }
    if (memcpy_s(cacheInfo.remotePtk, PTK_DEFAULT_LEN, remotePtk, PTK_DEFAULT_LEN) != EOK) {
        LNN_LOGE(LNN_LEDGER, "memcpy_s ptk fail");
        return true;
    }
    (void)LnnSaveRemoteDeviceInfo(&cacheInfo);
    return true;
}

int32_t LnnGetRemoteStrInfo(const char *networkId, InfoKey key, char *info, uint32_t len)
{
    uint32_t i;
    int32_t ret;
    if (!IsValidString(networkId, ID_MAX_LEN)) {
        return SOFTBUS_INVALID_PARAM;
    }
    if (info == NULL) {
        LNN_LOGE(LNN_LEDGER, "info is null");
        return SOFTBUS_INVALID_PARAM;
    }
    if (key >= STRING_KEY_END) {
        LNN_LOGE(LNN_LEDGER, "KEY error");
        return SOFTBUS_INVALID_PARAM;
    }
    if (SoftBusMutexLock(&(LnnGetDistributedNetLedger()->lock)) != 0) {
        LNN_LOGE(LNN_LEDGER, "lock mutex fail");
        return SOFTBUS_LOCK_ERR;
    }
    for (i = 0; i < sizeof(g_dlKeyTable) / sizeof(DistributedLedgerKey); i++) {
        if (key == g_dlKeyTable[i].key) {
            if (g_dlKeyTable[i].getInfo != NULL) {
                ret = g_dlKeyTable[i].getInfo(networkId, true, (void *)info, len);
                SoftBusMutexUnlock(&(LnnGetDistributedNetLedger()->lock));
                return ret;
            }
        }
    }
    SoftBusMutexUnlock(&(LnnGetDistributedNetLedger()->lock));
    LNN_LOGE(LNN_LEDGER, "KEY NOT exist");
    return SOFTBUS_NOT_FIND;
}

int32_t LnnGetRemoteNumInfo(const char *networkId, InfoKey key, int32_t *info)
{
    uint32_t i;
    int32_t ret;
    if (!IsValidString(networkId, ID_MAX_LEN)) {
        LNN_LOGE(LNN_LEDGER, "networkId is invalid");
        return SOFTBUS_INVALID_PARAM;
    }
    if (info == NULL) {
        LNN_LOGE(LNN_LEDGER, "info is null");
        return SOFTBUS_INVALID_PARAM;
    }
    if (key < NUM_KEY_BEGIN || key >= NUM_KEY_END) {
        LNN_LOGE(LNN_LEDGER, "KEY error");
        return SOFTBUS_INVALID_PARAM;
    }
    if (SoftBusMutexLock(&(LnnGetDistributedNetLedger()->lock)) != 0) {
        LNN_LOGE(LNN_LEDGER, "lock mutex fail");
        return SOFTBUS_LOCK_ERR;
    }
    for (i = 0; i < sizeof(g_dlKeyTable) / sizeof(DistributedLedgerKey); i++) {
        if (key == g_dlKeyTable[i].key) {
            if (g_dlKeyTable[i].getInfo != NULL) {
                ret = g_dlKeyTable[i].getInfo(networkId, true, (void *)info, LNN_COMMON_LEN);
                SoftBusMutexUnlock(&(LnnGetDistributedNetLedger()->lock));
                return ret;
            }
        }
    }
    SoftBusMutexUnlock(&(LnnGetDistributedNetLedger()->lock));
    LNN_LOGE(LNN_LEDGER, "KEY NOT exist");
    return SOFTBUS_NOT_FIND;
}

int32_t LnnGetRemoteNumU32Info(const char *networkId, InfoKey key, uint32_t *info)
{
    uint32_t i;
    int32_t ret;
    if (!IsValidString(networkId, ID_MAX_LEN)) {
        LNN_LOGE(LNN_LEDGER, "networkId is invalid");
        return SOFTBUS_INVALID_PARAM;
    }
    if (info == NULL) {
        LNN_LOGE(LNN_LEDGER, "info is null");
        return SOFTBUS_INVALID_PARAM;
    }
    if (key < NUM_KEY_BEGIN || key >= NUM_KEY_END) {
        LNN_LOGE(LNN_LEDGER, "KEY error");
        return SOFTBUS_INVALID_PARAM;
    }
    if (SoftBusMutexLock(&(LnnGetDistributedNetLedger()->lock)) != 0) {
        LNN_LOGE(LNN_LEDGER, "lock mutex fail");
        return SOFTBUS_LOCK_ERR;
    }
    for (i = 0; i < sizeof(g_dlKeyTable) / sizeof(DistributedLedgerKey); i++) {
        if (key == g_dlKeyTable[i].key) {
            if (g_dlKeyTable[i].getInfo != NULL) {
                ret = g_dlKeyTable[i].getInfo(networkId, true, (void *)info, LNN_COMMON_LEN);
                SoftBusMutexUnlock(&(LnnGetDistributedNetLedger()->lock));
                return ret;
            }
        }
    }
    SoftBusMutexUnlock(&(LnnGetDistributedNetLedger()->lock));
    LNN_LOGE(LNN_LEDGER, "KEY NOT exist");
    return SOFTBUS_NOT_FIND;
}

int32_t LnnGetRemoteNumU64Info(const char *networkId, InfoKey key, uint64_t *info)
{
    uint32_t i;
    int32_t ret;
    if (!IsValidString(networkId, ID_MAX_LEN)) {
        return SOFTBUS_INVALID_PARAM;
    }
    if (info == NULL) {
        LNN_LOGE(LNN_LEDGER, "info is null");
        return SOFTBUS_INVALID_PARAM;
    }
    if (key < NUM_KEY_BEGIN || key >= NUM_KEY_END) {
        LNN_LOGE(LNN_LEDGER, "KEY error");
        return SOFTBUS_INVALID_PARAM;
    }
    if (SoftBusMutexLock(&(LnnGetDistributedNetLedger()->lock)) != 0) {
        LNN_LOGE(LNN_LEDGER, "lock mutex fail");
        return SOFTBUS_LOCK_ERR;
    }
    for (i = 0; i < sizeof(g_dlKeyTable) / sizeof(DistributedLedgerKey); i++) {
        if (key == g_dlKeyTable[i].key) {
            if (g_dlKeyTable[i].getInfo != NULL) {
                ret = g_dlKeyTable[i].getInfo(networkId, true, (void *)info, LNN_COMMON_LEN_64);
                SoftBusMutexUnlock(&(LnnGetDistributedNetLedger()->lock));
                return ret;
            }
        }
    }
    SoftBusMutexUnlock(&(LnnGetDistributedNetLedger()->lock));
    LNN_LOGE(LNN_LEDGER, "KEY NOT exist");
    return SOFTBUS_NOT_FIND;
}

int32_t LnnGetRemoteNum16Info(const char *networkId, InfoKey key, int16_t *info)
{
    uint32_t i;
    int32_t ret;
    if (!IsValidString(networkId, ID_MAX_LEN)) {
        return SOFTBUS_INVALID_PARAM;
    }
    if (info == NULL) {
        LNN_LOGE(LNN_LEDGER, "info is null");
        return SOFTBUS_INVALID_PARAM;
    }
    if (key < NUM_KEY_BEGIN || key >= NUM_KEY_END) {
        LNN_LOGE(LNN_LEDGER, "KEY error");
        return SOFTBUS_INVALID_PARAM;
    }
    if (SoftBusMutexLock(&(LnnGetDistributedNetLedger()->lock)) != 0) {
        LNN_LOGE(LNN_LEDGER, "lock mutex fail");
        return SOFTBUS_LOCK_ERR;
    }
    for (i = 0; i < sizeof(g_dlKeyTable) / sizeof(DistributedLedgerKey); i++) {
        if (key == g_dlKeyTable[i].key) {
            if (g_dlKeyTable[i].getInfo != NULL) {
                ret = g_dlKeyTable[i].getInfo(networkId, true, (void *)info, sizeof(int16_t));
                SoftBusMutexUnlock(&(LnnGetDistributedNetLedger()->lock));
                return ret;
            }
        }
    }
    SoftBusMutexUnlock(&(LnnGetDistributedNetLedger()->lock));
    LNN_LOGE(LNN_LEDGER, "KEY NOT exist");
    return SOFTBUS_NOT_FIND;
}

static int32_t LnnGetRemoteBoolInfoCommon(const char *networkId, bool checkOnline, InfoKey key, bool *info)
{
    uint32_t i;
    int32_t ret;
    if (!IsValidString(networkId, ID_MAX_LEN)) {
        return SOFTBUS_INVALID_PARAM;
    }
    if (info == NULL) {
        LNN_LOGE(LNN_LEDGER, "info is null");
        return SOFTBUS_INVALID_PARAM;
    }
    if (key < BOOL_KEY_BEGIN || key >= BOOL_KEY_END) {
        LNN_LOGE(LNN_LEDGER, "KEY error");
        return SOFTBUS_INVALID_PARAM;
    }
    if (SoftBusMutexLock(&(LnnGetDistributedNetLedger()->lock)) != 0) {
        LNN_LOGE(LNN_LEDGER, "lock mutex fail");
        return SOFTBUS_LOCK_ERR;
    }
    for (i = 0; i < sizeof(g_dlKeyTable) / sizeof(DistributedLedgerKey); i++) {
        if (key == g_dlKeyTable[i].key) {
            if (g_dlKeyTable[i].getInfo != NULL) {
                ret = g_dlKeyTable[i].getInfo(networkId, checkOnline, (void *)info, sizeof(bool));
                SoftBusMutexUnlock(&(LnnGetDistributedNetLedger()->lock));
                return ret;
            }
        }
    }
    SoftBusMutexUnlock(&(LnnGetDistributedNetLedger()->lock));
    LNN_LOGE(LNN_LEDGER, "KEY NOT exist");
    return SOFTBUS_NOT_FIND;
}

int32_t LnnGetRemoteBoolInfo(const char *networkId, InfoKey key, bool *info)
{
    return LnnGetRemoteBoolInfoCommon(networkId, true, key, info);
}

int32_t LnnGetRemoteBoolInfoIgnoreOnline(const char *networkId, InfoKey key, bool *info)
{
    return LnnGetRemoteBoolInfoCommon(networkId, false, key, info);
}

int32_t LnnGetRemoteByteInfo(const char *networkId, InfoKey key, uint8_t *info, uint32_t len)
{
    uint32_t i;
    int32_t ret;
    if (!IsValidString(networkId, ID_MAX_LEN) || info == NULL) {
        LNN_LOGE(LNN_LEDGER, "para error.");
        return SOFTBUS_INVALID_PARAM;
    }
    if (key < BYTE_KEY_BEGIN || key >= BYTE_KEY_END) {
        LNN_LOGE(LNN_LEDGER, "KEY error.");
        return SOFTBUS_INVALID_PARAM;
    }
    if (SoftBusMutexLock(&(LnnGetDistributedNetLedger()->lock)) != 0) {
        LNN_LOGE(LNN_LEDGER, "lock mutex fail!");
        return SOFTBUS_LOCK_ERR;
    }
    for (i = 0; i < sizeof(g_dlKeyTable) / sizeof(DistributedLedgerKey); i++) {
        if (key == g_dlKeyTable[i].key) {
            if (g_dlKeyTable[i].getInfo != NULL) {
                ret = g_dlKeyTable[i].getInfo(networkId, true, info, len);
                SoftBusMutexUnlock(&(LnnGetDistributedNetLedger()->lock));
                return ret;
            }
        }
    }
    SoftBusMutexUnlock(&(LnnGetDistributedNetLedger()->lock));
    LNN_LOGE(LNN_LEDGER, "KEY NOT exist.");
    return SOFTBUS_NOT_FIND;
}

int32_t LnnGetNetworkIdByBtMac(const char *btMac, char *buf, uint32_t len)
{
    if (btMac == NULL || btMac[0] == '\0' || buf == NULL) {
        LNN_LOGE(LNN_LEDGER, "btMac is empty");
        return SOFTBUS_INVALID_PARAM;
    }
    if (SoftBusMutexLock(&(LnnGetDistributedNetLedger()->lock)) != 0) {
        LNN_LOGE(LNN_LEDGER, "lock mutex fail");
        return SOFTBUS_LOCK_ERR;
    }
    MapIterator *it = LnnMapInitIterator(&(LnnGetDistributedNetLedger()->distributedInfo.udidMap));
    if (it == NULL) {
        LNN_LOGE(LNN_LEDGER, "it is null");
        (void)SoftBusMutexUnlock(&(LnnGetDistributedNetLedger()->lock));
        return SOFTBUS_NETWORK_MAP_INIT_FAILED;
    }
    while (LnnMapHasNext(it)) {
        it = LnnMapNext(it);
        if (it == NULL) {
            (void)SoftBusMutexUnlock(&(LnnGetDistributedNetLedger()->lock));
            return SOFTBUS_NETWORK_MAP_INIT_FAILED;
        }
        NodeInfo *nodeInfo = (NodeInfo *)it->node->value;
        if ((LnnIsNodeOnline(nodeInfo) || nodeInfo->metaInfo.isMetaNode) &&
            StrCmpIgnoreCase(nodeInfo->connectInfo.macAddr, btMac) == 0) {
            if (strcpy_s(buf, len, nodeInfo->networkId) != EOK) {
                LNN_LOGE(LNN_LEDGER, "strcpy_s networkId fail");
                LnnMapDeinitIterator(it);
                (void)SoftBusMutexUnlock(&(LnnGetDistributedNetLedger()->lock));
                return SOFTBUS_MEM_ERR;
            }
            LnnMapDeinitIterator(it);
            (void)SoftBusMutexUnlock(&(LnnGetDistributedNetLedger()->lock));
            return SOFTBUS_OK;
        }
    }
    LnnMapDeinitIterator(it);
    (void)SoftBusMutexUnlock(&(LnnGetDistributedNetLedger()->lock));
    return SOFTBUS_NOT_FIND;
}

int32_t LnnGetNetworkIdByUdidHash(const uint8_t *udidHash, uint32_t udidHashLen, char *buf, uint32_t len,
    bool needOnline)
{
    if (udidHash == NULL || buf == NULL || udidHashLen == 0) {
        LNN_LOGE(LNN_LEDGER, "udidHash is empty");
        return SOFTBUS_INVALID_PARAM;
    }
    if (SoftBusMutexLock(&(LnnGetDistributedNetLedger()->lock)) != 0) {
        LNN_LOGE(LNN_LEDGER, "lock mutex fail");
        return SOFTBUS_LOCK_ERR;
    }
    MapIterator *it = LnnMapInitIterator(&(LnnGetDistributedNetLedger()->distributedInfo.udidMap));
    if (it == NULL) {
        LNN_LOGE(LNN_LEDGER, "it is null");
        (void)SoftBusMutexUnlock(&(LnnGetDistributedNetLedger()->lock));
        return SOFTBUS_NETWORK_MAP_INIT_FAILED;
    }
    uint8_t nodeUdidHash[SHA_256_HASH_LEN] = {0};
    while (LnnMapHasNext(it)) {
        it = LnnMapNext(it);
        if (it == NULL) {
            (void)SoftBusMutexUnlock(&(LnnGetDistributedNetLedger()->lock));
            return SOFTBUS_NETWORK_MAP_INIT_FAILED;
        }
        NodeInfo *nodeInfo = (NodeInfo *)it->node->value;
        if (!needOnline || LnnIsNodeOnline(nodeInfo) || nodeInfo->metaInfo.isMetaNode) {
            if (SoftBusGenerateStrHash((uint8_t*)nodeInfo->deviceInfo.deviceUdid,
                strlen(nodeInfo->deviceInfo.deviceUdid), nodeUdidHash) != SOFTBUS_OK) {
                continue;
            }
            if (memcmp(nodeUdidHash, udidHash, SHA_256_HASH_LEN) != 0) {
                continue;
            }
            if (strcpy_s(buf, len, nodeInfo->networkId) != EOK) {
                LNN_LOGE(LNN_LEDGER, "strcpy_s networkId fail");
                LnnMapDeinitIterator(it);
                (void)SoftBusMutexUnlock(&(LnnGetDistributedNetLedger()->lock));
                return SOFTBUS_MEM_ERR;
            }
            LnnMapDeinitIterator(it);
            (void)SoftBusMutexUnlock(&(LnnGetDistributedNetLedger()->lock));
            return SOFTBUS_OK;
        }
    }
    LnnMapDeinitIterator(it);
    (void)SoftBusMutexUnlock(&(LnnGetDistributedNetLedger()->lock));
    return SOFTBUS_NOT_FIND;
}

int32_t LnnGetConnSubFeatureByUdidHashStr(const char *udidHashStr, uint64_t *connSubFeature)
{
    if (udidHashStr == NULL || udidHashStr[0] == '\0' || connSubFeature == NULL) {
        LNN_LOGE(LNN_LEDGER, "para is empty");
        return SOFTBUS_INVALID_PARAM;
    }
    if (SoftBusMutexLock(&(LnnGetDistributedNetLedger()->lock)) != 0) {
        LNN_LOGE(LNN_LEDGER, "lock mutex fail");
        return SOFTBUS_LOCK_ERR;
    }
    MapIterator *it = LnnMapInitIterator(&(LnnGetDistributedNetLedger()->distributedInfo.udidMap));
    if (it == NULL) {
        LNN_LOGE(LNN_LEDGER, "it is null");
        (void)SoftBusMutexUnlock(&(LnnGetDistributedNetLedger()->lock));
        return SOFTBUS_NETWORK_MAP_INIT_FAILED;
    }
    unsigned char shortUdidHashStr[SHORT_UDID_HASH_HEX_LEN + 1] = {0};
    while (LnnMapHasNext(it)) {
        it = LnnMapNext(it);
        if (it == NULL) {
            (void)SoftBusMutexUnlock(&(LnnGetDistributedNetLedger()->lock));
            return SOFTBUS_NETWORK_MAP_INIT_FAILED;
        }
        NodeInfo *nodeInfo = (NodeInfo *)it->node->value;
        if (LnnIsNodeOnline(nodeInfo)) {
            if (GenerateStrHashAndConvertToHexString((const unsigned char *)nodeInfo->deviceInfo.deviceUdid,
                SHORT_UDID_HASH_HEX_LEN, shortUdidHashStr, SHORT_UDID_HASH_HEX_LEN + 1) != SOFTBUS_OK) {
                continue;
            }
            if (memcmp(shortUdidHashStr, udidHashStr, SHORT_UDID_HASH_HEX_LEN) != 0) {
                continue;
            }
            *connSubFeature = nodeInfo->connSubFeature;
            LnnMapDeinitIterator(it);
            (void)SoftBusMutexUnlock(&(LnnGetDistributedNetLedger()->lock));
            return SOFTBUS_OK;
        }
    }
    LnnMapDeinitIterator(it);
    (void)SoftBusMutexUnlock(&(LnnGetDistributedNetLedger()->lock));
    return SOFTBUS_NOT_FIND;
}

int32_t LnnGetNetworkIdByUuid(const char *uuid, char *buf, uint32_t len)
{
    if (!IsValidString(uuid, ID_MAX_LEN)) {
        LNN_LOGE(LNN_LEDGER, "uuid is invalid");
        return SOFTBUS_INVALID_PARAM;
    }

    if (SoftBusMutexLock(&(LnnGetDistributedNetLedger()->lock)) != 0) {
        LNN_LOGE(LNN_LEDGER, "lock mutex fail");
        return SOFTBUS_LOCK_ERR;
    }
    NodeInfo *nodeInfo = LnnGetNodeInfoById(uuid, CATEGORY_UUID);
    if (nodeInfo == NULL) {
        LNN_LOGE(LNN_LEDGER, "get info fail");
        (void)SoftBusMutexUnlock(&(LnnGetDistributedNetLedger()->lock));
        return SOFTBUS_NOT_FIND;
    }
    if (strncpy_s(buf, len, nodeInfo->networkId, strlen(nodeInfo->networkId)) != EOK) {
        LNN_LOGE(LNN_LEDGER, "STR COPY ERROR");
        (void)SoftBusMutexUnlock(&(LnnGetDistributedNetLedger()->lock));
        return SOFTBUS_MEM_ERR;
    }
    (void)SoftBusMutexUnlock(&(LnnGetDistributedNetLedger()->lock));
    return SOFTBUS_OK;
}

int32_t LnnGetNetworkIdByUdid(const char *udid, char *buf, uint32_t len)
{
    if (!IsValidString(udid, ID_MAX_LEN)) {
        LNN_LOGE(LNN_LEDGER, "udid is invalid");
        return SOFTBUS_INVALID_PARAM;
    }

    if (SoftBusMutexLock(&(LnnGetDistributedNetLedger()->lock)) != 0) {
        LNN_LOGE(LNN_LEDGER, "lock mutex fail");
        return SOFTBUS_LOCK_ERR;
    }
    NodeInfo *nodeInfo = LnnGetNodeInfoById(udid, CATEGORY_UDID);
    if (nodeInfo == NULL) {
        LNN_LOGE(LNN_LEDGER, "get info fail");
        (void)SoftBusMutexUnlock(&(LnnGetDistributedNetLedger()->lock));
        return SOFTBUS_NOT_FIND;
    }
    if (strncpy_s(buf, len, nodeInfo->networkId, strlen(nodeInfo->networkId)) != EOK) {
        LNN_LOGE(LNN_LEDGER, "STR COPY ERROR");
        (void)SoftBusMutexUnlock(&(LnnGetDistributedNetLedger()->lock));
        return SOFTBUS_MEM_ERR;
    }
    (void)SoftBusMutexUnlock(&(LnnGetDistributedNetLedger()->lock));
    return SOFTBUS_OK;
}

int32_t LnnGetDLOnlineTimestamp(const char *networkId, uint64_t *timestamp)
{
    if (SoftBusMutexLock(&(LnnGetDistributedNetLedger()->lock)) != 0) {
        LNN_LOGE(LNN_LEDGER, "lock mutex fail");
        return SOFTBUS_LOCK_ERR;
    }
    NodeInfo *nodeInfo = LnnGetNodeInfoById(networkId, CATEGORY_NETWORK_ID);
    if (nodeInfo == NULL) {
        LNN_LOGE(LNN_LEDGER, "get info fail");
        (void)SoftBusMutexUnlock(&(LnnGetDistributedNetLedger()->lock));
        return SOFTBUS_NOT_FIND;
    }
    *timestamp = nodeInfo->onlinetTimestamp;
    (void)SoftBusMutexUnlock(&(LnnGetDistributedNetLedger()->lock));
    return SOFTBUS_OK;
}

int32_t LnnGetDLHeartbeatTimestamp(const char *networkId, uint64_t *timestamp)
{
    if (SoftBusMutexLock(&(LnnGetDistributedNetLedger()->lock)) != 0) {
        LNN_LOGE(LNN_LEDGER, "lock mutex fail");
        return SOFTBUS_LOCK_ERR;
    }
    NodeInfo *nodeInfo = LnnGetNodeInfoById(networkId, CATEGORY_NETWORK_ID);
    if (nodeInfo == NULL) {
        LNN_LOGE(LNN_LEDGER, "get info fail");
        (void)SoftBusMutexUnlock(&(LnnGetDistributedNetLedger()->lock));
        return SOFTBUS_NOT_FIND;
    }
    *timestamp = nodeInfo->heartbeatTimestamp;
    (void)SoftBusMutexUnlock(&(LnnGetDistributedNetLedger()->lock));
    return SOFTBUS_OK;
}

int32_t LnnSetDLHeartbeatTimestamp(const char *networkId, uint64_t timestamp)
{
    if (SoftBusMutexLock(&(LnnGetDistributedNetLedger()->lock)) != 0) {
        LNN_LOGE(LNN_LEDGER, "lock mutex fail");
        return SOFTBUS_LOCK_ERR;
    }
    NodeInfo *nodeInfo = LnnGetNodeInfoById(networkId, CATEGORY_NETWORK_ID);
    if (nodeInfo == NULL) {
        LNN_LOGE(LNN_LEDGER, "get info fail");
        (void)SoftBusMutexUnlock(&(LnnGetDistributedNetLedger()->lock));
        return SOFTBUS_NOT_FIND;
    }
    nodeInfo->heartbeatTimestamp = timestamp;
    (void)SoftBusMutexUnlock(&(LnnGetDistributedNetLedger()->lock));
    return SOFTBUS_OK;
}

int32_t LnnGetDLBleDirectTimestamp(const char *networkId, uint64_t *timestamp)
{
    if (networkId == NULL || timestamp == NULL) {
        LNN_LOGE(LNN_LEDGER, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    if (SoftBusMutexLock(&(LnnGetDistributedNetLedger()->lock)) != 0) {
        LNN_LOGE(LNN_LEDGER, "lock mutex fail");
        return SOFTBUS_LOCK_ERR;
    }
    NodeInfo *nodeInfo = LnnGetNodeInfoById(networkId, CATEGORY_NETWORK_ID);
    if (nodeInfo == NULL) {
        LNN_LOGE(LNN_LEDGER, "get info fail");
        (void)SoftBusMutexUnlock(&(LnnGetDistributedNetLedger()->lock));
        return SOFTBUS_NOT_FIND;
    }
    *timestamp = nodeInfo->bleDirectTimestamp;
    (void)SoftBusMutexUnlock(&(LnnGetDistributedNetLedger()->lock));
    return SOFTBUS_OK;
}

int32_t LnnGetDLUpdateTimestamp(const char *udid, uint64_t *timestamp)
{
    if (udid == NULL || timestamp == NULL) {
        LNN_LOGE(LNN_LEDGER, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    if (SoftBusMutexLock(&(LnnGetDistributedNetLedger()->lock)) != 0) {
        LNN_LOGE(LNN_LEDGER, "lock mutex fail");
        return SOFTBUS_LOCK_ERR;
    }
    NodeInfo *nodeInfo = LnnGetNodeInfoById(udid, CATEGORY_UDID);
    if (nodeInfo == NULL) {
        LNN_LOGE(LNN_LEDGER, "get info fail");
        (void)SoftBusMutexUnlock(&(LnnGetDistributedNetLedger()->lock));
        return SOFTBUS_NOT_FIND;
    }
    *timestamp = nodeInfo->updateTimestamp;
    (void)SoftBusMutexUnlock(&(LnnGetDistributedNetLedger()->lock));
    return SOFTBUS_OK;
}

int32_t LnnGetDLAuthCapacity(const char *networkId, uint32_t *authCapacity)
{
    if (SoftBusMutexLock(&(LnnGetDistributedNetLedger()->lock)) != 0) {
        LNN_LOGE(LNN_LEDGER, "lock mutex fail");
        return SOFTBUS_LOCK_ERR;
    }
    NodeInfo *nodeInfo = LnnGetNodeInfoById(networkId, CATEGORY_NETWORK_ID);
    if (nodeInfo == NULL) {
        LNN_LOGE(LNN_LEDGER, "get info fail");
        (void)SoftBusMutexUnlock(&(LnnGetDistributedNetLedger()->lock));
        return SOFTBUS_NOT_FIND;
    }
    *authCapacity = nodeInfo->authCapacity;
    (void)SoftBusMutexUnlock(&(LnnGetDistributedNetLedger()->lock));
    return SOFTBUS_OK;
}

int32_t LnnSetDLBleDirectTimestamp(const char *networkId, uint64_t timestamp)
{
    if (SoftBusMutexLock(&(LnnGetDistributedNetLedger()->lock)) != 0) {
        LNN_LOGE(LNN_LEDGER, "lock mutex fail");
        return SOFTBUS_LOCK_ERR;
    }
    NodeInfo *nodeInfo = LnnGetNodeInfoById(networkId, CATEGORY_NETWORK_ID);
    if (nodeInfo == NULL) {
        LNN_LOGE(LNN_LEDGER, "get info fail");
        (void)SoftBusMutexUnlock(&(LnnGetDistributedNetLedger()->lock));
        return SOFTBUS_NOT_FIND;
    }
    nodeInfo->bleDirectTimestamp = timestamp;
    (void)SoftBusMutexUnlock(&(LnnGetDistributedNetLedger()->lock));
    return SOFTBUS_OK;
}

int32_t LnnSetDLConnCapability(const char *networkId, uint32_t connCapability)
{
    if (SoftBusMutexLock(&(LnnGetDistributedNetLedger()->lock)) != 0) {
        LNN_LOGE(LNN_LEDGER, "lock mutex fail");
        return SOFTBUS_LOCK_ERR;
    }
    NodeInfo *nodeInfo = LnnGetNodeInfoById(networkId, CATEGORY_NETWORK_ID);
    if (nodeInfo == NULL) {
        LNN_LOGE(LNN_LEDGER, "get info fail");
        (void)SoftBusMutexUnlock(&(LnnGetDistributedNetLedger()->lock));
        return SOFTBUS_NOT_FIND;
    }
    nodeInfo->netCapacity = connCapability;
    int32_t ret = LnnSaveRemoteDeviceInfo(nodeInfo);
    if (ret != SOFTBUS_OK) {
        (void)SoftBusMutexUnlock(&(LnnGetDistributedNetLedger()->lock));
        LNN_LOGE(LNN_LEDGER, "save remote netCapacity fail");
        return ret;
    }
    (void)SoftBusMutexUnlock(&(LnnGetDistributedNetLedger()->lock));
    return SOFTBUS_OK;
}

int32_t LnnSetDLConnUserIdCheckSum(const char *networkId, int32_t userIdCheckSum)
{
    if (networkId == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }

    if (SoftBusMutexLock(&(LnnGetDistributedNetLedger()->lock)) != 0) {
        LNN_LOGE(LNN_LEDGER, "lock mutex fail");
        return SOFTBUS_LOCK_ERR;
    }
    NodeInfo *nodeInfo = LnnGetNodeInfoById(networkId, CATEGORY_NETWORK_ID);
    if (nodeInfo == NULL) {
        LNN_LOGE(LNN_LEDGER, "get info fail");
        (void)SoftBusMutexUnlock(&(LnnGetDistributedNetLedger()->lock));
        return SOFTBUS_NOT_FIND;
    }
    int32_t ret = memcpy_s(nodeInfo->userIdCheckSum, USERID_CHECKSUM_LEN, &userIdCheckSum, sizeof(int32_t));
    if (ret != EOK) {
        LNN_LOGE(LNN_LEDGER, "memcpy fail");
        (void)SoftBusMutexUnlock(&(LnnGetDistributedNetLedger()->lock));
        return ret;
    }
    ret = LnnSaveRemoteDeviceInfo(nodeInfo);
    if (ret != SOFTBUS_OK) {
        (void)SoftBusMutexUnlock(&(LnnGetDistributedNetLedger()->lock));
        LNN_LOGE(LNN_LEDGER, "save remote useridchecksum faile");
        return ret;
    }
    (void)SoftBusMutexUnlock(&(LnnGetDistributedNetLedger()->lock));
    return SOFTBUS_OK;
}

int32_t LnnSetDLConnUserId(const char *networkId, int32_t userId)
{
    if (networkId == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    if (SoftBusMutexLock(&(LnnGetDistributedNetLedger()->lock)) != 0) {
        LNN_LOGE(LNN_LEDGER, "lock mutex fail");
        return SOFTBUS_LOCK_ERR;
    }
    NodeInfo *nodeInfo = LnnGetNodeInfoById(networkId, CATEGORY_NETWORK_ID);
    if (nodeInfo == NULL) {
        LNN_LOGE(LNN_LEDGER, "get info fail");
        (void)SoftBusMutexUnlock(&(LnnGetDistributedNetLedger()->lock));
        return SOFTBUS_NOT_FIND;
    }
    nodeInfo->userId = userId;
    int32_t ret = LnnSaveRemoteDeviceInfo(nodeInfo);
    if (ret != SOFTBUS_OK) {
        (void)SoftBusMutexUnlock(&(LnnGetDistributedNetLedger()->lock));
        LNN_LOGE(LNN_LEDGER, "save remote userid faile");
        return ret;
    }
    (void)SoftBusMutexUnlock(&(LnnGetDistributedNetLedger()->lock));
    return SOFTBUS_OK;
}

int32_t LnnSetDLBatteryInfo(const char *networkId, const BatteryInfo *info)
{
    if (networkId == NULL || info == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    if (SoftBusMutexLock(&(LnnGetDistributedNetLedger()->lock)) != 0) {
        LNN_LOGE(LNN_LEDGER, "lock mutex fail");
        return SOFTBUS_LOCK_ERR;
    }
    NodeInfo *nodeInfo = LnnGetNodeInfoById(networkId, CATEGORY_NETWORK_ID);
    if (nodeInfo == NULL) {
        LNN_LOGE(LNN_LEDGER, "get info fail");
        (void)SoftBusMutexUnlock(&(LnnGetDistributedNetLedger()->lock));
        return SOFTBUS_NOT_FIND;
    }
    nodeInfo->batteryInfo.batteryLevel = info->batteryLevel;
    nodeInfo->batteryInfo.isCharging = info->isCharging;
    (void)SoftBusMutexUnlock(&(LnnGetDistributedNetLedger()->lock));
    return SOFTBUS_OK;
}

int32_t LnnSetDLBssTransInfo(const char *networkId, const BssTransInfo *info)
{
    if (networkId == NULL || info == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    if (SoftBusMutexLock(&(LnnGetDistributedNetLedger()->lock)) != 0) {
        LNN_LOGE(LNN_LEDGER, "lock mutex fail");
        return SOFTBUS_LOCK_ERR;
    }
    NodeInfo *nodeInfo = LnnGetNodeInfoById(networkId, CATEGORY_NETWORK_ID);
    if (nodeInfo == NULL) {
        LNN_LOGE(LNN_LEDGER, "get info fail");
        (void)SoftBusMutexUnlock(&(LnnGetDistributedNetLedger()->lock));
        return SOFTBUS_NOT_FIND;
    }
    if (memcpy_s(&(nodeInfo->bssTransInfo), sizeof(BssTransInfo), info,
        sizeof(BssTransInfo)) != SOFTBUS_OK) {
        (void)SoftBusMutexUnlock(&(LnnGetDistributedNetLedger()->lock));
        return SOFTBUS_MEM_ERR;
    }
    (void)SoftBusMutexUnlock(&(LnnGetDistributedNetLedger()->lock));
    return SOFTBUS_OK;
}

int32_t LnnSetDLNodeAddr(const char *id, IdCategory type, const char *addr)
{
    if (SoftBusMutexLock(&(LnnGetDistributedNetLedger()->lock)) != 0) {
        LNN_LOGE(LNN_LEDGER, "lock mutex fail");
        return SOFTBUS_LOCK_ERR;
    }
    NodeInfo *nodeInfo = LnnGetNodeInfoById(id, type);
    if (nodeInfo == NULL) {
        LNN_LOGE(LNN_LEDGER, "get info fail");
        (void)SoftBusMutexUnlock(&(LnnGetDistributedNetLedger()->lock));
        return SOFTBUS_NOT_FIND;
    }
    int ret = strcpy_s(nodeInfo->nodeAddress, sizeof(nodeInfo->nodeAddress), addr);
    if (ret != EOK) {
        LNN_LOGE(LNN_LEDGER, "set node addr failed! ret=%{public}d", ret);
    }
    (void)SoftBusMutexUnlock(&(LnnGetDistributedNetLedger()->lock));
    return ret == EOK ? SOFTBUS_OK : SOFTBUS_STRCPY_ERR;
}

int32_t LnnSetDLProxyPort(const char *id, IdCategory type, int32_t proxyPort)
{
    if (SoftBusMutexLock(&(LnnGetDistributedNetLedger()->lock)) != 0) {
        LNN_LOGE(LNN_LEDGER, "lock mutex fail");
        return SOFTBUS_LOCK_ERR;
    }
    NodeInfo *nodeInfo = LnnGetNodeInfoById(id, type);
    if (nodeInfo == NULL) {
        LNN_LOGE(LNN_LEDGER, "get info fail");
        (void)SoftBusMutexUnlock(&(LnnGetDistributedNetLedger()->lock));
        return SOFTBUS_NOT_FIND;
    }
    nodeInfo->connectInfo.proxyPort = proxyPort;
    (void)SoftBusMutexUnlock(&(LnnGetDistributedNetLedger()->lock));
    return SOFTBUS_OK;
}

int32_t LnnSetDLSessionPort(const char *id, IdCategory type, int32_t sessionPort)
{
    if (SoftBusMutexLock(&(LnnGetDistributedNetLedger()->lock)) != 0) {
        LNN_LOGE(LNN_LEDGER, "lock mutex fail");
        return SOFTBUS_LOCK_ERR;
    }
    NodeInfo *nodeInfo = LnnGetNodeInfoById(id, type);
    if (nodeInfo == NULL) {
        LNN_LOGE(LNN_LEDGER, "get info fail");
        (void)SoftBusMutexUnlock(&(LnnGetDistributedNetLedger()->lock));
        return SOFTBUS_NOT_FIND;
    }
    nodeInfo->connectInfo.sessionPort = sessionPort;
    (void)SoftBusMutexUnlock(&(LnnGetDistributedNetLedger()->lock));
    return SOFTBUS_OK;
}

int32_t LnnSetDLAuthPort(const char *id, IdCategory type, int32_t authPort)
{
    if (SoftBusMutexLock(&(LnnGetDistributedNetLedger()->lock)) != 0) {
        LNN_LOGE(LNN_LEDGER, "lock mutex fail");
        return SOFTBUS_LOCK_ERR;
    }
    NodeInfo *nodeInfo = LnnGetNodeInfoById(id, type);
    if (nodeInfo == NULL) {
        LNN_LOGE(LNN_LEDGER, "get info fail");
        (void)SoftBusMutexUnlock(&(LnnGetDistributedNetLedger()->lock));
        return SOFTBUS_NOT_FIND;
    }
    nodeInfo->connectInfo.authPort = authPort;
    (void)SoftBusMutexUnlock(&(LnnGetDistributedNetLedger()->lock));
    return SOFTBUS_OK;
}

int32_t LnnSetDLP2pIp(const char *id, IdCategory type, const char *p2pIp)
{
    if (id == NULL || p2pIp == NULL) {
        LNN_LOGE(LNN_LEDGER, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    if (SoftBusMutexLock(&(LnnGetDistributedNetLedger()->lock)) != 0) {
        LNN_LOGE(LNN_LEDGER, "lock mutex fail");
        return SOFTBUS_LOCK_ERR;
    }
    NodeInfo *nodeInfo = LnnGetNodeInfoById(id, type);
    if (nodeInfo == NULL) {
        LNN_LOGE(LNN_LEDGER, "get info fail");
        (void)SoftBusMutexUnlock(&(LnnGetDistributedNetLedger()->lock));
        return SOFTBUS_NOT_FIND;
    }
    if (strcpy_s(nodeInfo->p2pInfo.p2pIp, sizeof(nodeInfo->p2pInfo.p2pIp), p2pIp) != EOK) {
        LNN_LOGE(LNN_LEDGER, "STR COPY ERROR");
        (void)SoftBusMutexUnlock(&(LnnGetDistributedNetLedger()->lock));
        return SOFTBUS_MEM_ERR;
    }
    (void)SoftBusMutexUnlock(&(LnnGetDistributedNetLedger()->lock));
    return SOFTBUS_OK;
}

bool LnnSetDLWifiDirectAddr(const char *networkId, const char *addr)
{
    NodeInfo *node = NULL;
    if (networkId == NULL || addr == NULL) {
        LNN_LOGE(LNN_LEDGER, "invalid param");
        return false;
    }
    if (SoftBusMutexLock(&(LnnGetDistributedNetLedger()->lock)) != 0) {
        LNN_LOGE(LNN_LEDGER, "lock mutex fail");
        return false;
    }
    node = LnnGetNodeInfoById(networkId, CATEGORY_NETWORK_ID);
    if (node == NULL) {
        LNN_LOGE(LNN_LEDGER, "udid not found");
        goto EXIT;
    }
    if (LnnSetWifiDirectAddr(node, addr) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "set wifidirect addr fail");
        goto EXIT;
    }
    SoftBusMutexUnlock(&(LnnGetDistributedNetLedger()->lock));
    return true;
EXIT:
    SoftBusMutexUnlock(&(LnnGetDistributedNetLedger()->lock));
    return false;
}

bool LnnSaveBroadcastLinkKey(const char *udid, const BroadcastCipherInfo *info)
{
    if (udid == NULL || info == NULL) {
        LNN_LOGE(LNN_LEDGER, "invalid param");
        return false;
    }
    char udidHash[SHORT_UDID_HASH_HEX_LEN + 1] = { 0 };
    if (LnnGenerateHexStringHash((const unsigned char *)udid, udidHash, SHORT_UDID_HASH_HEX_LEN) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "generate udid hex string hash fail");
        return false;
    }
    NodeInfo cacheInfo;
    (void)memset_s(&cacheInfo, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    if (LnnRetrieveDeviceInfo(udidHash, &cacheInfo) != SOFTBUS_OK) {
        LNN_LOGI(LNN_LEDGER, "no this device info, ignore update");
        return true;
    }
    if (memcmp(cacheInfo.cipherInfo.key, info->key, SESSION_KEY_LENGTH) == 0 &&
        memcmp(cacheInfo.cipherInfo.iv, info->iv, BROADCAST_IV_LEN) == 0) {
        LNN_LOGI(LNN_LEDGER, "remote link key same, ignore update");
        return true;
    }
    if (memcpy_s(cacheInfo.cipherInfo.key, SESSION_KEY_LENGTH, info->key, SESSION_KEY_LENGTH) != EOK ||
        memcpy_s(cacheInfo.cipherInfo.iv, BROADCAST_IV_LEN, info->iv, BROADCAST_IV_LEN) != EOK) {
        LNN_LOGE(LNN_LEDGER, "copy link key failed");
        return false;
    }
    (void)LnnSaveRemoteDeviceInfo(&cacheInfo);
    return true;
}