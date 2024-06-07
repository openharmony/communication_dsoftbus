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
#include "lnn_log.h"
#include "softbus_errcode.h"
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

static int32_t DlGetDeviceUuid(const char *networkId, void *buf, uint32_t len)
{
    NodeInfo *info = NULL;
    RETURN_IF_GET_NODE_VALID(networkId, buf, info);
    if (strncpy_s((char*)buf, len, info->uuid, strlen(info->uuid)) != EOK) {
        LNN_LOGE(LNN_LEDGER, "STR COPY ERROR!");
        return SOFTBUS_MEM_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t DlGetDeviceOfflineCode(const char *networkId, void *buf, uint32_t len)
{
    NodeInfo *info = NULL;
    RETURN_IF_GET_NODE_VALID(networkId, buf, info);
    if (memcpy_s(buf, len, info->offlineCode, OFFLINE_CODE_BYTE_SIZE) != EOK) {
        LNN_LOGE(LNN_LEDGER, "memcpy_s offlinecode ERROR!");
        return SOFTBUS_MEM_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t DlGetDeviceUdid(const char *networkId, void *buf, uint32_t len)
{
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

static int32_t DlGetNodeSoftBusVersion(const char *networkId, void *buf, uint32_t len)
{
    NodeInfo *info = NULL;
    RETURN_IF_GET_NODE_VALID(networkId, buf, info);
    if (strncpy_s((char*)buf, len, info->softBusVersion, strlen(info->softBusVersion)) != EOK) {
        LNN_LOGE(LNN_LEDGER, "STR COPY ERROR!");
        return SOFTBUS_MEM_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t DlGetDeviceType(const char *networkId, void *buf, uint32_t len)
{
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

static int32_t DlGetDeviceTypeId(const char *networkId, void *buf, uint32_t len)
{
    NodeInfo *info = NULL;
    RETURN_IF_GET_NODE_VALID(networkId, buf, info);
    *((int32_t *)buf) = info->deviceInfo.deviceTypeId;
    return SOFTBUS_OK;
}

static int32_t DlGetAuthType(const char *networkId, void *buf, uint32_t len)
{
    NodeInfo *info = NULL;
    RETURN_IF_GET_NODE_VALID(networkId, buf, info);
    *((uint32_t *)buf) = info->AuthTypeValue;
    return SOFTBUS_OK;
}

static int32_t DlGetDeviceName(const char *networkId, void *buf, uint32_t len)
{
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

static int32_t DlGetBtMac(const char *networkId, void *buf, uint32_t len)
{
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

static int32_t DlGetWlanIp(const char *networkId, void *buf, uint32_t len)
{
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

static int32_t DlGetMasterUdid(const char *networkId, void *buf, uint32_t len)
{
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

static int32_t DlGetNodeBleMac(const char *networkId, void *buf, uint32_t len)
{
    NodeInfo *info = NULL;

    RETURN_IF_GET_NODE_VALID(networkId, buf, info);
    if (strlen(info->connectInfo.bleMacAddr) == 0) {
        LNN_LOGE(LNN_LEDGER, "ble mac is invalid.");
        return SOFTBUS_ERR;
    }
    if (info->bleMacRefreshSwitch != 0) {
        uint64_t currentTimeMs = GetCurrentTime();
        LNN_CHECK_AND_RETURN_RET_LOGE(info->connectInfo.latestTime + BLE_ADV_LOST_TIME >= currentTimeMs, SOFTBUS_ERR,
            LNN_LEDGER, "ble mac out date, lastAdvTime=%{public}" PRIu64 ", now=%{public}" PRIu64,
            info->connectInfo.latestTime, currentTimeMs);
    }
    if (strcpy_s((char *)buf, len, info->connectInfo.bleMacAddr) != EOK) {
        return SOFTBUS_MEM_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t DlGetRemotePtk(const char *networkId, void *buf, uint32_t len)
{
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

static int32_t DlGetStaticCapLen(const char *networkId, void *buf, uint32_t len)
{
    NodeInfo *info = NULL;
    if (len != LNN_COMMON_LEN) {
        LNN_LOGE(LNN_LEDGER, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    RETURN_IF_GET_NODE_VALID(networkId, buf, info);
    if (!LnnIsNodeOnline(info)) {
        LNN_LOGE(LNN_LEDGER, "device is offline");
        return SOFTBUS_ERR;
    }
    *((int32_t *)buf) = info->staticCapLen;
    return SOFTBUS_OK;
}

static int32_t DlGetDeviceSecurityLevel(const char *networkId, void *buf, uint32_t len)
{
    NodeInfo *info = NULL;
    if (len != LNN_COMMON_LEN) {
        LNN_LOGE(LNN_LEDGER, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    RETURN_IF_GET_NODE_VALID(networkId, buf, info);
    *((int32_t *)buf) = info->deviceSecurityLevel;
    return SOFTBUS_OK;
}

static int32_t DlGetStaticCap(const char *networkId, void *buf, uint32_t len)
{
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

static int32_t DlGetAuthPort(const char *networkId, void *buf, uint32_t len)
{
    NodeInfo *info = NULL;
    if (len != LNN_COMMON_LEN) {
        return SOFTBUS_INVALID_PARAM;
    }
    RETURN_IF_GET_NODE_VALID(networkId, buf, info);
    *((int32_t *)buf) = LnnGetAuthPort(info);
    return SOFTBUS_OK;
}

static int32_t DlGetSessionPort(const char *networkId, void *buf, uint32_t len)
{
    NodeInfo *info = NULL;
    if (len != LNN_COMMON_LEN) {
        return SOFTBUS_INVALID_PARAM;
    }
    RETURN_IF_GET_NODE_VALID(networkId, buf, info);
    *((int32_t *)buf) = LnnGetSessionPort(info);
    return SOFTBUS_OK;
}

static int32_t DlGetProxyPort(const char *networkId, void *buf, uint32_t len)
{
    NodeInfo *info = NULL;
    if (len != LNN_COMMON_LEN) {
        return SOFTBUS_INVALID_PARAM;
    }
    RETURN_IF_GET_NODE_VALID(networkId, buf, info);
    *((int32_t *)buf) = LnnGetProxyPort(info);
    return SOFTBUS_OK;
}

static int32_t DlGetNetCap(const char *networkId, void *buf, uint32_t len)
{
    NodeInfo *info = NULL;
    if (len != LNN_COMMON_LEN) {
        return SOFTBUS_INVALID_PARAM;
    }
    RETURN_IF_GET_NODE_VALID(networkId, buf, info);
    *((uint32_t *)buf) = info->netCapacity;
    return SOFTBUS_OK;
}

static int32_t DlGetFeatureCap(const char *networkId, void *buf, uint32_t len)
{
    NodeInfo *info = NULL;
    if (len != LNN_COMMON_LEN_64) {
        return SOFTBUS_INVALID_PARAM;
    }
    RETURN_IF_GET_NODE_VALID(networkId, buf, info);
    *((uint64_t *)buf) = info->feature;
    return SOFTBUS_OK;
}

static int32_t DlGetNetType(const char *networkId, void *buf, uint32_t len)
{
    NodeInfo *info = NULL;
    if (len != LNN_COMMON_LEN) {
        return SOFTBUS_INVALID_PARAM;
    }
    RETURN_IF_GET_NODE_VALID(networkId, buf, info);
    *((int32_t *)buf) = (int32_t)info->discoveryType;
    return SOFTBUS_OK;
}

static int32_t DlGetMasterWeight(const char *networkId, void *buf, uint32_t len)
{
    NodeInfo *info = NULL;

    if (len != LNN_COMMON_LEN) {
        return SOFTBUS_INVALID_PARAM;
    }
    RETURN_IF_GET_NODE_VALID(networkId, buf, info);
    *((int32_t *)buf) = info->masterWeight;
    return SOFTBUS_OK;
}

static int32_t DlGetP2pMac(const char *networkId, void *buf, uint32_t len)
{
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

static int32_t DlGetWifiDirectAddr(const char *networkId, void *buf, uint32_t len)
{
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
        return SOFTBUS_ERR;
    }
    if (strcpy_s((char*)buf, len, wifiDirectAddr) != EOK) {
        LNN_LOGE(LNN_LEDGER, "copy wifidirect addr to buf fail");
        return SOFTBUS_MEM_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t DlGetNodeAddr(const char *networkId, void *buf, uint32_t len)
{
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

static int32_t DlGetP2pGoMac(const char *networkId, void *buf, uint32_t len)
{
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

static int32_t DlGetWifiCfg(const char *networkId, void *buf, uint32_t len)
{
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

static int32_t DlGetChanList5g(const char *networkId, void *buf, uint32_t len)
{
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

static int32_t DlGetP2pRole(const char *networkId, void *buf, uint32_t len)
{
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

static int32_t DlGetStateVersion(const char *networkId, void *buf, uint32_t len)
{
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

static int32_t DlGetStaFrequency(const char *networkId, void *buf, uint32_t len)
{
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

static int32_t DlGetNodeDataChangeFlag(const char *networkId, void *buf, uint32_t len)
{
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

static int32_t DlGetNodeTlvNegoFlag(const char *networkId, void *buf, uint32_t len)
{
    NodeInfo *info = NULL;
    if (len != sizeof(bool)) {
        return SOFTBUS_INVALID_PARAM;
    }
    RETURN_IF_GET_NODE_VALID(networkId, buf, info);
    if (!LnnIsNodeOnline(info) && !IsMetaNode(info)) {
        LNN_LOGE(LNN_LEDGER, "node is offline");
        return SOFTBUS_NETWORK_NODE_OFFLINE;
    }
    *((bool *)buf) = IsFeatureSupport(info->feature, BIT_WIFI_DIRECT_TLV_NEGOTIATION);
    return SOFTBUS_OK;
}

static int32_t DlGetAccountHash(const char *networkId, void *buf, uint32_t len)
{
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

static int32_t DlGetDeviceIrk(const char *networkId, void *buf, uint32_t len)
{
    NodeInfo *info = NULL;
    RETURN_IF_GET_NODE_VALID(networkId, buf, info);
    if (memcpy_s(buf, len, info->rpaInfo.peerIrk, LFINDER_IRK_LEN) != EOK) {
        LNN_LOGE(LNN_LEDGER, "memcpy peerIrk fail");
        return SOFTBUS_MEM_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t DlGetDevicePubMac(const char *networkId, void *buf, uint32_t len)
{
    NodeInfo *info = NULL;
    RETURN_IF_GET_NODE_VALID(networkId, buf, info);
    if (memcpy_s(buf, len, info->rpaInfo.publicAddress, LFINDER_MAC_ADDR_LEN) != EOK) {
        LNN_LOGE(LNN_LEDGER, "memcpy publicAddress fail");
        return SOFTBUS_MEM_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t DlGetDeviceCipherInfoKey(const char *networkId, void *buf, uint32_t len)
{
    NodeInfo *info = NULL;
    RETURN_IF_GET_NODE_VALID(networkId, buf, info);
    if (memcpy_s(buf, len, info->cipherInfo.key, SESSION_KEY_LENGTH) != EOK) {
        LNN_LOGE(LNN_LEDGER, "memcpy cipher key fail");
        return SOFTBUS_MEM_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t DlGetDeviceCipherInfoIv(const char *networkId, void *buf, uint32_t len)
{
    NodeInfo *info = NULL;
    RETURN_IF_GET_NODE_VALID(networkId, buf, info);
    if (memcpy_s(buf, len, info->cipherInfo.iv, BROADCAST_IV_LEN) != EOK) {
        LNN_LOGE(LNN_LEDGER, "memcpy cipher iv fail");
        return SOFTBUS_MEM_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t DlGetNodeP2pIp(const char *networkId, void *buf, uint32_t len)
{
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
    {BOOL_KEY_TLV_NEGOTIATION, DlGetNodeTlvNegoFlag},
    {BYTE_KEY_ACCOUNT_HASH, DlGetAccountHash},
    {BYTE_KEY_REMOTE_PTK, DlGetRemotePtk},
    {BYTE_KEY_STATIC_CAPABILITY, DlGetStaticCap},
    {BYTE_KEY_IRK, DlGetDeviceIrk},
    {BYTE_KEY_PUB_MAC, DlGetDevicePubMac},
    {BYTE_KEY_BROADCAST_CIPHER_KEY, DlGetDeviceCipherInfoKey},
    {BYTE_KEY_BROADCAST_CIPHER_IV, DlGetDeviceCipherInfoIv},
};


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
                ret = g_dlKeyTable[i].getInfo(networkId, (void *)info, len);
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
                ret = g_dlKeyTable[i].getInfo(networkId, (void *)info, LNN_COMMON_LEN);
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
                ret = g_dlKeyTable[i].getInfo(networkId, (void *)info, LNN_COMMON_LEN);
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
                ret = g_dlKeyTable[i].getInfo(networkId, (void *)info, LNN_COMMON_LEN_64);
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
                ret = g_dlKeyTable[i].getInfo(networkId, (void *)info, sizeof(int16_t));
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
                ret = g_dlKeyTable[i].getInfo(networkId, (void *)info, sizeof(bool));
                SoftBusMutexUnlock(&(LnnGetDistributedNetLedger()->lock));
                return ret;
            }
        }
    }
    SoftBusMutexUnlock(&(LnnGetDistributedNetLedger()->lock));
    LNN_LOGE(LNN_LEDGER, "KEY NOT exist");
    return SOFTBUS_NOT_FIND;
}

int32_t LnnGetRemoteByteInfo(const char *networkId, InfoKey key, uint8_t *info, uint32_t len)
{
    uint32_t i;
    int32_t ret;
    if (!IsValidString(networkId, ID_MAX_LEN)) {
        return SOFTBUS_INVALID_PARAM;
    }
    if (info == NULL) {
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
                ret = g_dlKeyTable[i].getInfo(networkId, info, len);
                SoftBusMutexUnlock(&(LnnGetDistributedNetLedger()->lock));
                return ret;
            }
        }
    }
    SoftBusMutexUnlock(&(LnnGetDistributedNetLedger()->lock));
    LNN_LOGE(LNN_LEDGER, "KEY NOT exist.");
    return SOFTBUS_NOT_FIND;
}
