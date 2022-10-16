/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include "lnn_local_net_ledger.h"

#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include <securec.h>

#include "bus_center_adapter.h"
#include "bus_center_manager.h"
#include "lnn_ohos_account.h"
#include "lnn_p2p_info.h"
#include "softbus_adapter_crypto.h"
#include "softbus_adapter_thread.h"
#include "softbus_errcode.h"
#include "softbus_log.h"
#include "softbus_utils.h"
#include "softbus_hidumper_buscenter.h"

#define SOFTBUS_VERSION "hm.1.0.0"
#define VERSION_TYPE_LITE "LITE"
#define VERSION_TYPE_DEFAULT ""
#define SOFTBUS_BUSCENTER_DUMP_LOCALDEVICEINFO "local_device_info"

typedef struct {
    NodeInfo localInfo;
    SoftBusMutex lock;
    LocalLedgerStatus status;
} LocalNetLedger;

static LocalNetLedger g_localNetLedger;

static int32_t LlGetNodeSoftBusVersion(void *buf, uint32_t len)
{
    NodeInfo *info = &g_localNetLedger.localInfo;
    if (buf == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    if (strncpy_s(buf, len, info->softBusVersion, strlen(info->softBusVersion)) != EOK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "STR COPY ERROR!");
        return SOFTBUS_MEM_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t LlGetDeviceUdid(void *buf, uint32_t len)
{
    const char *udid = NULL;
    NodeInfo *info = &g_localNetLedger.localInfo;
    if (buf == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    udid = LnnGetDeviceUdid(info);
    if (udid == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "get device udid fail");
        return SOFTBUS_ERR;
    }
    if (strlen(udid) <= 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "get local udid invalid!\n");
        return SOFTBUS_ERR;
    }
    if (strncpy_s(buf, len, udid, strlen(udid)) != EOK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "STR COPY ERROR!");
        return SOFTBUS_MEM_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t LlGetNetworkId(void *buf, uint32_t len)
{
    NodeInfo *info = &g_localNetLedger.localInfo;
    if (buf == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    if (strncpy_s(buf, len, info->networkId, strlen(info->networkId)) != EOK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "STR COPY ERROR!");
        return SOFTBUS_MEM_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t LlGetOffLineCode(void *buf, uint32_t len)
{
    NodeInfo *info = &g_localNetLedger.localInfo;
    if (buf == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "buf of offlinecode is null!");
        return SOFTBUS_INVALID_PARAM;
    }
    if (memcpy_s(buf, len, info->offlineCode, OFFLINE_CODE_BYTE_SIZE) != EOK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "memcpy_s offlinecode ERROR!");
        return SOFTBUS_MEM_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t LlGetUuid(void *buf, uint32_t len)
{
    NodeInfo *info = &g_localNetLedger.localInfo;
    if (buf == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    if (strncpy_s(buf, len, info->uuid, strlen(info->uuid)) != EOK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "STR COPY ERROR!");
        return SOFTBUS_MEM_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t UpdateLocalDeviceUdid(const void *buf)
{
    NodeInfo *info = &g_localNetLedger.localInfo;
    if (buf == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    return LnnSetDeviceUdid(info, (char *)buf);
}

static int32_t LlGetDeviceType(void *buf, uint32_t len)
{
    NodeInfo *info = &g_localNetLedger.localInfo;
    char *deviceType = NULL;
    if (buf == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    deviceType = LnnConvertIdToDeviceType(info->deviceInfo.deviceTypeId);
    if (deviceType == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "deviceType fail.");
        return SOFTBUS_ERR;
    }
    if (strncpy_s(buf, len, deviceType, strlen(deviceType)) != EOK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "STR COPY ERROR!");
        return SOFTBUS_MEM_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t LlGetAccount(void *buf, uint32_t len)
{
    NodeInfo *info = &g_localNetLedger.localInfo;

    if (buf == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    if (memcpy_s(buf, len, info->accountHash, SHA_256_HASH_LEN) != EOK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "LlGetAccount copy error.");
        return SOFTBUS_MEM_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t LlUpdateAccount(const void *buf)
{
    if (buf == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }

    NodeInfo *info = &g_localNetLedger.localInfo;
    if (memcpy_s(info->accountHash, SHA_256_HASH_LEN, buf, SHA_256_HASH_LEN) != EOK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "LlUpdateAccount copy error.");
        return SOFTBUS_MEM_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t UpdateLocalDeviceType(const void *buf)
{
    NodeInfo *info = &g_localNetLedger.localInfo;
    uint16_t typeId;
    if (buf == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    if (LnnConvertDeviceTypeToId((char *)buf, &typeId) == SOFTBUS_OK) {
        info->deviceInfo.deviceTypeId = typeId;
        return SOFTBUS_OK;
    }
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "set device type error.");
    return SOFTBUS_ERR;
}

static int32_t UpdateNodeDataChangeFlag(const void *buf)
{
    NodeInfo *info = &g_localNetLedger.localInfo;
    if (buf == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    return LnnSetDataChangeFlag(info, *(int16_t *)buf);
}

static int32_t LlGetDeviceName(void *buf, uint32_t len)
{
    NodeInfo *info = &g_localNetLedger.localInfo;
    const char *deviceName = NULL;
    if (buf == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    deviceName = LnnGetDeviceName(&info->deviceInfo);
    if (deviceName == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "get device name fail.");
        return SOFTBUS_ERR;
    }
    if (strncpy_s(buf, len, deviceName, strlen(deviceName)) != EOK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "STR COPY ERROR!");
        return SOFTBUS_MEM_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t LlGetBtMac(void *buf, uint32_t len)
{
    NodeInfo *info = &g_localNetLedger.localInfo;
    const char *mac = NULL;
    if (buf == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    mac = LnnGetBtMac(info);
    if (mac == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "get bt mac fail.");
        return SOFTBUS_ERR;
    }
    if (strncpy_s(buf, len, mac, strlen(mac)) != EOK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "STR COPY ERROR!");
        return SOFTBUS_MEM_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t LlGetWlanIp(void *buf, uint32_t len)
{
    NodeInfo *info = &g_localNetLedger.localInfo;
    const char *ip = NULL;
    if (buf == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    ip = LnnGetWiFiIp(info);
    if (ip == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "get wifi ip fail.");
        return SOFTBUS_ERR;
    }
    if (strncpy_s(buf, len, ip, strlen(ip)) != EOK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "STR COPY ERROR!");
        return SOFTBUS_MEM_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t LlGetNetIfName(void *buf, uint32_t len)
{
    NodeInfo *info = &g_localNetLedger.localInfo;
    const char *ifName = NULL;
    if (buf == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    ifName = LnnGetNetIfName(info);
    if (ifName == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "get bt mac fail.");
        return SOFTBUS_ERR;
    }
    if (strncpy_s(buf, len, ifName, strlen(ifName)) != EOK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "STR COPY ERROR!");
        return SOFTBUS_MEM_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t L1GetMasterNodeUdid(void *buf, uint32_t len)
{
    NodeInfo *info = &g_localNetLedger.localInfo;
    const char *udid = NULL;

    if (buf == NULL || len < UDID_BUF_LEN) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "invalid get master node udid arguments");
        return SOFTBUS_INVALID_PARAM;
    }
    udid = LnnGetMasterUdid(info);
    if (udid == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "get master udid fail.");
        return SOFTBUS_ERR;
    }
    if (strncpy_s(buf, len, udid, strlen(udid)) != EOK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "copy master udid failed");
        return SOFTBUS_MEM_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t LlGetAuthPort(void *buf, uint32_t len)
{
    NodeInfo *info = &g_localNetLedger.localInfo;
    if (buf == NULL || len != LNN_COMMON_LEN) {
        return SOFTBUS_INVALID_PARAM;
    }
    int32_t port = LnnGetAuthPort(info);
    if (port <= 0) {
        return SOFTBUS_ERR;
    }
    *((int32_t *)buf) = port;
    return SOFTBUS_OK;
}

static int32_t UpdateLocalAuthPort(const void *buf)
{
    NodeInfo *info = &g_localNetLedger.localInfo;
    if (buf == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    return LnnSetAuthPort(info, *(int *)buf);
}

static int32_t LlGetSessionPort(void *buf, uint32_t len)
{
    NodeInfo *info = &g_localNetLedger.localInfo;
    if (buf == NULL || len != LNN_COMMON_LEN) {
        return SOFTBUS_INVALID_PARAM;
    }
    *((int32_t *)buf) = LnnGetSessionPort(info);
    return SOFTBUS_OK;
}

static int32_t UpdateLocalSessionPort(const void *buf)
{
    NodeInfo *info = &g_localNetLedger.localInfo;
    if (buf == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    return LnnSetSessionPort(info, *(int *)buf);
}

static int32_t LlGetProxyPort(void *buf, uint32_t len)
{
    NodeInfo *info = &g_localNetLedger.localInfo;
    if (buf == NULL || len != LNN_COMMON_LEN) {
        return SOFTBUS_INVALID_PARAM;
    }
    *((int32_t *)buf) = LnnGetProxyPort(info);
    return SOFTBUS_OK;
}

static int32_t UpdateLocalProxyPort(const void *buf)
{
    NodeInfo *info = &g_localNetLedger.localInfo;
    if (buf == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    return LnnSetProxyPort(info, *(int *)buf);
}

static int32_t LlGetNetCap(void *buf, uint32_t len)
{
    NodeInfo *info = &g_localNetLedger.localInfo;
    if (buf == NULL || len != LNN_COMMON_LEN) {
        return SOFTBUS_INVALID_PARAM;
    }
    *((int32_t *)buf) = info->netCapacity;
    return SOFTBUS_OK;
}

static int32_t LlGetNetType(void *buf, uint32_t len)
{
    NodeInfo *info = &g_localNetLedger.localInfo;
    if (buf == NULL || len != LNN_COMMON_LEN) {
        return SOFTBUS_INVALID_PARAM;
    }
    *((int32_t *)buf) = info->discoveryType;
    return SOFTBUS_OK;
}

static int32_t LlGetDeviceTypeId(void *buf, uint32_t len)
{
    NodeInfo *info = &g_localNetLedger.localInfo;
    if (buf == NULL || len != LNN_COMMON_LEN) {
        return SOFTBUS_INVALID_PARAM;
    }
    *((int32_t *)buf) = info->deviceInfo.deviceTypeId;
    return SOFTBUS_OK;
}

static int32_t L1GetMasterNodeWeight(void *buf, uint32_t len)
{
    NodeInfo *info = &g_localNetLedger.localInfo;

    if (buf == NULL || len != LNN_COMMON_LEN) {
        return SOFTBUS_INVALID_PARAM;
    }
    *((int32_t *)buf) = info->masterWeight;
    return SOFTBUS_OK;
}

static int32_t LlGetP2pMac(void *buf, uint32_t len)
{
    const char *mac = NULL;
    if (buf == NULL || len < MAC_LEN) {
        return SOFTBUS_INVALID_PARAM;
    }
    mac = LnnGetP2pMac(&g_localNetLedger.localInfo);
    if (mac == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "get p2p mac fail.");
        return SOFTBUS_ERR;
    }
    if (strncpy_s(buf, len, mac, strlen(mac)) != EOK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "copy p2p mac failed");
        return SOFTBUS_MEM_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t LlGetP2pGoMac(void *buf, uint32_t len)
{
    const char *mac = NULL;
    if (buf == NULL || len < MAC_LEN) {
        return SOFTBUS_INVALID_PARAM;
    }
    mac = LnnGetP2pGoMac(&g_localNetLedger.localInfo);
    if (mac == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "get p2p go mac fail.");
        return SOFTBUS_ERR;
    }
    if (strncpy_s(buf, len, mac, strlen(mac)) != EOK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "copy p2p go mac failed");
        return SOFTBUS_MEM_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t L1GetP2pRole(void *buf, uint32_t len)
{
    if (buf == NULL || len != LNN_COMMON_LEN) {
        return SOFTBUS_INVALID_PARAM;
    }
    *((int32_t *)buf) = LnnGetP2pRole(&g_localNetLedger.localInfo);
    return SOFTBUS_OK;
}

static int32_t L1GetNodeDataChangeFlag(void *buf, uint32_t len)
{
    if (buf == NULL || len != DATA_CHANGE_FLAG_BUF_LEN) {
        return SOFTBUS_INVALID_PARAM;
    }
    *((int16_t *)buf) = LnnGetDataChangeFlag(&g_localNetLedger.localInfo);
    return SOFTBUS_OK;
}

static int32_t InitLocalDeviceInfo(DeviceBasicInfo *info)
{
    char devType[DEVICE_TYPE_BUF_LEN] = TYPE_UNKNOWN;

    if (info == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "fail:para error!");
        return SOFTBUS_INVALID_PARAM;
    }
    (void)memset_s(info, sizeof(DeviceBasicInfo), 0, sizeof(DeviceBasicInfo));

    // get device info
    if (GetCommonDevInfo(COMM_DEVICE_KEY_DEVNAME, info->deviceName, DEVICE_NAME_BUF_LEN) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "GetCommonDevInfo: COMM_DEVICE_KEY_DEVNAME failed");
        return SOFTBUS_ERR;
    }
    if (GetCommonDevInfo(COMM_DEVICE_KEY_DEVTYPE, devType, DEVICE_TYPE_BUF_LEN) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "GetCommonDevInfo: COMM_DEVICE_KEY_DEVTYPE failed");
        return SOFTBUS_ERR;
    }
    if (UpdateLocalDeviceType(devType) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "UpdateLocalDeviceType failed");
    }
    return SOFTBUS_OK;
}

static int32_t InitLocalVersionType(NodeInfo *info)
{
    if (info == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "fail:para error!");
        return SOFTBUS_INVALID_PARAM;
    }
    if (strncpy_s(info->versionType, VERSION_MAX_LEN, VERSION_TYPE_LITE, strlen(VERSION_TYPE_LITE)) != EOK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "strncpy_s error");
        return SOFTBUS_MEM_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t InitOfflineCode(NodeInfo *info)
{
    if (info == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "info of offlinecode is null!");
        return SOFTBUS_INVALID_PARAM;
    }
    if (memset_s(info->offlineCode, OFFLINE_CODE_BYTE_SIZE, 0, OFFLINE_CODE_BYTE_SIZE) != EOK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "offlineCode memset_s failed");
        return SOFTBUS_ERR;
    }
    if (SoftBusGenerateRandomArray(info->offlineCode, OFFLINE_CODE_BYTE_SIZE) != SOFTBUS_OK) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "generate offlinecode error.");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t InitConnectInfo(ConnectInfo *info)
{
    if (info == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "fail:para error!");
        return SOFTBUS_INVALID_PARAM;
    }
    // get mac addr
    return GetCommonDevInfo(COMM_DEVICE_KEY_BT_MAC, info->macAddr, MAC_LEN);
}

static int32_t ModifyId(char *dstId, uint32_t dstLen, const char *sourceId)
{
    if (dstId == NULL || sourceId == NULL || strlen(sourceId) > dstLen - 1) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "id:para error!");
        return SOFTBUS_INVALID_PARAM;
    }
    if (strncpy_s(dstId, dstLen, sourceId, strlen(sourceId)) != EOK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "strncpy_s error");
        return SOFTBUS_MEM_ERR;
    }
    return SOFTBUS_OK;
}

const NodeInfo *LnnGetLocalNodeInfo(void)
{
    return &g_localNetLedger.localInfo;
}

static int32_t UpdateLocalDeviceName(const void *name)
{
    return LnnSetDeviceName(&g_localNetLedger.localInfo.deviceInfo, (char *)name);
}

static int32_t UpdateLocalNetworkId(const void *id)
{
    return ModifyId(g_localNetLedger.localInfo.networkId, NETWORK_ID_BUF_LEN, (char *)id);
}

static int32_t LlUpdateLocalOffLineCode(const void *id)
{
    return ModifyId((char *)g_localNetLedger.localInfo.offlineCode, OFFLINE_CODE_BYTE_SIZE, (char *)id);
}

static int32_t UpdateLocalUuid(const void *id)
{
    return ModifyId(g_localNetLedger.localInfo.uuid, UUID_BUF_LEN, (char *)id);
}

int32_t UpdateLocalParentId(const char *id)
{
    return ModifyId(g_localNetLedger.localInfo.parentId, ID_MAX_LEN, id);
}

int32_t UpdateLocalPublicId(const char *id)
{
    return ModifyId(g_localNetLedger.localInfo.publicId, ID_MAX_LEN, id);
}

int32_t UpdateLocalRole(ConnectRole role)
{
    g_localNetLedger.localInfo.role = role;
    return SOFTBUS_OK;
}

static int32_t UpdateLocalNetCapability(const void *capability)
{
    if (capability == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    g_localNetLedger.localInfo.netCapacity = *(int32_t *)capability;
    return SOFTBUS_OK;
}

static int32_t UpdateMasgerNodeWeight(const void *weight)
{
    if (weight == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    g_localNetLedger.localInfo.masterWeight = *(int32_t *)weight;
    return SOFTBUS_OK;
}

int32_t UpdateLocalStatus(ConnectStatus status)
{
    g_localNetLedger.localInfo.status = status;
    return SOFTBUS_OK;
}

int32_t UpdateLocalWeight(int32_t weight)
{
    g_localNetLedger.localInfo.masterWeight = weight;
    return SOFTBUS_OK;
}

static int32_t UpdateLocalDeviceIp(const void *ip)
{
    if (ip == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "para error!");
        return SOFTBUS_INVALID_PARAM;
    }
    LnnSetWiFiIp(&g_localNetLedger.localInfo, ip);
    return SOFTBUS_OK;
}

static int32_t UpdateLocalBtMac(const void *mac)
{
    if (mac == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "para error!");
        return SOFTBUS_INVALID_PARAM;
    }
    LnnSetBtMac(&g_localNetLedger.localInfo, (char *)mac);
    return SOFTBUS_OK;
}

static int32_t UpdateLocalNetIfName(const void *netIfName)
{
    if (netIfName == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "para error!");
        return SOFTBUS_INVALID_PARAM;
    }
    LnnSetNetIfName(&g_localNetLedger.localInfo, (char *)netIfName);
    return SOFTBUS_OK;
}

static int32_t UpdateMasterNodeUdid(const void *udid)
{
    char localUdid[UDID_BUF_LEN];
    ConnectRole role;

    if (LlGetDeviceUdid(localUdid, UDID_BUF_LEN) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "get local udid fail");
    } else {
        role = g_localNetLedger.localInfo.role;
        if (strcmp(localUdid, udid) == 0) {
            g_localNetLedger.localInfo.role = ROLE_CONTROLLER;
        } else {
            g_localNetLedger.localInfo.role = ROLE_LEAF;
        }
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "update local role from %d to %d",
            role, g_localNetLedger.localInfo.role);
    }
    return LnnSetMasterUdid(&g_localNetLedger.localInfo, (const char *)udid);
}

static int32_t UpdateP2pMac(const void *mac)
{
    if (mac == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "para error!");
        return SOFTBUS_INVALID_PARAM;
    }
    return LnnSetP2pMac(&g_localNetLedger.localInfo, (char *)mac);
}

static int32_t UpdateP2pGoMac(const void *mac)
{
    if (mac == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "para error!");
        return SOFTBUS_INVALID_PARAM;
    }
    return LnnSetP2pGoMac(&g_localNetLedger.localInfo, (char *)mac);
}

static int32_t UpdateP2pRole(const void *p2pRole)
{
    if (p2pRole == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "para error!");
        return SOFTBUS_INVALID_PARAM;
    }
    return LnnSetP2pRole(&g_localNetLedger.localInfo, *(int32_t *)p2pRole);
}

static int32_t LlUpdateSupportedProtocols(const void *transProtos)
{
    uint64_t *protocols = (uint64_t *)transProtos;
    return LnnSetSupportedProtocols(&g_localNetLedger.localInfo, *protocols);
}

static int32_t LlGetSupportedProtocols(void *buf, uint32_t len)
{
    if (buf == NULL || len != sizeof(uint64_t)) {
        return SOFTBUS_INVALID_PARAM;
    }
    *((uint64_t *)buf) = LnnGetSupportedProtocols(&g_localNetLedger.localInfo);
    return SOFTBUS_OK;
}

static int32_t LlGetNodeAddr(void *buf, uint32_t len)
{
    NodeInfo *info = &g_localNetLedger.localInfo;
    if (buf == NULL || len == 0) {
        return SOFTBUS_INVALID_PARAM;
    }

    if (strcpy_s((char *)buf, len, info->nodeAddress) != EOK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "copy node addr to buf fail");
        return SOFTBUS_MEM_ERR;
    }
    return SOFTBUS_OK;
}

int32_t LlUpdateNodeAddr(const void *addr)
{
    if (addr == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }

    NodeInfo *info = &g_localNetLedger.localInfo;
    if (strcpy_s(info->nodeAddress, sizeof(info->nodeAddress), (const char*)addr) != EOK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "copy node addr to buf fail");
        return SOFTBUS_MEM_ERR;
    }
    return SOFTBUS_OK;
}

static LocalLedgerKey g_localKeyTable[] = {
    {STRING_KEY_HICE_VERSION, VERSION_MAX_LEN, LlGetNodeSoftBusVersion, NULL},
    {STRING_KEY_DEV_UDID, UDID_BUF_LEN, LlGetDeviceUdid, UpdateLocalDeviceUdid},
    {STRING_KEY_NETWORKID, NETWORK_ID_BUF_LEN, LlGetNetworkId, UpdateLocalNetworkId},
    {STRING_KEY_UUID, UUID_BUF_LEN, LlGetUuid, UpdateLocalUuid},
    {STRING_KEY_DEV_TYPE, DEVICE_TYPE_BUF_LEN, LlGetDeviceType, UpdateLocalDeviceType},
    {STRING_KEY_DEV_NAME, DEVICE_NAME_BUF_LEN, LlGetDeviceName, UpdateLocalDeviceName},
    {STRING_KEY_BT_MAC, MAC_LEN, LlGetBtMac, UpdateLocalBtMac},
    {STRING_KEY_WLAN_IP, IP_LEN, LlGetWlanIp, UpdateLocalDeviceIp},
    {STRING_KEY_NET_IF_NAME, NET_IF_NAME_LEN, LlGetNetIfName, UpdateLocalNetIfName},
    {STRING_KEY_MASTER_NODE_UDID, UDID_BUF_LEN, L1GetMasterNodeUdid, UpdateMasterNodeUdid},
    {STRING_KEY_NODE_ADDR, SHORT_ADDRESS_MAX_LEN, LlGetNodeAddr, LlUpdateNodeAddr},
    {STRING_KEY_P2P_MAC, MAC_LEN, LlGetP2pMac, UpdateP2pMac},
    {STRING_KEY_P2P_GO_MAC, MAC_LEN, LlGetP2pGoMac, UpdateP2pGoMac},
    {STRING_KEY_OFFLINE_CODE, OFFLINE_CODE_LEN, LlGetOffLineCode, LlUpdateLocalOffLineCode},
    {NUM_KEY_SESSION_PORT, -1, LlGetSessionPort, UpdateLocalSessionPort},
    {NUM_KEY_AUTH_PORT, -1, LlGetAuthPort, UpdateLocalAuthPort},
    {NUM_KEY_PROXY_PORT, -1, LlGetProxyPort, UpdateLocalProxyPort},
    {NUM_KEY_NET_CAP, -1, LlGetNetCap, UpdateLocalNetCapability},
    {NUM_KEY_DISCOVERY_TYPE, -1, LlGetNetType, NULL},
    {NUM_KEY_DEV_TYPE_ID, -1, LlGetDeviceTypeId, NULL},
    {NUM_KEY_MASTER_NODE_WEIGHT, -1, L1GetMasterNodeWeight, UpdateMasgerNodeWeight},
    {NUM_KEY_P2P_ROLE, -1, L1GetP2pRole, UpdateP2pRole},
    {NUM_KEY_TRANS_PROTOCOLS, sizeof(int64_t), LlGetSupportedProtocols, LlUpdateSupportedProtocols},
    {NUM_KEY_DATA_CHANGE_FLAG, sizeof(int16_t), L1GetNodeDataChangeFlag, UpdateNodeDataChangeFlag},
    {BYTE_KEY_ACCOUNT_HASH, SHA_256_HASH_LEN, LlGetAccount, LlUpdateAccount},
};

int32_t LnnGetLocalStrInfo(InfoKey key, char *info, uint32_t len)
{
    uint32_t i;
    int32_t ret;
    if (info == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "para error.");
        return SOFTBUS_INVALID_PARAM;
    }
    if (key >= STRING_KEY_END) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "KEY error.");
        return SOFTBUS_INVALID_PARAM;
    }
    if (SoftBusMutexLock(&g_localNetLedger.lock) != 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "lock mutex fail!");
        return SOFTBUS_ERR;
    }
    for (i = 0; i < sizeof(g_localKeyTable) / sizeof(LocalLedgerKey); i++) {
        if (key == g_localKeyTable[i].key) {
            if (g_localKeyTable[i].getInfo != NULL) {
                ret = g_localKeyTable[i].getInfo((void *)info, len);
                SoftBusMutexUnlock(&g_localNetLedger.lock);
                return ret;
            }
        }
    }
    SoftBusMutexUnlock(&g_localNetLedger.lock);
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "KEY NOT exist.");
    return SOFTBUS_ERR;
}

static int32_t LnnGetLocalInfo(InfoKey key, void* info, uint32_t infoSize)
{
    uint32_t i;
    int32_t ret;
    if (info == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "para error.");
        return SOFTBUS_INVALID_PARAM;
    }
    if ((key < NUM_KEY_BEGIN || key >= NUM_KEY_END) &&
        (key < BYTE_KEY_BEGIN || key >= BYTE_KEY_END)) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "KEY error.");
        return SOFTBUS_INVALID_PARAM;
    }
    if (SoftBusMutexLock(&g_localNetLedger.lock) != 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "lock mutex fail!");
        return SOFTBUS_ERR;
    }
    for (i = 0; i < sizeof(g_localKeyTable) / sizeof(LocalLedgerKey); i++) {
        if (key == g_localKeyTable[i].key) {
            if (g_localKeyTable[i].getInfo != NULL) {
                ret = g_localKeyTable[i].getInfo(info, infoSize);
                SoftBusMutexUnlock(&g_localNetLedger.lock);
                return ret;
            }
        }
    }
    SoftBusMutexUnlock(&g_localNetLedger.lock);
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "KEY NOT exist.");
    return SOFTBUS_ERR;
}

static bool JudgeString(const char *info, int32_t len)
{
    return (len <= 0) ? false : IsValidString(info, (uint32_t)len);
}

int32_t LnnSetLocalStrInfo(InfoKey key, const char *info)
{
    uint32_t i;
    int32_t ret;
    if (info == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "para error.");
        return SOFTBUS_INVALID_PARAM;
    }
    if (key >= STRING_KEY_END) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "KEY error.");
        return SOFTBUS_INVALID_PARAM;
    }
    if (SoftBusMutexLock(&g_localNetLedger.lock) != 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "lock mutex fail!");
        return SOFTBUS_ERR;
    }
    for (i = 0; i < sizeof(g_localKeyTable) / sizeof(LocalLedgerKey); i++) {
        if (key == g_localKeyTable[i].key) {
            if (g_localKeyTable[i].setInfo != NULL && JudgeString(info, g_localKeyTable[i].maxLen)) {
                ret = g_localKeyTable[i].setInfo((void *)info);
                SoftBusMutexUnlock(&g_localNetLedger.lock);
                return ret;
            }
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "key=%d not support or info format error", key);
            SoftBusMutexUnlock(&g_localNetLedger.lock);
            return SOFTBUS_INVALID_PARAM;
        }
    }
    SoftBusMutexUnlock(&g_localNetLedger.lock);
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "key not exist.");
    return SOFTBUS_ERR;
}

static int32_t LnnSetLocalInfo(InfoKey key, void* info)
{
    uint32_t i;
    int32_t ret;
    if ((key < NUM_KEY_BEGIN || key >= NUM_KEY_END) &&
        (key < BYTE_KEY_BEGIN || key >= BYTE_KEY_END)) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "KEY error.");
        return SOFTBUS_INVALID_PARAM;
    }
    if (SoftBusMutexLock(&g_localNetLedger.lock) != 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "lock mutex fail!");
        return SOFTBUS_ERR;
    }
    for (i = 0; i < sizeof(g_localKeyTable) / sizeof(LocalLedgerKey); i++) {
        if (key == g_localKeyTable[i].key) {
            if (g_localKeyTable[i].setInfo != NULL) {
                ret = g_localKeyTable[i].setInfo(info);
                SoftBusMutexUnlock(&g_localNetLedger.lock);
                return ret;
            }
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "key=%d not support", key);
            SoftBusMutexUnlock(&g_localNetLedger.lock);
            return SOFTBUS_ERR;
        }
    }
    SoftBusMutexUnlock(&g_localNetLedger.lock);
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "key not exist.");
    return SOFTBUS_ERR;
}

int32_t LnnGetLocalNumInfo(InfoKey key, int32_t *info)
{
    return LnnGetLocalInfo(key, (void*)info, sizeof(int32_t));
}

int32_t LnnGetLocalNum64Info(InfoKey key, int64_t *info)
{
    return LnnGetLocalInfo(key, (void*)info, sizeof(int64_t));
}

int32_t LnnSetLocalNum64Info(InfoKey key, int64_t info)
{
    return LnnSetLocalInfo(key, (void*)&info);
}

int32_t LnnGetLocalNum16Info(InfoKey key, int16_t *info)
{
    return LnnGetLocalInfo(key, (void*)info, sizeof(int16_t));
}

int32_t LnnSetLocalNum16Info(InfoKey key, int16_t info)
{
    return LnnSetLocalInfo(key, (void*)&info);
}

int32_t LnnSetLocalNumInfo(InfoKey key, int32_t info)
{
    return LnnSetLocalInfo(key, (void*)&info);
}

int32_t LnnSetLocalByteInfo(InfoKey key, const uint8_t *info, uint32_t len)
{
    (void)len;
    return LnnSetLocalInfo(key, (void *)info);
}

int32_t LnnGetLocalByteInfo(InfoKey key, uint8_t *info, uint32_t len)
{
    return LnnGetLocalInfo(key, (void *)info, len);
}

int32_t LnnGetLocalDeviceInfo(NodeBasicInfo *info)
{
    int32_t rc;
    char type[DEVICE_TYPE_BUF_LEN] = {0};

    if (info == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "info is null");
        return SOFTBUS_INVALID_PARAM;
    }
    rc = LnnGetLocalStrInfo(STRING_KEY_DEV_NAME, info->deviceName, DEVICE_NAME_BUF_LEN);
    if (rc != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "get local device info failed");
        return SOFTBUS_ERR;
    }
    rc = LnnGetLocalStrInfo(STRING_KEY_NETWORKID, info->networkId, NETWORK_ID_BUF_LEN);
    if (rc != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "get local network id info failed");
        return SOFTBUS_ERR;
    }
    rc = LnnGetLocalStrInfo(STRING_KEY_DEV_TYPE, type, DEVICE_TYPE_BUF_LEN);
    if (rc != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "get local device type failed");
        return SOFTBUS_ERR;
    }
    return LnnConvertDeviceTypeToId(type, &info->deviceTypeId);
}

int32_t SoftBusDumpBusCenterLocalDeviceInfo(int fd)
{
    SOFTBUS_DPRINTF(fd, "-----LocalDeviceInfo-----\n");
    NodeBasicInfo localNodeInfo;
    if (LnnGetLocalDeviceInfo(&localNodeInfo) != 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "LnnGetLocalDeviceInfo failed!");
        return SOFTBUS_ERR;
    }
    SoftBusDumpBusCenterPrintInfo(fd, &localNodeInfo);
    return SOFTBUS_OK;
}

int32_t LnnInitLocalLedger(void)
{
    NodeInfo *nodeInfo = NULL;
    if (g_localNetLedger.status == LL_INIT_SUCCESS) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "local net ledger already init.");
        return SOFTBUS_OK;
    }
    g_localNetLedger.status = LL_INIT_UNKNOWN;
    nodeInfo = &g_localNetLedger.localInfo;
    (void)memset_s(nodeInfo, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    if (strncpy_s(nodeInfo->softBusVersion, VERSION_MAX_LEN, SOFTBUS_VERSION, strlen(SOFTBUS_VERSION)) != EOK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "fail:strncpy_s fail!");
        g_localNetLedger.status = LL_INIT_FAIL;
        return SOFTBUS_MEM_ERR;
    }
    nodeInfo->netCapacity = LnnGetNetCapabilty();
    DeviceBasicInfo *deviceInfo = &nodeInfo->deviceInfo;
    if (InitOfflineCode(nodeInfo) != SOFTBUS_OK) {
        goto EXIT;
    }
    if (InitLocalDeviceInfo(deviceInfo) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "init local device info error!");
        goto EXIT;
    }
    if (InitLocalVersionType(nodeInfo) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "init local version type error!");
        goto EXIT;
    }
    if (InitConnectInfo(&nodeInfo->connectInfo) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "init local connect info error!");
        goto EXIT;
    }
    if (LnnInitLocalP2pInfo(nodeInfo) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "init local p2p info error!");
        goto EXIT;
    }

    if (SoftBusMutexInit(&g_localNetLedger.lock, NULL) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "mutex init fail!");
        goto EXIT;
    }
    if (SoftBusRegBusCenterVarDump(
        SOFTBUS_BUSCENTER_DUMP_LOCALDEVICEINFO, &SoftBusDumpBusCenterLocalDeviceInfo) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "SoftBusRegBusCenterVarDump regist fail");
        return SOFTBUS_ERR;
    }
    g_localNetLedger.status = LL_INIT_SUCCESS;
    return SOFTBUS_OK;
EXIT:
    g_localNetLedger.status = LL_INIT_FAIL;
    return SOFTBUS_ERR;
}

int32_t LnnInitLocalLedgerDelay(void)
{
    NodeInfo *nodeInfo = &g_localNetLedger.localInfo;
    DeviceBasicInfo *deviceInfo = &nodeInfo->deviceInfo;
    if (GetCommonDevInfo(COMM_DEVICE_KEY_UDID, deviceInfo->deviceUdid, UDID_BUF_LEN) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "GetCommonDevInfo: COMM_DEVICE_KEY_UDID failed");
        return SOFTBUS_ERR;
    }
    if (LnnInitOhosAccount() != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "init default ohos account failed");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

void LnnDeinitLocalLedger(void)
{
    if (g_localNetLedger.status == LL_INIT_SUCCESS) {
        SoftBusMutexDestroy(&g_localNetLedger.lock);
    }
    g_localNetLedger.status = LL_INIT_UNKNOWN;
}

bool LnnIsMasterNode(void)
{
    bool ret = false;
    if (SoftBusMutexLock(&g_localNetLedger.lock) != 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "lock mutex fail!");
        return ret;
    }
    const char* masterUdid = g_localNetLedger.localInfo.masterUdid;
    const char* deviceUdid = g_localNetLedger.localInfo.deviceInfo.deviceUdid;
    ret = strncmp(masterUdid, deviceUdid, strlen(deviceUdid)) == 0;
    SoftBusMutexUnlock(&g_localNetLedger.lock);
    return ret;
}
