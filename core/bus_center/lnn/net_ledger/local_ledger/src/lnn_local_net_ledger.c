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
#include "softbus_errcode.h"
#include "softbus_log.h"
#include "softbus_utils.h"

#define SOFTBUS_VERSION "hm.1.0.0"
#define VERSION_TYPE_LITE "LITE"
#define VERSION_TYPE_DEFAULT ""
#define NUM_BUF_SIZE 4

typedef struct {
    NodeInfo localInfo;
    pthread_mutex_t lock;
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
        LOG_ERR("STR COPY ERROR!");
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
        LOG_ERR("get device udid fail");
        return SOFTBUS_ERR;
    }
    if (strncpy_s(buf, len, udid, strlen(udid)) != EOK) {
        LOG_ERR("STR COPY ERROR!");
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
        LOG_ERR("STR COPY ERROR!");
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
        LOG_ERR("STR COPY ERROR!");
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
        LOG_ERR("deviceType fail.");
        return SOFTBUS_ERR;
    }
    if (strncpy_s(buf, len, deviceType, strlen(deviceType)) != EOK) {
        LOG_ERR("STR COPY ERROR!");
        return SOFTBUS_MEM_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t UpdateLocalDeviceType(const void *buf)
{
    NodeInfo *info = &g_localNetLedger.localInfo;
    uint8_t typeId;
    if (buf == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    if (LnnConvertDeviceTypeToId((char *)buf, &typeId) == SOFTBUS_OK) {
        info->deviceInfo.deviceTypeId = typeId;
        return SOFTBUS_OK;
    }
    LOG_ERR("set device type error.");
    return SOFTBUS_ERR;
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
        LOG_ERR("get device name fail.");
        return SOFTBUS_ERR;
    }
    if (strncpy_s(buf, len, deviceName, strlen(deviceName)) != EOK) {
        LOG_ERR("STR COPY ERROR!");
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
        LOG_ERR("get bt mac fail.");
        return SOFTBUS_ERR;
    }
    if (strncpy_s(buf, len, mac, strlen(mac)) != EOK) {
        LOG_ERR("STR COPY ERROR!");
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
        LOG_ERR("get wifi ip fail.");
        return SOFTBUS_ERR;
    }
    if (strncpy_s(buf, len, ip, strlen(ip)) != EOK) {
        LOG_ERR("STR COPY ERROR!");
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
        LOG_ERR("get bt mac fail.");
        return SOFTBUS_ERR;
    }
    if (strncpy_s(buf, len, ifName, strlen(ifName)) != EOK) {
        LOG_ERR("STR COPY ERROR!");
        return SOFTBUS_MEM_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t LlGetAuthPort(void *buf, uint32_t len)
{
    NodeInfo *info = &g_localNetLedger.localInfo;
    if (buf == NULL || len != NUM_BUF_SIZE) {
        return SOFTBUS_INVALID_PARAM;
    }
    *((int32_t *)buf) = LnnGetAuthPort(info);
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
    if (buf == NULL || len != NUM_BUF_SIZE) {
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
    if (buf == NULL || len != NUM_BUF_SIZE) {
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
    if (buf == NULL || len != NUM_BUF_SIZE) {
        return SOFTBUS_INVALID_PARAM;
    }
    *((int32_t *)buf) = info->netCapacity;
    return SOFTBUS_OK;
}

static int32_t LlGetDeviceTypeId(void *buf, uint32_t len)
{
    NodeInfo *info = &g_localNetLedger.localInfo;
    if (buf == NULL || len != NUM_BUF_SIZE) {
        return SOFTBUS_INVALID_PARAM;
    }
    *((int32_t *)buf) = info->deviceInfo.deviceTypeId;
    return SOFTBUS_OK;
}

static int32_t InitLocalDeviceInfo(DeviceBasicInfo *info)
{
    char devType[DEVICE_TYPE_BUF_LEN] = TYPE_UNKNOWN;

    if (info == NULL) {
        LOG_ERR("fail:para error!");
        return SOFTBUS_INVALID_PARAM;
    }
    (void)memset_s(info, sizeof(DeviceBasicInfo), 0, sizeof(DeviceBasicInfo));

    // get device info
    if (GetCommonDevInfo(COMM_DEVICE_KEY_UDID, info->deviceUdid, UDID_BUF_LEN) != SOFTBUS_OK) {
        LOG_ERR("GetCommonDevInfo: COMM_DEVICE_KEY_UDID failed");
        return SOFTBUS_ERR;
    }
    if (GetCommonDevInfo(COMM_DEVICE_KEY_DEVNAME, info->deviceName, DEVICE_NAME_BUF_LEN) != SOFTBUS_OK) {
        LOG_ERR("GetCommonDevInfo: COMM_DEVICE_KEY_DEVNAME failed");
        return SOFTBUS_ERR;
    }
    if (GetCommonDevInfo(COMM_DEVICE_KEY_DEVTYPE, devType, DEVICE_TYPE_BUF_LEN) != SOFTBUS_OK) {
        LOG_ERR("GetCommonDevInfo: COMM_DEVICE_KEY_DEVTYPE failed");
        return SOFTBUS_ERR;
    }
    if (UpdateLocalDeviceType(devType) != SOFTBUS_OK) {
        LOG_ERR("UpdateLocalDeviceType failed");
    }
    return SOFTBUS_OK;
}

static int32_t InitLocalVersionType(NodeInfo *info)
{
    if (info == NULL) {
        LOG_ERR("fail:para error!");
        return SOFTBUS_INVALID_PARAM;
    }
    if (strncpy_s(info->versionType, VERSION_MAX_LEN, VERSION_TYPE_LITE, strlen(VERSION_TYPE_LITE)) != EOK) {
        LOG_ERR("strncpy_s error");
        return SOFTBUS_MEM_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t InitConnectInfo(ConnectInfo *info)
{
    if (info == NULL) {
        LOG_ERR("fail:para error!");
        return SOFTBUS_INVALID_PARAM;
    }
    // get mac addr
    return GetCommonDevInfo(COMM_DEVICE_KEY_BT_MAC, info->macAddr, MAC_LEN);
}

static int32_t ModifyId(char *dstId, uint32_t dstLen, const char *sourceId)
{
    if (dstId == NULL || sourceId == NULL || strlen(sourceId) > dstLen - 1) {
        LOG_ERR("id:para error!");
        return SOFTBUS_INVALID_PARAM;
    }
    if (strncpy_s(dstId, dstLen, sourceId, strlen(sourceId)) != EOK) {
        LOG_ERR("strncpy_s error");
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

int32_t UpdateLocalStatus(ConnectStatus status)
{
    g_localNetLedger.localInfo.status = status;
    return SOFTBUS_OK;
}

int32_t UpdateLocalWeight(uint32_t weight)
{
    g_localNetLedger.localInfo.weight = weight;
    return SOFTBUS_OK;
}

static int32_t UpdateLocalDeviceIp(const void *ip)
{
    if (ip == NULL) {
        LOG_ERR("para error!");
        return SOFTBUS_INVALID_PARAM;
    }
    LnnSetWiFiIp(&g_localNetLedger.localInfo, ip);
    return SOFTBUS_OK;
}

static int32_t UpdateLocalBtMac(const void *mac)
{
    if (mac == NULL) {
        LOG_ERR("para error!");
        return SOFTBUS_INVALID_PARAM;
    }
    LnnSetBtMac(&g_localNetLedger.localInfo, (char *)mac);
    return SOFTBUS_OK;
}

static int32_t UpdateLocalNetIfName(const void *netIfName)
{
    if (netIfName == NULL) {
        LOG_ERR("para error!");
        return SOFTBUS_INVALID_PARAM;
    }
    LnnSetNetIfName(&g_localNetLedger.localInfo, (char *)netIfName);
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
    {STRING_KEY_WLAN_IP, IP_MAX_LEN, LlGetWlanIp, UpdateLocalDeviceIp},
    {STRING_KEY_NET_IF_NAME, NET_IF_NAME_LEN, LlGetNetIfName, UpdateLocalNetIfName},
    {NUM_KEY_SESSION_PORT, -1, LlGetSessionPort, UpdateLocalSessionPort},
    {NUM_KEY_AUTH_PORT, -1, LlGetAuthPort, UpdateLocalAuthPort},
    {NUM_KEY_PROXY_PORT, -1, LlGetProxyPort, UpdateLocalProxyPort},
    {NUM_KEY_NET_CAP, -1, LlGetNetCap, UpdateLocalNetCapability},
    {NUM_KEY_DEV_TYPE_ID, -1, LlGetDeviceTypeId, NULL},
};

int32_t LnnGetLocalLedgerStrInfo(InfoKey key, char *info, uint32_t len)
{
    uint32_t i;
    int32_t ret;
    if (info == NULL) {
        LOG_ERR("para error.");
        return SOFTBUS_INVALID_PARAM;
    }
    if (key >= STRING_KEY_END) {
        LOG_ERR("KEY error.");
        return SOFTBUS_INVALID_PARAM;
    }
    if (pthread_mutex_lock(&g_localNetLedger.lock) != 0) {
        LOG_ERR("lock mutex fail!");
        return SOFTBUS_ERR;
    }
    for (i = 0; i < sizeof(g_localKeyTable) / sizeof(LocalLedgerKey); i++) {
        if (key == g_localKeyTable[i].key) {
            if (g_localKeyTable[i].getInfo != NULL) {
                ret = g_localKeyTable[i].getInfo((void *)info, len);
                pthread_mutex_unlock(&g_localNetLedger.lock);
                return ret;
            }
        }
    }
    pthread_mutex_unlock(&g_localNetLedger.lock);
    LOG_ERR("KEY NOT exist.");
    return SOFTBUS_ERR;
}

int32_t LnnGetLocalLedgerNumInfo(InfoKey key, int32_t *info)
{
    uint32_t i;
    int32_t ret;
    if (info == NULL) {
        LOG_ERR("para error.");
        return SOFTBUS_INVALID_PARAM;
    }
    if (key < NUM_KEY_BEGIN || key >= NUM_KEY_END) {
        LOG_ERR("KEY error.");
        return SOFTBUS_INVALID_PARAM;
    }
    if (pthread_mutex_lock(&g_localNetLedger.lock) != 0) {
        LOG_ERR("lock mutex fail!");
        return SOFTBUS_ERR;
    }
    for (i = 0; i < sizeof(g_localKeyTable) / sizeof(LocalLedgerKey); i++) {
        if (key == g_localKeyTable[i].key) {
            if (g_localKeyTable[i].getInfo != NULL) {
                ret = g_localKeyTable[i].getInfo((void *)info, NUM_BUF_SIZE);
                pthread_mutex_unlock(&g_localNetLedger.lock);
                return ret;
            }
        }
    }
    pthread_mutex_unlock(&g_localNetLedger.lock);
    LOG_ERR("KEY NOT exist.");
    return SOFTBUS_ERR;
}

static bool JudgeString(const char *info, int32_t len)
{
    return (len <= 0) ? false : IsValidString(info, len);
}

int32_t LnnSetLocalLedgerStrInfo(InfoKey key, const char *info)
{
    uint32_t i;
    int32_t ret;
    if (info == NULL) {
        LOG_ERR("para error.");
        return SOFTBUS_INVALID_PARAM;
    }
    if (key >= STRING_KEY_END) {
        LOG_ERR("KEY error.");
        return SOFTBUS_INVALID_PARAM;
    }
    if (pthread_mutex_lock(&g_localNetLedger.lock) != 0) {
        LOG_ERR("lock mutex fail!");
        return SOFTBUS_ERR;
    }
    for (i = 0; i < sizeof(g_localKeyTable) / sizeof(LocalLedgerKey); i++) {
        if (key == g_localKeyTable[i].key) {
            if (g_localKeyTable[i].setInfo != NULL && JudgeString(info, g_localKeyTable[i].maxLen)) {
                ret = g_localKeyTable[i].setInfo((void *)info);
                pthread_mutex_unlock(&g_localNetLedger.lock);
                return ret;
            }
            LOG_ERR("key=%d not support or info format error", key);
            pthread_mutex_unlock(&g_localNetLedger.lock);
            return SOFTBUS_INVALID_PARAM;
        }
    }
    pthread_mutex_unlock(&g_localNetLedger.lock);
    LOG_ERR("key not exist.");
    return SOFTBUS_ERR;
}

int32_t LnnSetLocalLedgerNumInfo(InfoKey key, int32_t info)
{
    uint32_t i;
    int32_t ret;
    if (key < NUM_KEY_BEGIN || key >= NUM_KEY_END) {
        LOG_ERR("KEY error.");
        return SOFTBUS_INVALID_PARAM;
    }
    if (pthread_mutex_lock(&g_localNetLedger.lock) != 0) {
        LOG_ERR("lock mutex fail!");
        return SOFTBUS_ERR;
    }
    for (i = 0; i < sizeof(g_localKeyTable) / sizeof(LocalLedgerKey); i++) {
        if (key == g_localKeyTable[i].key) {
            if (g_localKeyTable[i].setInfo != NULL) {
                ret = g_localKeyTable[i].setInfo((void *)&info);
                pthread_mutex_unlock(&g_localNetLedger.lock);
                return ret;
            }
            LOG_ERR("key=%d not support", key);
            pthread_mutex_unlock(&g_localNetLedger.lock);
            return SOFTBUS_ERR;
        }
    }
    pthread_mutex_unlock(&g_localNetLedger.lock);
    LOG_ERR("key not exist.");
    return SOFTBUS_ERR;
}

int32_t LnnInitLocalLedger()
{
    NodeInfo *nodeInfo = NULL;
    if (g_localNetLedger.status == LL_INIT_SUCCESS) {
        LOG_INFO("local net ledger already init.");
        return SOFTBUS_OK;
    }
    g_localNetLedger.status = LL_INIT_UNKNOWN;
    nodeInfo = &g_localNetLedger.localInfo;
    (void)memset_s(nodeInfo, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    if (strncpy_s(nodeInfo->softBusVersion, VERSION_MAX_LEN, SOFTBUS_VERSION, strlen(SOFTBUS_VERSION)) != EOK) {
        LOG_ERR("fail:strncpy_s fail!");
        g_localNetLedger.status = LL_INIT_FAIL;
        return SOFTBUS_MEM_ERR;
    }
    nodeInfo->netCapacity = LnnGetNetCapabilty();
    DeviceBasicInfo *deviceInfo = &nodeInfo->deviceInfo;
    if (InitLocalDeviceInfo(deviceInfo) != SOFTBUS_OK) {
        LOG_ERR("init local device info error!");
        goto EXIT;
    }
    if (InitLocalVersionType(nodeInfo) != SOFTBUS_OK) {
        LOG_ERR("init local version type error!");
        goto EXIT;
    }
    if (InitConnectInfo(&nodeInfo->connectInfo) != SOFTBUS_OK) {
        LOG_ERR("init local connect info error!");
        goto EXIT;
    }

    if (pthread_mutex_init(&g_localNetLedger.lock, NULL) != 0) {
        LOG_ERR("mutex init fail!");
        goto EXIT;
    }
    g_localNetLedger.status = LL_INIT_SUCCESS;
    return SOFTBUS_OK;
EXIT:
    g_localNetLedger.status = LL_INIT_FAIL;
    return SOFTBUS_ERR;
}

void LnnDeinitLocalLedger()
{
    if (g_localNetLedger.status == LL_INIT_SUCCESS) {
        pthread_mutex_destroy(&g_localNetLedger.lock);
    }
    g_localNetLedger.status = LL_INIT_UNKNOWN;
}
