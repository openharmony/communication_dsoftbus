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

#include "anonymizer.h"
#include "bus_center_adapter.h"
#include "bus_center_manager.h"
#include "lnn_cipherkey_manager.h"
#include "lnn_device_info_recovery.h"
#include "lnn_log.h"
#include "lnn_ohos_account.h"
#include "lnn_p2p_info.h"
#include "lnn_feature_capability.h"
#include "lnn_settingdata_event_monitor.h"
#include "softbus_adapter_crypto.h"
#include "softbus_adapter_thread.h"
#include "softbus_def.h"
#include "softbus_errcode.h"
#include "softbus_utils.h"
#include "softbus_hidumper_buscenter.h"

#define SOFTBUS_VERSION "hm.1.0.0"
#define VERSION_TYPE_LITE "LITE"
#define VERSION_TYPE_DEFAULT ""
#define SOFTBUS_BUSCENTER_DUMP_LOCALDEVICEINFO "local_device_info"
#define ALL_GROUP_TYPE 0xF
#define MAX_STATE_VERSION 0xFF
#define SUPPORT_EXCHANGE_NETWORKID 1
#define DEFAULT_CONN_SUB_FEATURE 1

typedef struct {
    NodeInfo localInfo;
    SoftBusMutex lock;
    LocalLedgerStatus status;
} LocalNetLedger;

static LocalNetLedger g_localNetLedger;

static void UpdateStateVersionAndStore(void)
{
    int32_t ret;
    g_localNetLedger.localInfo.stateVersion++;
    if (g_localNetLedger.localInfo.stateVersion > MAX_STATE_VERSION) {
        g_localNetLedger.localInfo.stateVersion = 0;
    }
    LNN_LOGI(LNN_LEDGER, "local stateVersion=%{public}d",
        g_localNetLedger.localInfo.stateVersion);
    if ((ret = LnnSaveLocalDeviceInfo(&g_localNetLedger.localInfo)) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "update local store fail");
    }
}

static int32_t LlGetNodeSoftBusVersion(void *buf, uint32_t len)
{
    NodeInfo *info = &g_localNetLedger.localInfo;
    if (buf == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    if (strncpy_s((char *)buf, len, info->softBusVersion, strlen(info->softBusVersion)) != EOK) {
        LNN_LOGE(LNN_LEDGER, "STR COPY ERROR");
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
        LNN_LOGE(LNN_LEDGER, "get device udid fail");
        return SOFTBUS_ERR;
    }
    if (strlen(udid) <= 0) {
        LNN_LOGE(LNN_LEDGER, "get local udid invalid");
        return SOFTBUS_ERR;
    }
    if (strncpy_s((char *)buf, len, udid, strlen(udid)) != EOK) {
        LNN_LOGE(LNN_LEDGER, "STR COPY ERROR");
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
    if (strncpy_s((char *)buf, len, info->networkId, strlen(info->networkId)) != EOK) {
        LNN_LOGE(LNN_LEDGER, "STR COPY ERROR!");
        return SOFTBUS_MEM_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t LlGetOffLineCode(void *buf, uint32_t len)
{
    NodeInfo *info = &g_localNetLedger.localInfo;
    if (buf == NULL) {
        LNN_LOGE(LNN_LEDGER, "buf of offlinecode is null");
        return SOFTBUS_INVALID_PARAM;
    }
    if (memcpy_s(buf, len, info->offlineCode, OFFLINE_CODE_BYTE_SIZE) != EOK) {
        LNN_LOGE(LNN_LEDGER, "memcpy_s offlinecode ERROR");
        return SOFTBUS_MEM_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t LlGetExtData(void *buf, uint32_t len)
{
    NodeInfo *info = &g_localNetLedger.localInfo;
    if (buf == NULL) {
        LNN_LOGE(LNN_LEDGER, "buf of offlinecode is null");
        return SOFTBUS_INVALID_PARAM;
    }
    if (memcpy_s(buf, len, info->extData, EXTDATA_LEN) != EOK) {
        LNN_LOGE(LNN_LEDGER, "memcpy_s offlinecode ERROR!");
        return SOFTBUS_MEM_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t LlGetBleMac(void *buf, uint32_t len)
{
    NodeInfo *info = &g_localNetLedger.localInfo;
    const char *mac = NULL;
    if (buf == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    mac = LnnGetBleMac(info);
    if (mac == NULL) {
        LNN_LOGE(LNN_LEDGER, "get ble mac fail.");
        return SOFTBUS_ERR;
    }
    if (strcpy_s((char *)buf, len, mac) != EOK) {
        LNN_LOGE(LNN_LEDGER, "STR COPY ERROR!");
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
    if (strncpy_s((char *)buf, len, info->uuid, strlen(info->uuid)) != EOK) {
        LNN_LOGE(LNN_LEDGER, "STR COPY ERROR");
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
        LNN_LOGE(LNN_LEDGER, "deviceType fail");
        return SOFTBUS_ERR;
    }
    if (strncpy_s((char *)buf, len, deviceType, strlen(deviceType)) != EOK) {
        LNN_LOGE(LNN_LEDGER, "STR COPY ERROR");
        return SOFTBUS_MEM_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t LlGetWifiDirectAddr(void *buf, uint32_t len)
{
    const char *wifiDirectAddr = NULL;
    if (buf == NULL || len < MAC_LEN) {
        LNN_LOGE(LNN_LEDGER, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    wifiDirectAddr = LnnGetWifiDirectAddr(&g_localNetLedger.localInfo);
    if (wifiDirectAddr == NULL) {
        LNN_LOGE(LNN_LEDGER, "get wifidirect addr fail");
        return SOFTBUS_ERR;
    }
    if (strncpy_s((char *)buf, len, wifiDirectAddr, strlen(wifiDirectAddr)) != EOK) {
        LNN_LOGE(LNN_LEDGER, "copy wifidirect addr failed");
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
        LNN_LOGE(LNN_LEDGER, "LlGetAccount copy error");
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
        LNN_LOGE(LNN_LEDGER, "LlUpdateAccount copy error");
        return SOFTBUS_MEM_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t UpdateWifiDirectAddr(const void *wifiDirectAddr)
{
    if (wifiDirectAddr == NULL) {
        LNN_LOGE(LNN_LEDGER, "para error");
        return SOFTBUS_INVALID_PARAM;
    }
    return LnnSetWifiDirectAddr(&g_localNetLedger.localInfo, (char *)wifiDirectAddr);
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
    LNN_LOGE(LNN_LEDGER, "set device type error");
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

static int32_t LocalUpdateNodeAccountId(const void *buf)
{
    NodeInfo *info = &g_localNetLedger.localInfo;
    if (buf == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    info->accountId = *((int64_t *)buf);
    return SOFTBUS_OK;
}

static int32_t LocalUpdateBleStartTime(const void *buf)
{
    NodeInfo *info = &g_localNetLedger.localInfo;
    if (buf == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    info->bleStartTimestamp = *((int64_t *)buf);
    return SOFTBUS_OK;
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
        LNN_LOGE(LNN_LEDGER, "get device name fail");
        return SOFTBUS_ERR;
    }
    if (strncpy_s((char *)buf, len, deviceName, strlen(deviceName)) != EOK) {
        LNN_LOGE(LNN_LEDGER, "STR COPY ERROR");
        return SOFTBUS_MEM_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t LlGetUnifiedName(void *buf, uint32_t len)
{
    NodeInfo *info = &g_localNetLedger.localInfo;
    if (buf == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    if (strncpy_s((char *)buf, len, info->deviceInfo.unifiedName, strlen(info->deviceInfo.unifiedName)) != EOK) {
        LNN_LOGE(LNN_LEDGER, "strcpy err");
        return SOFTBUS_MEM_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t LlGetUnifiedDefaultName(void *buf, uint32_t len)
{
    NodeInfo *info = &g_localNetLedger.localInfo;
    if (buf == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    if (strncpy_s((char *)buf, len, info->deviceInfo.unifiedDefaultName,
        strlen(info->deviceInfo.unifiedDefaultName)) != EOK) {
        LNN_LOGE(LNN_LEDGER, "strcpy err");
        return SOFTBUS_MEM_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t LlGetNickName(void *buf, uint32_t len)
{
    NodeInfo *info = &g_localNetLedger.localInfo;
    if (buf == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    if (strncpy_s((char *)buf, len, info->deviceInfo.nickName, strlen(info->deviceInfo.nickName)) != EOK) {
        LNN_LOGE(LNN_LEDGER, "strcpy err");
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
        LNN_LOGE(LNN_LEDGER, "get bt mac fail.");
        return SOFTBUS_ERR;
    }
    if (strncpy_s((char *)buf, len, mac, strlen(mac)) != EOK) {
        LNN_LOGE(LNN_LEDGER, "STR COPY ERROR!");
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
        LNN_LOGE(LNN_LEDGER, "get wifi ip fail");
        return SOFTBUS_ERR;
    }
    char *anonyIp = NULL;
    Anonymize(ip, &anonyIp);
    LNN_LOGD(LNN_LEDGER, "get LocalIp=%{public}s", anonyIp);
    AnonymizeFree(anonyIp);
    if (strncpy_s((char *)buf, len, ip, strlen(ip)) != EOK) {
        LNN_LOGE(LNN_LEDGER, "STR COPY ERROR");
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
        LNN_LOGE(LNN_LEDGER, "get bt mac fail");
        return SOFTBUS_ERR;
    }
    if (strncpy_s((char *)buf, len, ifName, strlen(ifName)) != EOK) {
        LNN_LOGE(LNN_LEDGER, "STR COPY ERROR");
        return SOFTBUS_MEM_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t L1GetMasterNodeUdid(void *buf, uint32_t len)
{
    NodeInfo *info = &g_localNetLedger.localInfo;
    const char *udid = NULL;

    if (buf == NULL || len < UDID_BUF_LEN) {
        LNN_LOGE(LNN_LEDGER, "invalid get master node udid arguments");
        return SOFTBUS_INVALID_PARAM;
    }
    udid = LnnGetMasterUdid(info);
    if (udid == NULL) {
        LNN_LOGE(LNN_LEDGER, "get master udid fail");
        return SOFTBUS_ERR;
    }
    if (strncpy_s((char *)buf, len, udid, strlen(udid)) != EOK) {
        LNN_LOGE(LNN_LEDGER, "copy master udid failed");
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

static int32_t UpdateStateVersion(const void *buf)
{
    NodeInfo *info = &g_localNetLedger.localInfo;
    if (buf == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    if (*(int32_t *)buf > MAX_STATE_VERSION) {
        *(int32_t *)buf = 0;
    }
    info->stateVersion = *(int32_t *)buf;
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
    *((int32_t *)buf) = (int32_t)info->netCapacity;
    return SOFTBUS_OK;
}

static int32_t LlGetFeatureCapa(void *buf, uint32_t len)
{
    NodeInfo *info = &g_localNetLedger.localInfo;
    if (buf == NULL || len != sizeof(uint64_t)) {
        return SOFTBUS_INVALID_PARAM;
    }
    *((uint64_t *)buf) = info->feature;
    return SOFTBUS_OK;
}

static int32_t LlGetNetType(void *buf, uint32_t len)
{
    NodeInfo *info = &g_localNetLedger.localInfo;
    if (buf == NULL || len != LNN_COMMON_LEN) {
        return SOFTBUS_INVALID_PARAM;
    }
    *((int32_t *)buf) = (int32_t)info->discoveryType;
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
        LNN_LOGE(LNN_LEDGER, "get p2p mac fail");
        return SOFTBUS_ERR;
    }
    if (strncpy_s((char *)buf, len, mac, strlen(mac)) != EOK) {
        LNN_LOGE(LNN_LEDGER, "copy p2p mac failed");
        return SOFTBUS_MEM_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t L1GetWifiCfg(void *buf, uint32_t len)
{
    if (buf == NULL || len < WIFI_CFG_INFO_MAX_LEN) {
        return SOFTBUS_INVALID_PARAM;
    }
    const char *wifiCfg = LnnGetWifiCfg(&g_localNetLedger.localInfo);
    if (wifiCfg == NULL) {
        LNN_LOGE(LNN_LEDGER, "get wifi cfg fail");
        return SOFTBUS_ERR;
    }
    if (strncpy_s((char *)buf, len, wifiCfg, strlen(wifiCfg)) != EOK) {
        LNN_LOGE(LNN_LEDGER, "copy wifi cfg failed");
        return SOFTBUS_MEM_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t L1GetChanList5g(void *buf, uint32_t len)
{
    if (buf == NULL || len < WIFI_CFG_INFO_MAX_LEN) {
        return SOFTBUS_INVALID_PARAM;
    }
    const char *chanList5g = LnnGetWifiCfg(&g_localNetLedger.localInfo);
    if (chanList5g == NULL) {
        LNN_LOGE(LNN_LEDGER, "get chan list 5g fail");
        return SOFTBUS_ERR;
    }
    if (strncpy_s((char *)buf, len, chanList5g, strlen(chanList5g)) != EOK) {
        LNN_LOGE(LNN_LEDGER, "copy chan list 5g failed");
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
        LNN_LOGE(LNN_LEDGER, "get p2p go mac fail");
        return SOFTBUS_ERR;
    }
    if (strncpy_s((char *)buf, len, mac, strlen(mac)) != EOK) {
        LNN_LOGE(LNN_LEDGER, "copy p2p go mac failed");
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

static int32_t LlGetStateVersion(void *buf, uint32_t len)
{
    if (buf == NULL || len != LNN_COMMON_LEN) {
        return SOFTBUS_INVALID_PARAM;
    }
    *((int32_t *)buf) = g_localNetLedger.localInfo.stateVersion;
    return SOFTBUS_OK;
}

static int32_t L1GetStaFrequency(void *buf, uint32_t len)
{
    if (buf == NULL || len != LNN_COMMON_LEN) {
        return SOFTBUS_INVALID_PARAM;
    }
    *((int32_t *)buf) = LnnGetStaFrequency(&g_localNetLedger.localInfo);
    return SOFTBUS_OK;
}

static int32_t L1GetNodeDataChangeFlag(void *buf, uint32_t len)
{
    if (buf == NULL || len != DATA_CHANGE_FLAG_BUF_LEN) {
        return SOFTBUS_INVALID_PARAM;
    }
    *((int16_t *)buf) = (int16_t)LnnGetDataChangeFlag(&g_localNetLedger.localInfo);
    return SOFTBUS_OK;
}

static int32_t LocalGetNodeAccountId(void *buf, uint32_t len)
{
    if (buf == NULL || len != sizeof(int64_t)) {
        return SOFTBUS_INVALID_PARAM;
    }
    *((int64_t *)buf) = g_localNetLedger.localInfo.accountId;
    return SOFTBUS_OK;
}

static int32_t LocalGetNodeBleStartTime(void *buf, uint32_t len)
{
    if (buf == NULL || len != sizeof(int64_t)) {
        return SOFTBUS_INVALID_PARAM;
    }
    *((int64_t *)buf) = g_localNetLedger.localInfo.bleStartTimestamp;
    return SOFTBUS_OK;
}

static int32_t InitLocalDeviceInfo(DeviceBasicInfo *info)
{
    char devType[DEVICE_TYPE_BUF_LEN] = TYPE_UNKNOWN;

    if (info == NULL) {
        LNN_LOGE(LNN_LEDGER, "fail:para error!");
        return SOFTBUS_INVALID_PARAM;
    }
    (void)memset_s(info, sizeof(DeviceBasicInfo), 0, sizeof(DeviceBasicInfo));

    // get device info
    if (GetCommonDevInfo(COMM_DEVICE_KEY_DEVNAME, info->deviceName, DEVICE_NAME_BUF_LEN) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "COMM_DEVICE_KEY_DEVNAME failed");
        return SOFTBUS_ERR;
    }
    if (LnnGetUnifiedDeviceName(info->unifiedName, DEVICE_NAME_BUF_LEN) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "get unifiedName fail");
    }
    if (LnnGetUnifiedDefaultDeviceName(info->unifiedDefaultName, DEVICE_NAME_BUF_LEN) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "get unifiedDefaultName fail");
    }
    if (LnnGetSettingNickName(info->unifiedDefaultName, info->unifiedName,
        info->nickName, DEVICE_NAME_BUF_LEN) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "get nick name fail");
    }
    LNN_LOGD(LNN_LEDGER, "info->unifiedDefaultName=%{public}s, unifiedName=%{public}s, nickName=%{public}s",
        info->unifiedDefaultName, info->unifiedName, info->nickName);
    if (GetCommonDevInfo(COMM_DEVICE_KEY_DEVTYPE, devType, DEVICE_TYPE_BUF_LEN) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "GetCommonDevInfo: COMM_DEVICE_KEY_DEVTYPE failed");
        return SOFTBUS_ERR;
    }
    if (UpdateLocalDeviceType(devType) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "UpdateLocalDeviceType failed");
    }
    return SOFTBUS_OK;
}

static int32_t InitLocalVersionType(NodeInfo *info)
{
    char versionType[VERSION_MAX_LEN] = "";
    if (info == NULL) {
        LNN_LOGE(LNN_LEDGER, "fail:para error");
        return SOFTBUS_INVALID_PARAM;
    }
    if (GetCommonDevInfo(COMM_DEVICE_KEY_VERSION_TYPE, versionType, VERSION_MAX_LEN) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "COMM_DEVICE_KEY_VERSION_TYPE failed");
        return SOFTBUS_ERR;
    }
    if (strncpy_s(info->versionType, VERSION_MAX_LEN, versionType, strlen(versionType)) != EOK) {
        LNN_LOGE(LNN_LEDGER, "strncpy_s error");
        return SOFTBUS_MEM_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t InitOfflineCode(NodeInfo *info)
{
    if (info == NULL) {
        LNN_LOGE(LNN_LEDGER, "info of offlinecode is null");
        return SOFTBUS_INVALID_PARAM;
    }
    if (memset_s(info->offlineCode, OFFLINE_CODE_BYTE_SIZE, 0, OFFLINE_CODE_BYTE_SIZE) != EOK) {
        LNN_LOGE(LNN_LEDGER, "offlineCode memset_s failed");
        return SOFTBUS_ERR;
    }
    if (SoftBusGenerateRandomArray(info->offlineCode, OFFLINE_CODE_BYTE_SIZE) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "generate offlinecode error");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t InitConnectInfo(ConnectInfo *info)
{
    if (info == NULL) {
        LNN_LOGE(LNN_LEDGER, "fail:para error");
        return SOFTBUS_INVALID_PARAM;
    }
    // get mac addr
    if (GetCommonDevInfo(COMM_DEVICE_KEY_BLE_MAC, info->bleMacAddr, MAC_LEN) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "get ble mac fail!");
        return SOFTBUS_ERR;
    }
    return GetCommonDevInfo(COMM_DEVICE_KEY_BT_MAC, info->macAddr, MAC_LEN);
}

static int32_t ModifyId(char *dstId, uint32_t dstLen, const char *sourceId)
{
    if (dstId == NULL || sourceId == NULL || strlen(sourceId) > dstLen - 1) {
        LNN_LOGE(LNN_LEDGER, "id:para error");
        return SOFTBUS_INVALID_PARAM;
    }
    if (strncpy_s(dstId, dstLen, sourceId, strlen(sourceId)) != EOK) {
        LNN_LOGE(LNN_LEDGER, "strncpy_s error");
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
    if (name == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    const char *beforeName = LnnGetDeviceName(&g_localNetLedger.localInfo.deviceInfo);
    if (strcmp(beforeName, (char *)name) != 0) {
        if (LnnSetDeviceName(&g_localNetLedger.localInfo.deviceInfo, (char *)name) != SOFTBUS_OK) {
            LNN_LOGE(LNN_LEDGER, "set device name fail");
            return SOFTBUS_ERR;
        }
        UpdateStateVersionAndStore();
    }
    return SOFTBUS_OK;
}

static int32_t UpdateUnifiedName(const void *name)
{
    if (name == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    const char *beforeName = g_localNetLedger.localInfo.deviceInfo.unifiedName;
    if (strcmp(beforeName, (char *)name) != 0) {
        if (strcpy_s(g_localNetLedger.localInfo.deviceInfo.unifiedName,
            DEVICE_NAME_BUF_LEN, (char *)name) != EOK) {
            return SOFTBUS_ERR;
        }
        UpdateStateVersionAndStore();
    }
    return SOFTBUS_OK;
}

static int32_t UpdateUnifiedDefaultName(const void *name)
{
    if (name == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    const char *beforeName = g_localNetLedger.localInfo.deviceInfo.unifiedDefaultName;
    if (strcmp(beforeName, (char *)name) != 0) {
        if (strcpy_s(g_localNetLedger.localInfo.deviceInfo.unifiedDefaultName,
            DEVICE_NAME_BUF_LEN, (char *)name) != EOK) {
            return SOFTBUS_ERR;
        }
    }
    return SOFTBUS_OK;
}

static int32_t UpdateNickName(const void *name)
{
    if (name == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    const char *beforeName = g_localNetLedger.localInfo.deviceInfo.nickName;
    if (strcmp(beforeName, (char *)name) != 0) {
        if (strcpy_s(g_localNetLedger.localInfo.deviceInfo.nickName,
            DEVICE_NAME_BUF_LEN, (char *)name) != EOK) {
            return SOFTBUS_ERR;
        }
        UpdateStateVersionAndStore();
    }
    return SOFTBUS_OK;
}

static int32_t UpdateLocalNetworkId(const void *id)
{
    if (ModifyId(g_localNetLedger.localInfo.networkId, NETWORK_ID_BUF_LEN, (char *)id) != SOFTBUS_OK) {
        return SOFTBUS_ERR;
    }
    UpdateStateVersionAndStore();
    return SOFTBUS_OK;
}

static int32_t LlUpdateLocalOffLineCode(const void *id)
{
    return ModifyId((char *)g_localNetLedger.localInfo.offlineCode, OFFLINE_CODE_BYTE_SIZE, (char *)id);
}

static int32_t LlUpdateLocalExtData(const void *id)
{
    return ModifyId((char *)g_localNetLedger.localInfo.extData, EXTDATA_LEN, (char *)id);
}

static int32_t UpdateLocalBleMac(const void *mac)
{
    if (mac == NULL) {
        LNN_LOGE(LNN_LEDGER, "para error");
        return SOFTBUS_INVALID_PARAM;
    }
    LnnSetBleMac(&g_localNetLedger.localInfo, (char *)mac);
    return SOFTBUS_OK;
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

static int32_t UpdateLocalFeatureCapability(const void *capability)
{
    if (capability == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    g_localNetLedger.localInfo.feature |= *(uint64_t *)capability;
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
        LNN_LOGE(LNN_LEDGER, "para error");
        return SOFTBUS_INVALID_PARAM;
    }
    LnnSetWiFiIp(&g_localNetLedger.localInfo, (char *)ip);
    char *anonyIp = NULL;
    Anonymize((char *)ip, &anonyIp);
    LNN_LOGI(LNN_LEDGER, "set LocalIp=%{public}s", anonyIp);
    AnonymizeFree(anonyIp);
    return SOFTBUS_OK;
}

static int32_t UpdateLocalBtMac(const void *mac)
{
    if (mac == NULL) {
        LNN_LOGE(LNN_LEDGER, "para error");
        return SOFTBUS_INVALID_PARAM;
    }
    LnnSetBtMac(&g_localNetLedger.localInfo, (char *)mac);
    return SOFTBUS_OK;
}

static int32_t UpdateLocalNetIfName(const void *netIfName)
{
    if (netIfName == NULL) {
        LNN_LOGE(LNN_LEDGER, "para error");
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
        LNN_LOGE(LNN_LEDGER, "get local udid fail");
    } else {
        role = g_localNetLedger.localInfo.role;
        if (strcmp(localUdid, (char *)udid) == 0) {
            g_localNetLedger.localInfo.role = ROLE_CONTROLLER;
        } else {
            g_localNetLedger.localInfo.role = ROLE_LEAF;
        }
        LNN_LOGI(LNN_LEDGER, "update local role. role:%{public}d->%{public}d",
            role, g_localNetLedger.localInfo.role);
    }
    return LnnSetMasterUdid(&g_localNetLedger.localInfo, (const char *)udid);
}

static int32_t UpdateP2pMac(const void *mac)
{
    if (mac == NULL) {
        LNN_LOGE(LNN_LEDGER, "para error");
        return SOFTBUS_INVALID_PARAM;
    }
    return LnnSetP2pMac(&g_localNetLedger.localInfo, (char *)mac);
}

static int32_t UpdateWifiCfg(const void *wifiCfg)
{
    if (wifiCfg == NULL) {
        LNN_LOGE(LNN_LEDGER, "para error");
        return SOFTBUS_INVALID_PARAM;
    }
    return LnnSetWifiCfg(&g_localNetLedger.localInfo, (char *)wifiCfg);
}

static int32_t UpdateChanList5g(const void *chanList5g)
{
    if (chanList5g == NULL) {
        LNN_LOGE(LNN_LEDGER, "para error");
        return SOFTBUS_INVALID_PARAM;
    }
    return LnnSetChanList5g(&g_localNetLedger.localInfo, (char *)chanList5g);
}

static int32_t UpdateP2pGoMac(const void *mac)
{
    if (mac == NULL) {
        LNN_LOGE(LNN_LEDGER, "para error");
        return SOFTBUS_INVALID_PARAM;
    }
    return LnnSetP2pGoMac(&g_localNetLedger.localInfo, (char *)mac);
}

static int32_t UpdateP2pRole(const void *p2pRole)
{
    if (p2pRole == NULL) {
        LNN_LOGE(LNN_LEDGER, "para error");
        return SOFTBUS_INVALID_PARAM;
    }
    return LnnSetP2pRole(&g_localNetLedger.localInfo, *(int32_t *)p2pRole);
}

static int32_t UpdateStaFrequency(const void *staFrequency)
{
    if (staFrequency == NULL) {
        LNN_LOGE(LNN_LEDGER, "para error");
        return SOFTBUS_INVALID_PARAM;
    }
    return LnnSetStaFrequency(&g_localNetLedger.localInfo, *(int32_t *)staFrequency);
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
        LNN_LOGE(LNN_LEDGER, "copy node addr to buf fail");
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
        LNN_LOGE(LNN_LEDGER, "copy node addr to buf fail");
        return SOFTBUS_MEM_ERR;
    }
    return SOFTBUS_OK;
}

int32_t LnnUpdateLocalNetworkId(const void *id)
{
    if (ModifyId(g_localNetLedger.localInfo.networkId, NETWORK_ID_BUF_LEN, (char *)id) != SOFTBUS_OK) {
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

void LnnUpdateStateVersion()
{
    return UpdateStateVersionAndStore();
}

static int32_t LlGetStaticCapLen(void *buf, uint32_t len)
{
    if (buf == NULL || len > sizeof(int32_t)) {
        LNN_LOGE(LNN_LEDGER, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    *((int64_t *)buf) = g_localNetLedger.localInfo.staticCapLen;
    return SOFTBUS_OK;
}

static int32_t LlUpdateStaticCapLen(const void *len)
{
    if (len == NULL) {
        LNN_LOGE(LNN_LEDGER, "invalid length");
        return SOFTBUS_INVALID_PARAM;
    }
    g_localNetLedger.localInfo.staticCapLen = *(int32_t *)len;
    return SOFTBUS_OK;
}

int32_t LlUpdateStaticCapability(const void *staticCap)
{
    if (staticCap == NULL) {
        LNN_LOGE(LNN_LEDGER, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    NodeInfo *info = &g_localNetLedger.localInfo;
    return LnnSetStaticCapability(info, (uint8_t *)staticCap, info->staticCapLen);
}

int32_t LlGetStaticCapability(void *buf, uint32_t len)
{
    if (buf == NULL || len > STATIC_CAP_LEN) {
        LNN_LOGE(LNN_LEDGER, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    NodeInfo *info = &g_localNetLedger.localInfo;
    if (LnnGetStaticCapability(info, (uint8_t *)buf, len) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "get static cap fail");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t LlGetIrk(void *buf, uint32_t len)
{
    if (buf == NULL || len == 0) {
        LNN_LOGE(LNN_LEDGER, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    NodeInfo *info = &g_localNetLedger.localInfo;
    if (memcpy_s(buf, len, info->rpaInfo.peerIrk, LFINDER_IRK_LEN) != EOK) {
        LNN_LOGE(LNN_LEDGER, "memcpy peerIrk fail");
        return SOFTBUS_MEM_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t LlGetPubMac(void *buf, uint32_t len)
{
    if (buf == NULL || len == 0) {
        LNN_LOGE(LNN_LEDGER, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    NodeInfo *info = &g_localNetLedger.localInfo;
    if (memcpy_s(buf, len, info->rpaInfo.publicAddress, LFINDER_MAC_ADDR_LEN) != EOK) {
        LNN_LOGE(LNN_LEDGER, "memcpy publicAddress fail");
        return SOFTBUS_MEM_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t LlGetCipherInfoKey(void *buf, uint32_t len)
{
    if (buf == NULL || len == 0) {
        LNN_LOGE(LNN_LEDGER, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    NodeInfo *info = &g_localNetLedger.localInfo;
    if (memcpy_s(buf, len, info->cipherInfo.key, SESSION_KEY_LENGTH) != EOK) {
        LNN_LOGE(LNN_LEDGER, "memcpy cipher key fail");
        return SOFTBUS_MEM_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t LlGetCipherInfoIv(void *buf, uint32_t len)
{
    if (buf == NULL || len == 0) {
        LNN_LOGE(LNN_LEDGER, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    NodeInfo *info = &g_localNetLedger.localInfo;
    if (memcpy_s(buf, len, info->cipherInfo.iv, BROADCAST_IV_LEN) != EOK) {
        LNN_LOGE(LNN_LEDGER, "memcpy cipher iv fail");
        return SOFTBUS_MEM_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t UpdateLocalIrk(const void *id)
{
    if (id == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    if (memcpy_s((char *)g_localNetLedger.localInfo.rpaInfo.peerIrk, LFINDER_IRK_LEN, id, LFINDER_IRK_LEN) != EOK) {
        LNN_LOGE(LNN_LEDGER, "memcpy peerIrk fail");
        return SOFTBUS_MEM_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t UpdateLocalPubMac(const void *id)
{
    if (id == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    if (memcpy_s((char *)g_localNetLedger.localInfo.rpaInfo.publicAddress,
        LFINDER_MAC_ADDR_LEN, id, LFINDER_MAC_ADDR_LEN) != EOK) {
        LNN_LOGE(LNN_LEDGER, "memcpy publicAddress fail");
        return SOFTBUS_MEM_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t UpdateLocalCipherInfoKey(const void *id)
{
    if (id == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    if (memcpy_s((char *)g_localNetLedger.localInfo.cipherInfo.key,
    SESSION_KEY_LENGTH, id, SESSION_KEY_LENGTH) != EOK) {
        LNN_LOGE(LNN_LEDGER, "memcpy cipherInfo.key fail");
        return SOFTBUS_MEM_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t UpdateLocalCipherInfoIv(const void *id)
{
    if (id == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    if (memcpy_s((char *)g_localNetLedger.localInfo.cipherInfo.iv, BROADCAST_IV_LEN, id, BROADCAST_IV_LEN) != EOK) {
        LNN_LOGE(LNN_LEDGER, "memcpy cipherInfo.iv fail");
        return SOFTBUS_MEM_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t LlGetP2pIp(void *buf, uint32_t len)
{
    if (buf == NULL) {
        LNN_LOGE(LNN_LEDGER, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    NodeInfo *info = &g_localNetLedger.localInfo;
    if (strcpy_s((char *)buf, len, info->p2pInfo.p2pIp) != EOK) {
        LNN_LOGE(LNN_LEDGER, "STR COPY ERROR");
        return SOFTBUS_MEM_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t LlUpdateLocalP2pIp(const void *p2pIp)
{
    if (p2pIp == NULL) {
        LNN_LOGE(LNN_LEDGER, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    NodeInfo *info = &g_localNetLedger.localInfo;
    if (strcpy_s(info->p2pInfo.p2pIp, sizeof(info->p2pInfo.p2pIp), (const char *)p2pIp) != EOK) {
        LNN_LOGE(LNN_LEDGER, "STR COPY ERROR");
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
    {STRING_KEY_DEV_UNIFIED_NAME, DEVICE_NAME_BUF_LEN, LlGetUnifiedName, UpdateUnifiedName},
    {STRING_KEY_DEV_UNIFIED_DEFAULT_NAME, DEVICE_NAME_BUF_LEN, LlGetUnifiedDefaultName, UpdateUnifiedDefaultName},
    {STRING_KEY_DEV_NICK_NAME, DEVICE_NAME_BUF_LEN, LlGetNickName, UpdateNickName},
    {STRING_KEY_BT_MAC, MAC_LEN, LlGetBtMac, UpdateLocalBtMac},
    {STRING_KEY_WLAN_IP, IP_LEN, LlGetWlanIp, UpdateLocalDeviceIp},
    {STRING_KEY_NET_IF_NAME, NET_IF_NAME_LEN, LlGetNetIfName, UpdateLocalNetIfName},
    {STRING_KEY_MASTER_NODE_UDID, UDID_BUF_LEN, L1GetMasterNodeUdid, UpdateMasterNodeUdid},
    {STRING_KEY_NODE_ADDR, SHORT_ADDRESS_MAX_LEN, LlGetNodeAddr, LlUpdateNodeAddr},
    {STRING_KEY_P2P_MAC, MAC_LEN, LlGetP2pMac, UpdateP2pMac},
    {STRING_KEY_WIFI_CFG, WIFI_CFG_INFO_MAX_LEN, L1GetWifiCfg, UpdateWifiCfg},
    {STRING_KEY_CHAN_LIST_5G, CHANNEL_LIST_STR_LEN, L1GetChanList5g, UpdateChanList5g},
    {STRING_KEY_P2P_GO_MAC, MAC_LEN, LlGetP2pGoMac, UpdateP2pGoMac},
    {STRING_KEY_OFFLINE_CODE, OFFLINE_CODE_LEN, LlGetOffLineCode, LlUpdateLocalOffLineCode},
    {STRING_KEY_EXTDATA, EXTDATA_LEN, LlGetExtData, LlUpdateLocalExtData},
    {STRING_KEY_BLE_MAC, MAC_LEN, LlGetBleMac, UpdateLocalBleMac},
    {STRING_KEY_WIFIDIRECT_ADDR, MAC_LEN, LlGetWifiDirectAddr, UpdateWifiDirectAddr},
    {STRING_KEY_P2P_IP, IP_LEN, LlGetP2pIp, LlUpdateLocalP2pIp},
    {NUM_KEY_SESSION_PORT, -1, LlGetSessionPort, UpdateLocalSessionPort},
    {NUM_KEY_AUTH_PORT, -1, LlGetAuthPort, UpdateLocalAuthPort},
    {NUM_KEY_PROXY_PORT, -1, LlGetProxyPort, UpdateLocalProxyPort},
    {NUM_KEY_NET_CAP, -1, LlGetNetCap, UpdateLocalNetCapability},
    {NUM_KEY_FEATURE_CAPA, -1, LlGetFeatureCapa, UpdateLocalFeatureCapability},
    {NUM_KEY_DISCOVERY_TYPE, -1, LlGetNetType, NULL},
    {NUM_KEY_DEV_TYPE_ID, -1, LlGetDeviceTypeId, NULL},
    {NUM_KEY_MASTER_NODE_WEIGHT, -1, L1GetMasterNodeWeight, UpdateMasgerNodeWeight},
    {NUM_KEY_P2P_ROLE, -1, L1GetP2pRole, UpdateP2pRole},
    {NUM_KEY_STATE_VERSION, -1, LlGetStateVersion, UpdateStateVersion},
    {NUM_KEY_STA_FREQUENCY, -1, L1GetStaFrequency, UpdateStaFrequency},
    {NUM_KEY_TRANS_PROTOCOLS, sizeof(int64_t), LlGetSupportedProtocols, LlUpdateSupportedProtocols},
    {NUM_KEY_DATA_CHANGE_FLAG, sizeof(int16_t), L1GetNodeDataChangeFlag, UpdateNodeDataChangeFlag},
    {NUM_KEY_ACCOUNT_LONG, sizeof(int64_t), LocalGetNodeAccountId, LocalUpdateNodeAccountId},
    {NUM_KEY_BLE_START_TIME, sizeof(int64_t), LocalGetNodeBleStartTime, LocalUpdateBleStartTime},
    {NUM_KEY_STATIC_CAP_LEN, sizeof(int32_t), LlGetStaticCapLen, LlUpdateStaticCapLen},
    {BYTE_KEY_IRK, LFINDER_IRK_LEN, LlGetIrk, UpdateLocalIrk},
    {BYTE_KEY_PUB_MAC, LFINDER_MAC_ADDR_LEN, LlGetPubMac, UpdateLocalPubMac},
    {BYTE_KEY_BROADCAST_CIPHER_KEY, SESSION_KEY_LENGTH, LlGetCipherInfoKey, UpdateLocalCipherInfoKey},
    {BYTE_KEY_BROADCAST_CIPHER_IV, BROADCAST_IV_LEN, LlGetCipherInfoIv, UpdateLocalCipherInfoIv},
    {BYTE_KEY_ACCOUNT_HASH, SHA_256_HASH_LEN, LlGetAccount, LlUpdateAccount},
    {BYTE_KEY_STATIC_CAPABILITY, STATIC_CAP_LEN, LlGetStaticCapability, LlUpdateStaticCapability},
};

int32_t LnnGetLocalStrInfo(InfoKey key, char *info, uint32_t len)
{
    uint32_t i;
    int32_t ret;
    if (info == NULL) {
        LNN_LOGE(LNN_LEDGER, "para error");
        return SOFTBUS_INVALID_PARAM;
    }
    if (key >= STRING_KEY_END) {
        LNN_LOGE(LNN_LEDGER, "KEY error");
        return SOFTBUS_INVALID_PARAM;
    }
    if (SoftBusMutexLock(&g_localNetLedger.lock) != 0) {
        LNN_LOGE(LNN_LEDGER, "lock mutex fail");
        return SOFTBUS_LOCK_ERR;
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
    LNN_LOGE(LNN_LEDGER, "KEY NOT exist");
    return SOFTBUS_ERR;
}

static int32_t LnnGetLocalInfo(InfoKey key, void* info, uint32_t infoSize)
{
    uint32_t i;
    int32_t ret;
    if (info == NULL) {
        LNN_LOGE(LNN_LEDGER, "para error");
        return SOFTBUS_INVALID_PARAM;
    }
    if ((key < NUM_KEY_BEGIN || key >= NUM_KEY_END) &&
        (key < BYTE_KEY_BEGIN || key >= BYTE_KEY_END)) {
        LNN_LOGE(LNN_LEDGER, "KEY error");
        return SOFTBUS_INVALID_PARAM;
    }
    if (SoftBusMutexLock(&g_localNetLedger.lock) != 0) {
        LNN_LOGE(LNN_LEDGER, "lock mutex fail");
        return SOFTBUS_LOCK_ERR;
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
    LNN_LOGE(LNN_LEDGER, "KEY NOT exist");
    return SOFTBUS_ERR;
}

static bool JudgeString(const char *info, int32_t len)
{
    return (len <= 0) ? false : IsValidString(info, (uint32_t)len);
}

int32_t LnnSetLocalUnifiedName(const char *unifiedName)
{
    if (unifiedName == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    if (SoftBusMutexLock(&g_localNetLedger.lock) != 0) {
        LNN_LOGE(LNN_LEDGER, "lock mutex fail");
        return SOFTBUS_LOCK_ERR;
    }
    if (strcpy_s(g_localNetLedger.localInfo.deviceInfo.unifiedName,
        DEVICE_NAME_BUF_LEN, unifiedName) != EOK) {
        SoftBusMutexUnlock(&g_localNetLedger.lock);
        return SOFTBUS_ERR;
    }
    SoftBusMutexUnlock(&g_localNetLedger.lock);
    return SOFTBUS_OK;
}

int32_t LnnSetLocalStrInfo(InfoKey key, const char *info)
{
    uint32_t i;
    int32_t ret;
    if (info == NULL) {
        LNN_LOGE(LNN_LEDGER, "para error");
        return SOFTBUS_INVALID_PARAM;
    }
    if (key >= STRING_KEY_END) {
        LNN_LOGE(LNN_LEDGER, "KEY error");
        return SOFTBUS_INVALID_PARAM;
    }
    if (SoftBusMutexLock(&g_localNetLedger.lock) != 0) {
        LNN_LOGE(LNN_LEDGER, "lock mutex fail");
        return SOFTBUS_LOCK_ERR;
    }
    for (i = 0; i < sizeof(g_localKeyTable) / sizeof(LocalLedgerKey); i++) {
        if (key == g_localKeyTable[i].key) {
            if (g_localKeyTable[i].setInfo != NULL && JudgeString(info, g_localKeyTable[i].maxLen)) {
                ret = g_localKeyTable[i].setInfo((void *)info);
                SoftBusMutexUnlock(&g_localNetLedger.lock);
                return ret;
            }
            LNN_LOGE(LNN_LEDGER, "key not support or info format error. key=%{public}d", key);
            SoftBusMutexUnlock(&g_localNetLedger.lock);
            return SOFTBUS_INVALID_PARAM;
        }
    }
    SoftBusMutexUnlock(&g_localNetLedger.lock);
    LNN_LOGE(LNN_LEDGER, "key not exist");
    return SOFTBUS_ERR;
}

static int32_t LnnSetLocalInfo(InfoKey key, void* info)
{
    uint32_t i;
    int32_t ret;
    if ((key < NUM_KEY_BEGIN || key >= NUM_KEY_END) &&
        (key < BYTE_KEY_BEGIN || key >= BYTE_KEY_END)) {
        LNN_LOGE(LNN_LEDGER, "KEY error");
        return SOFTBUS_INVALID_PARAM;
    }
    if (SoftBusMutexLock(&g_localNetLedger.lock) != 0) {
        LNN_LOGE(LNN_LEDGER, "lock mutex fail");
        return SOFTBUS_LOCK_ERR;
    }
    for (i = 0; i < sizeof(g_localKeyTable) / sizeof(LocalLedgerKey); i++) {
        if (key == g_localKeyTable[i].key) {
            if (g_localKeyTable[i].setInfo != NULL) {
                ret = g_localKeyTable[i].setInfo(info);
                SoftBusMutexUnlock(&g_localNetLedger.lock);
                return ret;
            }
            LNN_LOGE(LNN_LEDGER, "key not support. key=%{public}d", key);
            SoftBusMutexUnlock(&g_localNetLedger.lock);
            return SOFTBUS_ERR;
        }
    }
    SoftBusMutexUnlock(&g_localNetLedger.lock);
    LNN_LOGE(LNN_LEDGER, "key not exist");
    return SOFTBUS_ERR;
}

static int32_t LnnFirstGetUdid(void)
{
    NodeInfo *nodeInfo = &g_localNetLedger.localInfo;
    DeviceBasicInfo *deviceInfo = &nodeInfo->deviceInfo;
    if (GetCommonDevInfo(COMM_DEVICE_KEY_UDID, deviceInfo->deviceUdid, UDID_BUF_LEN) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "COMM_DEVICE_KEY_UDID failed");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t LnnGenBroadcastCipherInfo(void)
{
    if (LnnLoadLocalBroadcastCipherKey() == SOFTBUS_OK) {
        BroadcastCipherKey broadcastKey;
        (void)memset_s(&broadcastKey, sizeof(BroadcastCipherKey), 0, sizeof(BroadcastCipherKey));
        if (LnnGetLocalBroadcastCipherKey(&broadcastKey) != SOFTBUS_OK) {
            LNN_LOGE(LNN_LEDGER, "get local info failed.");
            return SOFTBUS_ERR;
        }
        if (LnnSetLocalByteInfo(BYTE_KEY_BROADCAST_CIPHER_KEY,
            broadcastKey.cipherInfo.key, SESSION_KEY_LENGTH) != SOFTBUS_OK) {
            (void)memset_s(&broadcastKey, sizeof(BroadcastCipherKey), 0, sizeof(BroadcastCipherKey));
            LNN_LOGE(LNN_LEDGER, "set key error.");
            return SOFTBUS_ERR;
        }
        if (LnnSetLocalByteInfo(BYTE_KEY_BROADCAST_CIPHER_IV,
            broadcastKey.cipherInfo.iv, BROADCAST_IV_LEN) != SOFTBUS_OK) {
            (void)memset_s(&broadcastKey, sizeof(BroadcastCipherKey), 0, sizeof(BroadcastCipherKey));
            LNN_LOGE(LNN_LEDGER, "set iv error.");
            return SOFTBUS_ERR;
        }
        (void)memset_s(&broadcastKey, sizeof(BroadcastCipherKey), 0, sizeof(BroadcastCipherKey));
        LNN_LOGI(LNN_LEDGER, "load BroadcastCipherInfo success!");
        return SOFTBUS_OK;
    }

    BroadcastCipherKey broadcastKey;
    (void)memset_s(&broadcastKey, sizeof(BroadcastCipherKey), 0, sizeof(BroadcastCipherKey));
    if (SoftBusGenerateRandomArray(broadcastKey.cipherInfo.key, SESSION_KEY_LENGTH) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "generate broadcast key error.");
        return SOFTBUS_ERR;
    }
    if (SoftBusGenerateRandomArray(broadcastKey.cipherInfo.iv, BROADCAST_IV_LEN) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "generate broadcast iv error.");
        return SOFTBUS_ERR;
    }
    if (LnnSetLocalByteInfo(BYTE_KEY_BROADCAST_CIPHER_KEY,
        broadcastKey.cipherInfo.key, SESSION_KEY_LENGTH) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "set key error.");
        return SOFTBUS_ERR;
    }
    if (LnnSetLocalByteInfo(BYTE_KEY_BROADCAST_CIPHER_IV,
        broadcastKey.cipherInfo.iv, BROADCAST_IV_LEN) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "set iv error.");
        return SOFTBUS_ERR;
    }
    if (LnnUpdateLocalBroadcastCipherKey(&broadcastKey) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "update local broadcast key failed");
        return SOFTBUS_ERR;
    }
    LNN_LOGI(LNN_LEDGER, "generate BroadcastCipherInfo success!");
    return SOFTBUS_OK;
}

int32_t LnnGetLocalNumInfo(InfoKey key, int32_t *info)
{
    return LnnGetLocalInfo(key, (void*)info, sizeof(int32_t));
}

int32_t LnnGetLocalNum64Info(InfoKey key, int64_t *info)
{
    return LnnGetLocalInfo(key, (void*)info, sizeof(int64_t));
}

int32_t LnnGetLocalNumU64Info(InfoKey key, uint64_t *info)
{
    return LnnGetLocalInfo(key, (void*)info, sizeof(uint64_t));
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
        LNN_LOGE(LNN_LEDGER, "info is null");
        return SOFTBUS_INVALID_PARAM;
    }
    rc = LnnGetLocalStrInfo(STRING_KEY_DEV_NAME, info->deviceName, DEVICE_NAME_BUF_LEN);
    if (rc != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "get local device info failed");
        return SOFTBUS_ERR;
    }
    rc = LnnGetLocalStrInfo(STRING_KEY_NETWORKID, info->networkId, NETWORK_ID_BUF_LEN);
    if (rc != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "get local network id info failed");
        return SOFTBUS_ERR;
    }
    rc = LnnGetLocalStrInfo(STRING_KEY_DEV_TYPE, type, DEVICE_TYPE_BUF_LEN);
    if (rc != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "get local device type failed");
        return SOFTBUS_ERR;
    }
    return LnnConvertDeviceTypeToId(type, &info->deviceTypeId);
}

int32_t SoftBusDumpBusCenterLocalDeviceInfo(int fd)
{
    SOFTBUS_DPRINTF(fd, "-----LocalDeviceInfo-----\n");
    NodeBasicInfo localNodeInfo;
    if (LnnGetLocalDeviceInfo(&localNodeInfo) != 0) {
        LNN_LOGE(LNN_LEDGER, "LnnGetLocalDeviceInfo failed");
        return SOFTBUS_ERR;
    }
    SoftBusDumpBusCenterPrintInfo(fd, &localNodeInfo);
    return SOFTBUS_OK;
}

static int32_t LnnInitLocalNodeInfo(NodeInfo *nodeInfo)
{
    if (InitOfflineCode(nodeInfo) != SOFTBUS_OK) {
        return SOFTBUS_ERR;
    }
    if (strcpy_s(nodeInfo->nodeAddress, sizeof(nodeInfo->nodeAddress), NODE_ADDR_LOOPBACK) != EOK) {
        LNN_LOGE(LNN_LEDGER, "fail:strncpy_s fail");
        return SOFTBUS_ERR;
    }
    if (InitLocalDeviceInfo(&nodeInfo->deviceInfo) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "init local device info error");
        return SOFTBUS_ERR;
    }
    if (InitLocalVersionType(nodeInfo) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "init local version type error");
        return SOFTBUS_ERR;
    }
    if (InitConnectInfo(&nodeInfo->connectInfo) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "init local connect info error");
        return SOFTBUS_ERR;
    }
    if (LnnInitLocalP2pInfo(nodeInfo) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "init local p2p info error");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int32_t LnnInitLocalLedger(void)
{
    NodeInfo *nodeInfo = NULL;
    if (g_localNetLedger.status == LL_INIT_SUCCESS) {
        LNN_LOGI(LNN_LEDGER, "local net ledger already init");
        return SOFTBUS_OK;
    }
    g_localNetLedger.status = LL_INIT_UNKNOWN;
    nodeInfo = &g_localNetLedger.localInfo;
    (void)memset_s(nodeInfo, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    if (strncpy_s(nodeInfo->softBusVersion, VERSION_MAX_LEN, SOFTBUS_VERSION, strlen(SOFTBUS_VERSION)) != EOK) {
        LNN_LOGE(LNN_LEDGER, "fail:strncpy_s fail");
        g_localNetLedger.status = LL_INIT_FAIL;
        return SOFTBUS_MEM_ERR;
    }
    nodeInfo->groupType = ALL_GROUP_TYPE;
    nodeInfo->discoveryType = 0;
    nodeInfo->netCapacity = LnnGetNetCapabilty();
    nodeInfo->authCapacity = SUPPORT_EXCHANGE_NETWORKID;
    nodeInfo->feature = LnnGetFeatureCapabilty();
    nodeInfo->connSubFeature = DEFAULT_CONN_SUB_FEATURE;
    if (LnnInitLocalNodeInfo(nodeInfo) != SOFTBUS_OK) {
        g_localNetLedger.status = LL_INIT_FAIL;
        return SOFTBUS_ERR;
    }
    if (SoftBusMutexInit(&g_localNetLedger.lock, NULL) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "mutex init fail");
        g_localNetLedger.status = LL_INIT_FAIL;
        return SOFTBUS_ERR;
    }
    if (SoftBusRegBusCenterVarDump(
        (char *)SOFTBUS_BUSCENTER_DUMP_LOCALDEVICEINFO, &SoftBusDumpBusCenterLocalDeviceInfo) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "SoftBusRegBusCenterVarDump regist fail");
        return SOFTBUS_ERR;
    }
    if (LnnFirstGetUdid() != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "first get udid fail, try again in one second");
    }
    if (LnnGenBroadcastCipherInfo() != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "generate cipher fail");
    }
    g_localNetLedger.status = LL_INIT_SUCCESS;
    return SOFTBUS_OK;
}

int32_t LnnInitLocalLedgerDelay(void)
{
    NodeInfo *nodeInfo = &g_localNetLedger.localInfo;
    DeviceBasicInfo *deviceInfo = &nodeInfo->deviceInfo;
    if (GetCommonDevInfo(COMM_DEVICE_KEY_UDID, deviceInfo->deviceUdid, UDID_BUF_LEN) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "GetCommonDevInfo: COMM_DEVICE_KEY_UDID failed");
        return SOFTBUS_ERR;
    }
    if (LnnInitOhosAccount() != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "init default ohos account failed");
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
        LNN_LOGE(LNN_LEDGER, "lock mutex fail");
        return ret;
    }
    const char* masterUdid = g_localNetLedger.localInfo.masterUdid;
    const char* deviceUdid = g_localNetLedger.localInfo.deviceInfo.deviceUdid;
    ret = strncmp(masterUdid, deviceUdid, strlen(deviceUdid)) == 0;
    SoftBusMutexUnlock(&g_localNetLedger.lock);
    return ret;
}
