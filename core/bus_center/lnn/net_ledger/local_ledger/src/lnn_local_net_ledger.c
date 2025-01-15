/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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
#include "auth_common.h"
#include "bus_center_adapter.h"
#include "bus_center_manager.h"
#include "lnn_ble_heartbeat.h"
#include "lnn_cipherkey_manager.h"
#include "lnn_data_cloud_sync.h"
#include "lnn_device_info_recovery.h"
#include "lnn_log.h"
#include "lnn_ohos_account.h"
#include "lnn_p2p_info.h"
#include "lnn_feature_capability.h"
#include "lnn_settingdata_event_monitor.h"
#include "softbus_adapter_bt_common.h"
#include "softbus_adapter_crypto.h"
#include "softbus_adapter_thread.h"
#include "softbus_def.h"
#include "softbus_error_code.h"
#include "softbus_utils.h"
#include "legacy/softbus_hidumper_buscenter.h"

#define SOFTBUS_VERSION "hm.1.0.0"
#define VERSION_TYPE_LITE "LITE"
#define VERSION_TYPE_DEFAULT ""
#define SOFTBUS_BUSCENTER_DUMP_LOCALDEVICEINFO "local_device_info"
#define ALL_GROUP_TYPE 0xF
#define MAX_STATE_VERSION 0xFF
#define DEFAULT_SUPPORT_HBCAPACITY 0x3
#define DEFAULT_CONN_SUB_FEATURE 3
#define CACHE_KEY_LENGTH 32
#define STATE_VERSION_VALUE_LENGTH 8
#define DEFAULT_DEVICE_NAME "OpenHarmony"

typedef struct {
    LocalLedgerStatus status;
    SoftBusMutex lock;
    NodeInfo localInfo;
} LocalNetLedger;

static LocalNetLedger g_localNetLedger;

static void UpdateStateVersionAndStore(StateVersionChangeReason reason)
{
    int32_t ret;
    g_localNetLedger.localInfo.stateVersion++;
    if (g_localNetLedger.localInfo.stateVersion > MAX_STATE_VERSION) {
        g_localNetLedger.localInfo.stateVersion = 1;
    }
    g_localNetLedger.localInfo.stateVersionReason = reason;
    LNN_LOGI(LNN_LEDGER,
        "reason=%{public}u changed, update local stateVersion=%{public}d, stateVersionReason=%{public}u", reason,
        g_localNetLedger.localInfo.stateVersion, g_localNetLedger.localInfo.stateVersionReason);

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
        return SOFTBUS_NETWORK_GET_DEVICE_INFO_ERR;
    }
    if (strlen(udid) <= 0) {
        LNN_LOGE(LNN_LEDGER, "get local udid invalid");
        return SOFTBUS_NETWORK_GET_DEVICE_INFO_ERR;
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

static int32_t LlGetOsVersion(void *buf, uint32_t len)
{
    NodeInfo *info = &g_localNetLedger.localInfo;
    if (buf == NULL) {
        LNN_LOGE(LNN_LEDGER, "buf of osVersion is null");
        return SOFTBUS_INVALID_PARAM;
    }
    if (strcpy_s((char *)buf, len, info->deviceInfo.osVersion) != EOK) {
        LNN_LOGE(LNN_LEDGER, "strcpy_s osVersion ERROR!");
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
        return SOFTBUS_NETWORK_GET_DEVICE_INFO_ERR;
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

static int32_t L1GetNodeScreenOnFlag(void *buf, uint32_t len)
{
    if (buf == NULL) {
        LNN_LOGE(LNN_LEDGER, "buf is NULL");
        return SOFTBUS_INVALID_PARAM;
    }
    if (len != NODE_SCREEN_STATUS_LEN) {
        LNN_LOGE(LNN_LEDGER, "buf len=%{public}d is invalid", len);
        return SOFTBUS_INVALID_PARAM;
    }
    *((bool *)buf) = g_localNetLedger.localInfo.isScreenOn;
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
        return SOFTBUS_NETWORK_GET_DEVICE_INFO_ERR;
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
        return SOFTBUS_NETWORK_GET_DEVICE_INFO_ERR;
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
        LNN_LOGI(LNN_LEDGER, "update local deviceTypeId=%{public}u, deviceType=%{public}s", typeId, (char *)buf);
        return SOFTBUS_OK;
    }
    LNN_LOGE(LNN_LEDGER, "set device type error");
    return SOFTBUS_NETWORK_SET_LEDGER_INFO_ERR;
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

    int64_t accountId = 0;
    if (LnnGetAccountIdFromLocalCache(&accountId) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "get accountId info from cache fail");
    }
    if (accountId == *((int64_t *)buf) && *((int64_t *)buf) != 0) {
        LNN_LOGI(LNN_LEDGER, "no new accountId login");
        info->accountId = *((int64_t *)buf);
        return SOFTBUS_OK;
    }
    if (info->accountId == 0) {
        if (*((int64_t *)buf) == 0) {
            LNN_LOGI(LNN_LEDGER, "no accountId login, default is 0");
            return SOFTBUS_OK;
        }
        LNN_LOGI(LNN_LEDGER, "accountId login");
        info->accountId = *((int64_t *)buf);
        UpdateStateVersionAndStore(UPDATE_ACCOUNT_LONG);
        return SOFTBUS_OK;
    }
    if (*((int64_t *)buf) == 0) {
        LNN_LOGI(LNN_LEDGER, "accountId logout");
        info->accountId = *((int64_t *)buf);
        LnnSaveLocalDeviceInfo(info);
        return SOFTBUS_OK;
    }
    LNN_LOGI(LNN_LEDGER, "accountId changed, accountId=%{public}" PRId64 "->%{public}" PRId64, info->accountId,
        *((int64_t *)buf));
    info->accountId = *((int64_t *)buf);
    UpdateStateVersionAndStore(UPDATE_ACCOUNT_LONG);
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

static int32_t LocalUpdateNetworkIdTimeStamp(const void *buf)
{
    NodeInfo *info = &g_localNetLedger.localInfo;
    if (buf == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    info->networkIdTimestamp = *((int64_t *)buf);
    LNN_LOGI(LNN_LEDGER, "local networkId timeStamp=%{public}" PRId64, info->networkIdTimestamp);
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
        return SOFTBUS_NETWORK_GET_DEVICE_INFO_ERR;
    }
    if (strlen(deviceName) != 0) {
        if (strncpy_s((char *)buf, len, deviceName, strlen(deviceName)) != EOK) {
            LNN_LOGE(LNN_LEDGER, "STR COPY ERROR");
            return SOFTBUS_MEM_ERR;
        }
    } else {
        LNN_LOGI(LNN_LEDGER, "device name not inited, user default value");
        if (strncpy_s((char *)buf, len, DEFAULT_DEVICE_NAME, strlen(DEFAULT_DEVICE_NAME)) != EOK) {
            LNN_LOGE(LNN_LEDGER, "STR COPY ERROR");
            return SOFTBUS_MEM_ERR;
        }
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

static void UpdateBrMac(void)
{
    char brMac[BT_MAC_LEN] = {0};
    SoftBusBtAddr mac = {0};
    int32_t ret = 0;
    ret = SoftBusGetBtMacAddr(&mac);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "get bt mac addr fail");
        return;
    }
    ret = ConvertBtMacToStr(brMac, BT_MAC_LEN, mac.addr, sizeof(mac.addr));
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "convert bt mac to str fail");
        return;
    }
    if (strcpy_s(g_localNetLedger.localInfo.connectInfo.macAddr, MAC_LEN, brMac) != EOK) {
        LNN_LOGE(LNN_LEDGER, "str copy error!");
    }
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
        return SOFTBUS_NETWORK_GET_DEVICE_INFO_ERR;
    }
    if (SoftBusGetBtState() == BLE_ENABLE && mac[0] == '\0') {
        LNN_LOGE(LNN_LEDGER, "bt status is on update brmac");
        UpdateBrMac();
    }
    if (strcpy_s((char *)buf, len, mac) != EOK) {
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
        return SOFTBUS_NETWORK_GET_DEVICE_INFO_ERR;
    }
    char *anonyIp = NULL;
    Anonymize(ip, &anonyIp);
    LNN_LOGD(LNN_LEDGER, "get LocalIp=%{public}s", AnonymizeWrapper(anonyIp));
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
        return SOFTBUS_NETWORK_GET_DEVICE_INFO_ERR;
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
        return SOFTBUS_NETWORK_GET_DEVICE_INFO_ERR;
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
        return SOFTBUS_INVALID_PORT;
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

static bool IsLocalLedgerReady(void)
{
    bool accountIdInited = (g_localNetLedger.localInfo.accountId != 0);
    bool deviceNameInited = (strlen(g_localNetLedger.localInfo.deviceInfo.deviceName) != 0);
    bool networkIdInited = (strlen(g_localNetLedger.localInfo.networkId) != 0);
    bool btMacInited = (strlen(g_localNetLedger.localInfo.connectInfo.macAddr) != 0);
    if (accountIdInited & deviceNameInited & networkIdInited & btMacInited) {
        return true;
    }
    LNN_LOGI(LNN_LEDGER, "no need upload to cloud. stateVersion=%{public}d, accountIdInited=%{public}d, "
        "deviceNameInited=%{public}d, networkIdInited=%{public}d, btMacInited=%{public}d",
        g_localNetLedger.localInfo.stateVersion, accountIdInited, deviceNameInited, networkIdInited, btMacInited);
    return false;
}

static int32_t UpdateStateVersion(const void *buf)
{
    NodeInfo *info = &g_localNetLedger.localInfo;
    if (buf == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    if (*(int32_t *)buf > MAX_STATE_VERSION) {
        *(int32_t *)buf = 1;
    }
    if (info->stateVersion == *(int32_t *)buf) {
        LNN_LOGI(LNN_LEDGER, "unchanged. no need update, stateVersion=%{public}d", info->stateVersion);
        return SOFTBUS_OK;
    }
    info->stateVersion = *(int32_t *)buf;
    if (!IsLocalLedgerReady()) {
        return SOFTBUS_OK;
    }
    LNN_LOGI(LNN_LEDGER, "stateVersion is changed, stateVersion=%{public}d", info->stateVersion);
    NodeInfo nodeInfo = {};
    if (memcpy_s(&nodeInfo, sizeof(NodeInfo), &g_localNetLedger.localInfo, sizeof(NodeInfo)) != EOK) {
        LNN_LOGE(LNN_LEDGER, "memcpy fail");
        return SOFTBUS_MEM_ERR;
    }
    if (LnnAsyncCallLedgerAllDataSyncToDB(&nodeInfo) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "ledger stateversion change sync to cloud failed");
    }
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
    *((uint32_t *)buf) = info->netCapacity;
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

static int32_t L1GetConnSubFeatureCapa(void *buf, uint32_t len)
{
    if (buf == NULL || len != sizeof(uint64_t)) {
        return SOFTBUS_INVALID_PARAM;
    }
    NodeInfo *info = &g_localNetLedger.localInfo;
    *((uint64_t *)buf) = info->connSubFeature;
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

static int32_t LlGetOsType(void *buf, uint32_t len)
{
    NodeInfo *info = &g_localNetLedger.localInfo;
    if (buf == NULL || len != sizeof(uint32_t)) {
        LNN_LOGE(LNN_LEDGER, "buf of osType is null");
        return SOFTBUS_INVALID_PARAM;
    }
    *((int32_t *)buf) = info->deviceInfo.osType;
    return SOFTBUS_OK;
}

static int32_t LlGetAuthCapability(void *buf, uint32_t len)
{
    NodeInfo *info = &g_localNetLedger.localInfo;
    if (buf == NULL || len != sizeof(uint32_t)) {
        LNN_LOGE(LNN_LEDGER, "buf of authCapability is null");
        return SOFTBUS_INVALID_PARAM;
    }
    *((int32_t *)buf) = info->authCapacity;
    return SOFTBUS_OK;
}

static int32_t LlGetHbCapability(void *buf, uint32_t len)
{
    NodeInfo *info = &g_localNetLedger.localInfo;
    if (buf == NULL || len != sizeof(uint32_t)) {
        LNN_LOGE(LNN_LEDGER, "buf of heartbeatCapacity is null");
        return SOFTBUS_INVALID_PARAM;
    }
    *((int32_t *)buf) = info->heartbeatCapacity;
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
        return SOFTBUS_NETWORK_GET_DEVICE_INFO_ERR;
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
        return SOFTBUS_GET_WIFI_DEVICE_CONFIG_FAIL;
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
        return SOFTBUS_GET_WIFI_DEVICE_CONFIG_FAIL;
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
        return SOFTBUS_NETWORK_GET_DEVICE_INFO_ERR;
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

static int32_t L1GetDataDynamicLevel(void *buf, uint32_t len)
{
    if (buf == NULL || len != DATA_DYNAMIC_LEVEL_BUF_LEN) {
        return SOFTBUS_INVALID_PARAM;
    }
    *((uint16_t *)buf) = (uint16_t)LnnGetDataDynamicLevel(&g_localNetLedger.localInfo);
    return SOFTBUS_OK;
}

static int32_t UpdateDataDynamicLevel(const void *buf)
{
    if (buf == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    NodeInfo *info = &g_localNetLedger.localInfo;
    return LnnSetDataDynamicLevel(info, *(uint16_t *)buf);
}

static int32_t L1GetDataStaticLevel(void *buf, uint32_t len)
{
    if (buf == NULL || len != DATA_STATIC_LEVEL_BUF_LEN) {
        return SOFTBUS_INVALID_PARAM;
    }
    *((uint16_t *)buf) = (uint16_t)LnnGetDataStaticLevel(&g_localNetLedger.localInfo);
    return SOFTBUS_OK;
}

static int32_t UpdateDataStaticLevel(const void *buf)
{
    if (buf == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    NodeInfo *info = &g_localNetLedger.localInfo;
    return LnnSetDataStaticLevel(info, *(uint16_t *)buf);
}

static int32_t L1GetDataSwitchLevel(void *buf, uint32_t len)
{
    if (buf == NULL || len != DATA_SWITCH_LEVEL_BUF_LEN) {
        return SOFTBUS_INVALID_PARAM;
    }
    *((uint32_t *)buf) = (uint32_t)LnnGetDataSwitchLevel(&g_localNetLedger.localInfo);
    return SOFTBUS_OK;
}

static int32_t UpdateDataSwitchLevel(const void *buf)
{
    if (buf == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    NodeInfo *info = &g_localNetLedger.localInfo;
    return LnnSetDataSwitchLevel(info, *(uint32_t *)buf);
}

static int32_t L1GetDataSwitchLength(void *buf, uint32_t len)
{
    if (buf == NULL || len != DATA_SWITCH_LENGTH_BUF_LEN) {
        return SOFTBUS_INVALID_PARAM;
    }
    *((uint16_t *)buf) = (uint16_t)LnnGetDataSwitchLength(&g_localNetLedger.localInfo);
    return SOFTBUS_OK;
}

static int32_t UpdateDataSwitchLength(const void *buf)
{
    if (buf == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    NodeInfo *info = &g_localNetLedger.localInfo;
    return LnnSetDataSwitchLength(info, *(uint16_t *)buf);
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

static int32_t LocalGetNetworkIdTimeStamp(void *buf, uint32_t len)
{
    if (buf == NULL || len != sizeof(int64_t)) {
        return SOFTBUS_INVALID_PARAM;
    }
    *((int64_t *)buf) = g_localNetLedger.localInfo.networkIdTimestamp;
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
        return SOFTBUS_NETWORK_GET_DEVICE_INFO_ERR;
    }
    if (GetCommonOsType(&info->osType) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "get os type failed");
    }
    if (GetCommonOsVersion(info->osVersion, OS_VERSION_BUF_LEN) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "get os version failed");
    }
    if (GetCommonDeviceVersion(info->deviceVersion, DEVICE_VERSION_SIZE_MAX) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "get device version failed");
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
    if (GetCommonDevInfo(COMM_DEVICE_KEY_DEVTYPE, devType, DEVICE_TYPE_BUF_LEN) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "GetCommonDevInfo: COMM_DEVICE_KEY_DEVTYPE failed");
        return SOFTBUS_NETWORK_GET_DEVICE_INFO_ERR;
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
        return SOFTBUS_NETWORK_GET_DEVICE_INFO_ERR;
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
        return SOFTBUS_MEM_ERR;
    }
    if (SoftBusGenerateRandomArray(info->offlineCode, OFFLINE_CODE_BYTE_SIZE) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "generate offlinecode error");
        return SOFTBUS_GENERATE_RANDOM_ARRAY_FAIL;
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
        return SOFTBUS_NETWORK_GET_DEVICE_INFO_ERR;
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

int32_t LnnGetLocalNodeInfoSafe(NodeInfo *info)
{
    if (SoftBusMutexLock(&g_localNetLedger.lock) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "lock mutex fail");
        return SOFTBUS_LOCK_ERR;
    }
    if (memcpy_s(info, sizeof(NodeInfo), LnnGetLocalNodeInfo(), sizeof(NodeInfo)) != EOK) {
        LNN_LOGE(LNN_LEDGER, "memcpy node info fail");
        SoftBusMutexUnlock(&g_localNetLedger.lock);
        return SOFTBUS_MEM_ERR;
    }
    SoftBusMutexUnlock(&g_localNetLedger.lock);
    return SOFTBUS_OK;
}

static int32_t UpdateLocalDeviceName(const void *name)
{
    if (name == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    NodeInfo localNodeInfo = {};
    (void)LnnGetLocalDevInfo(&localNodeInfo);
    const char *beforeName = LnnGetDeviceName(&g_localNetLedger.localInfo.deviceInfo);
    char *anonyBeforeName = NULL;
    Anonymize(beforeName, &anonyBeforeName);
    char *anonyName = NULL;
    Anonymize((char *)name, &anonyName);
    char *anonyDeviceName = NULL;
    Anonymize(localNodeInfo.deviceInfo.deviceName, &anonyDeviceName);
    LNN_LOGI(LNN_LEDGER, "device name=%{public}s->%{public}s, cache=%{public}s",
        AnonymizeWrapper(anonyBeforeName), AnonymizeWrapper(anonyName), AnonymizeWrapper(anonyDeviceName));
    AnonymizeFree(anonyBeforeName);
    AnonymizeFree(anonyName);
    AnonymizeFree(anonyDeviceName);
    if (strcmp(beforeName, (char *)name) != 0) {
        if (LnnSetDeviceName(&g_localNetLedger.localInfo.deviceInfo, (char *)name) != SOFTBUS_OK) {
            LNN_LOGE(LNN_LEDGER, "set device name fail");
            return SOFTBUS_NETWORK_SET_DEVICE_INFO_ERR;
        }
        if (strcmp((char *)name, localNodeInfo.deviceInfo.deviceName) == 0) {
            LNN_LOGI(LNN_LEDGER, "device name is same as localcache");
            return SOFTBUS_OK;
        }
        UpdateStateVersionAndStore(UPDATE_DEV_NAME);
        if (!IsLocalLedgerReady()) {
            return SOFTBUS_OK;
        }
        NodeInfo nodeInfo = {};
        if (memcpy_s(&nodeInfo, sizeof(NodeInfo), &g_localNetLedger.localInfo, sizeof(NodeInfo)) != EOK) {
            LNN_LOGE(LNN_LEDGER, "memcpy fail");
            return SOFTBUS_MEM_ERR;
        }
        if (LnnAsyncCallLedgerAllDataSyncToDB(&nodeInfo) != SOFTBUS_OK) {
            LNN_LOGE(LNN_LEDGER, "ledger device name change sync to cloud failed");
        }
    }
    return SOFTBUS_OK;
}

static int32_t UpdateUnifiedName(const void *name)
{
    if (name == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    NodeInfo localNodeInfo = {};
    (void)LnnGetLocalDevInfo(&localNodeInfo);
    const char *beforeName = g_localNetLedger.localInfo.deviceInfo.unifiedName;
    if (strcmp(beforeName, (char *)name) != 0) {
        if (strcpy_s(g_localNetLedger.localInfo.deviceInfo.unifiedName,
            DEVICE_NAME_BUF_LEN, (char *)name) != EOK) {
            return SOFTBUS_STRCPY_ERR;
        }
        if (strcmp((char *)name, localNodeInfo.deviceInfo.unifiedName) == 0) {
            LNN_LOGI(LNN_LEDGER, "device unified name is same as localcache");
            return SOFTBUS_OK;
        }
        UpdateStateVersionAndStore(UPDATE_DEV_UNIFIED_NAME);
        if (!IsLocalLedgerReady()) {
            return SOFTBUS_OK;
        }
        LNN_LOGI(LNN_LEDGER, "unified device name is changed");
        NodeInfo nodeInfo = {};
        if (memcpy_s(&nodeInfo, sizeof(NodeInfo), &g_localNetLedger.localInfo, sizeof(NodeInfo)) != EOK) {
            LNN_LOGE(LNN_LEDGER, "memcpy fail");
            return SOFTBUS_MEM_ERR;
        }
        if (LnnLedgerAllDataSyncToDB(&nodeInfo) != SOFTBUS_OK) {
            LNN_LOGE(LNN_LEDGER, "ledger unified device name change sync to cloud failed");
        }
    }
    return SOFTBUS_OK;
}

static int32_t UpdateUnifiedDefaultName(const void *name)
{
    if (name == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    NodeInfo localNodeInfo = {};
    (void)LnnGetLocalDevInfo(&localNodeInfo);
    const char *beforeName = g_localNetLedger.localInfo.deviceInfo.unifiedDefaultName;
    if (strcmp(beforeName, (char *)name) != 0) {
        if (strcpy_s(g_localNetLedger.localInfo.deviceInfo.unifiedDefaultName, DEVICE_NAME_BUF_LEN, (char *)name) !=
            EOK) {
            return SOFTBUS_STRCPY_ERR;
        }
        if (strcmp((char *)name, localNodeInfo.deviceInfo.unifiedDefaultName) == 0) {
            LNN_LOGI(LNN_LEDGER, "device unified default name is same as localcache");
            return SOFTBUS_OK;
        }
        UpdateStateVersionAndStore(UPDATE_DEV_UNIFIED_DEFAULT_NAME);
        if (!IsLocalLedgerReady()) {
            return SOFTBUS_OK;
        }
        LNN_LOGI(LNN_LEDGER, "device unified default name is changed");
        NodeInfo nodeInfo = {};
        if (memcpy_s(&nodeInfo, sizeof(NodeInfo), &g_localNetLedger.localInfo, sizeof(NodeInfo)) != EOK) {
            LNN_LOGE(LNN_LEDGER, "memcpy fail");
            return SOFTBUS_MEM_ERR;
        }
        if (LnnAsyncCallLedgerAllDataSyncToDB(&nodeInfo) != SOFTBUS_OK) {
            LNN_LOGE(LNN_LEDGER, "ledger unified default device name change sync to cloud failed");
        }
    }
    return SOFTBUS_OK;
}

static int32_t UpdateNickName(const void *name)
{
    if (name == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    NodeInfo localNodeInfo = {};
    (void)LnnGetLocalDevInfo(&localNodeInfo);
    const char *beforeName = g_localNetLedger.localInfo.deviceInfo.nickName;
    if (strcmp(beforeName, (char *)name) != 0) {
        if (strcpy_s(g_localNetLedger.localInfo.deviceInfo.nickName, DEVICE_NAME_BUF_LEN, (char *)name) != EOK) {
            return SOFTBUS_STRCPY_ERR;
        }
        if (strcmp((char *)name, localNodeInfo.deviceInfo.nickName) == 0) {
            LNN_LOGI(LNN_LEDGER, "device nick name is same as localcache");
            return SOFTBUS_OK;
        }
        UpdateStateVersionAndStore(UPDATE_DEV_NICK_NAME);
        if (!IsLocalLedgerReady()) {
            return SOFTBUS_OK;
        }
        LNN_LOGI(LNN_LEDGER, "device nick name is changed");
        NodeInfo nodeInfo = {};
        if (memcpy_s(&nodeInfo, sizeof(NodeInfo), &g_localNetLedger.localInfo, sizeof(NodeInfo)) != EOK) {
            LNN_LOGE(LNN_LEDGER, "memcpy fail");
            return SOFTBUS_MEM_ERR;
        }
        if (LnnAsyncCallLedgerAllDataSyncToDB(&nodeInfo) != SOFTBUS_OK) {
            LNN_LOGE(LNN_LEDGER, "ledger nick name change sync to cloud failed");
        }
    }
    return SOFTBUS_OK;
}

int32_t LnnUpdateLocalNetworkIdTime(int64_t time)
{
    if (SoftBusMutexLock(&g_localNetLedger.lock) != 0) {
        LNN_LOGE(LNN_LEDGER, "lock mutex fail");
        return SOFTBUS_LOCK_ERR;
    }
    g_localNetLedger.localInfo.networkIdTimestamp = time;
    SoftBusMutexUnlock(&g_localNetLedger.lock);
    return SOFTBUS_OK;
}

static int32_t UpdateLocalNetworkId(const void *id)
{
    int32_t ret = ModifyId(g_localNetLedger.localInfo.lastNetworkId, NETWORK_ID_BUF_LEN,
        g_localNetLedger.localInfo.networkId);
    if (ret != SOFTBUS_OK) {
        return ret;
    }
    ret = ModifyId(g_localNetLedger.localInfo.networkId, NETWORK_ID_BUF_LEN, (char *)id);
    if (ret != SOFTBUS_OK) {
        return ret;
    }
    char *anonyNetworkId = NULL;
    char *anonyOldNetworkId = NULL;
    Anonymize(g_localNetLedger.localInfo.networkId, &anonyNetworkId);
    Anonymize(g_localNetLedger.localInfo.lastNetworkId, &anonyOldNetworkId);
    g_localNetLedger.localInfo.networkIdTimestamp = (int64_t)SoftBusGetSysTimeMs();
    LNN_LOGI(LNN_LEDGER, "networkId change %{public}s -> %{public}s, networkIdTimestamp=%{public}" PRId64,
        AnonymizeWrapper(anonyOldNetworkId), AnonymizeWrapper(anonyNetworkId),
        g_localNetLedger.localInfo.networkIdTimestamp);
    UpdateStateVersionAndStore(UPDATE_NETWORKID);
    AnonymizeFree(anonyNetworkId);
    AnonymizeFree(anonyOldNetworkId);
    if (!IsLocalLedgerReady()) {
        return SOFTBUS_OK;
    }
    NodeInfo nodeInfo =  {};
    if (memcpy_s(&nodeInfo, sizeof(NodeInfo), &g_localNetLedger.localInfo, sizeof(NodeInfo)) != EOK) {
        LNN_LOGE(LNN_LEDGER, "memcpy fail");
        return SOFTBUS_MEM_ERR;
    }
    if (LnnAsyncCallLedgerAllDataSyncToDB(&nodeInfo) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "ledger networkId change sync to cloud failed");
    }
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

static int32_t UpdateLocalConnSubFeatureCapability(const void *capability)
{
    if (capability == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    g_localNetLedger.localInfo.connSubFeature |= *(uint64_t *)capability;
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
    LNN_LOGI(LNN_LEDGER, "set LocalIp=%{public}s", AnonymizeWrapper(anonyIp));
    AnonymizeFree(anonyIp);
    return SOFTBUS_OK;
}

static int32_t UpdateLocalBtMac(const void *mac)
{
    if (mac == NULL) {
        LNN_LOGE(LNN_LEDGER, "para error");
        return SOFTBUS_INVALID_PARAM;
    }
    const char *beforeMac = LnnGetBtMac(&g_localNetLedger.localInfo);
    if (strcmp(beforeMac, (char *)mac) == 0) {
        LNN_LOGI(LNN_LEDGER, "unchanged. no need update");
        return SOFTBUS_OK;
    }
    LnnSetBtMac(&g_localNetLedger.localInfo, (char *)mac);
    NodeInfo localNodeInfo;
    (void)memset_s(&localNodeInfo, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    if (LnnGetLocalDevInfo(&localNodeInfo) == SOFTBUS_OK) {
        LnnSetBtMac(&localNodeInfo, (char *)mac);
        if (LnnSaveLocalDeviceInfo(&localNodeInfo) != SOFTBUS_OK) {
            LNN_LOGE(LNN_LEDGER, "update Bt mac to localdevinfo store fail");
        }
    } else {
        LNN_LOGE(LNN_LEDGER, "get local device info fail");
    }
    if (!IsLocalLedgerReady()) {
        return SOFTBUS_OK;
    }
    LNN_LOGI(LNN_LEDGER, "device bt mac is changed");
    NodeInfo nodeInfo = {};
    if (memcpy_s(&nodeInfo, sizeof(NodeInfo), &g_localNetLedger.localInfo, sizeof(NodeInfo)) != EOK) {
        LNN_LOGE(LNN_LEDGER, "memcpy fail");
        return SOFTBUS_MEM_ERR;
    }
    if (LnnAsyncCallLedgerAllDataSyncToDB(&nodeInfo) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "ledger btMac change sync to cloud failed");
    }
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
    if (SoftBusMutexLock(&g_localNetLedger.lock) != 0) {
        LNN_LOGE(LNN_LEDGER, "lock mutex fail");
        return SOFTBUS_LOCK_ERR;
    }
    int32_t ret = ModifyId(g_localNetLedger.localInfo.lastNetworkId, NETWORK_ID_BUF_LEN,
        g_localNetLedger.localInfo.networkId);
    if (ret != SOFTBUS_OK) {
        SoftBusMutexUnlock(&g_localNetLedger.lock);
        return ret;
    }
    ret = ModifyId(g_localNetLedger.localInfo.networkId, NETWORK_ID_BUF_LEN, (char *)id);
    if (ret != SOFTBUS_OK) {
        SoftBusMutexUnlock(&g_localNetLedger.lock);
        return ret;
    }
    SoftBusMutexUnlock(&g_localNetLedger.lock);
    return SOFTBUS_OK;
}

int32_t LnnUpdateLocalDeviceName(const DeviceBasicInfo *info)
{
    if (info == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    if (SoftBusMutexLock(&g_localNetLedger.lock) != 0) {
        LNN_LOGE(LNN_LEDGER, "lock mutex fail");
        return SOFTBUS_LOCK_ERR;
    }
    if (strlen(g_localNetLedger.localInfo.deviceInfo.deviceName) > 0) {
        SoftBusMutexUnlock(&g_localNetLedger.lock);
        return SOFTBUS_OK;
    }
    int32_t ret = ModifyId(g_localNetLedger.localInfo.deviceInfo.deviceName, DEVICE_NAME_BUF_LEN, info->deviceName);
    if (ret != SOFTBUS_OK) {
        SoftBusMutexUnlock(&g_localNetLedger.lock);
        return ret;
    }
    ret = ModifyId(g_localNetLedger.localInfo.deviceInfo.unifiedName, DEVICE_NAME_BUF_LEN, info->unifiedName);
    if (ret != SOFTBUS_OK) {
        SoftBusMutexUnlock(&g_localNetLedger.lock);
        return ret;
    }
    ret = ModifyId(g_localNetLedger.localInfo.deviceInfo.nickName, DEVICE_NAME_BUF_LEN, info->nickName);
    if (ret != SOFTBUS_OK) {
        SoftBusMutexUnlock(&g_localNetLedger.lock);
        return ret;
    }
    ret = ModifyId(g_localNetLedger.localInfo.deviceInfo.unifiedDefaultName, DEVICE_NAME_BUF_LEN,
        info->unifiedDefaultName);
    if (ret != SOFTBUS_OK) {
        SoftBusMutexUnlock(&g_localNetLedger.lock);
        return ret;
    }
    SoftBusMutexUnlock(&g_localNetLedger.lock);
    return SOFTBUS_OK;
}

void LnnUpdateStateVersion(StateVersionChangeReason reason)
{
    UpdateStateVersionAndStore(reason);
    if (!IsLocalLedgerReady()) {
        return;
    }
    NodeInfo nodeInfo = {};
    if (memcpy_s(&nodeInfo, sizeof(NodeInfo), &g_localNetLedger.localInfo, sizeof(NodeInfo)) != EOK) {
        LNN_LOGE(LNN_LEDGER, "memcpy fail");
        return;
    }
    if (LnnAsyncCallLedgerAllDataSyncToDB(&nodeInfo) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "ledger stateversion change sync to cloud failed");
    }
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

static int32_t LlGetDeviceSecurityLevel(void *buf, uint32_t len)
{
    if (buf == NULL || len != sizeof(int32_t)) {
        LNN_LOGE(LNN_LEDGER, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    *((int32_t *)buf) = g_localNetLedger.localInfo.deviceSecurityLevel;
    return SOFTBUS_OK;
}

static int32_t LlUpdateDeviceSecurityLevel(const void *buf)
{
    NodeInfo *info = &g_localNetLedger.localInfo;
    if (buf == NULL) {
        LNN_LOGE(LNN_LEDGER, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    info->deviceSecurityLevel = *((int32_t *)buf);
    return SOFTBUS_OK;
}

static int32_t LlUpdateStaticCapability(const void *staticCap)
{
    if (staticCap == NULL) {
        LNN_LOGE(LNN_LEDGER, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    NodeInfo *info = &g_localNetLedger.localInfo;
    return LnnSetStaticCapability(info, (uint8_t *)staticCap, info->staticCapLen);
}

static int32_t LlGetStaticCapability(void *buf, uint32_t len)
{
    if (buf == NULL || len > STATIC_CAP_LEN) {
        LNN_LOGE(LNN_LEDGER, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    NodeInfo *info = &g_localNetLedger.localInfo;
    int32_t ret = LnnGetStaticCapability(info, (uint8_t *)buf, len);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "get static cap fail");
        return ret;
    }
    return SOFTBUS_OK;
}

static int32_t LlUpdateUserIdCheckSum(const void *data)
{
    if (data == NULL) {
        LNN_LOGE(LNN_LEDGER, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    NodeInfo *info = &g_localNetLedger.localInfo;
    return LnnSetUserIdCheckSum(info, (uint8_t *)data, USERID_CHECKSUM_LEN);
}

static int32_t LlGetUserIdCheckSum(void *buf, uint32_t len)
{
    if (buf == NULL || len > USERID_CHECKSUM_LEN) {
        LNN_LOGE(LNN_LEDGER, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    NodeInfo *info = &g_localNetLedger.localInfo;
    int32_t ret = LnnGetUserIdCheckSum(info, (uint8_t *)buf, len);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "get useridchecksum fail");
        return ret;
    }
    return SOFTBUS_OK;
}

static int32_t LlGetUdidHash(void *buf, uint32_t len)
{
    if (buf == NULL || len < UDID_HASH_LEN) {
        LNN_LOGE(LNN_LEDGER, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    NodeInfo *info = &g_localNetLedger.localInfo;
    uint8_t hash[UDID_HASH_LEN] = {0};
    if (SoftBusGenerateStrHash((unsigned char *)info->deviceInfo.deviceUdid,
        strlen(info->deviceInfo.deviceUdid), (unsigned char *)hash) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "restore manager fail because generate strhash");
        return SOFTBUS_NETWORK_GENERATE_STR_HASH_ERR;
    }
    if (memcpy_s(buf, len, hash, UDID_HASH_LEN) != EOK) {
        LNN_LOGE(LNN_LEDGER, "memcpy cipher iv fail");
        return SOFTBUS_MEM_ERR;
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
        LNN_LOGE(LNN_LEDGER, "id is null");
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
        LNN_LOGE(LNN_LEDGER, "id is null");
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
        LNN_LOGE(LNN_LEDGER, "id is null");
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
        LNN_LOGE(LNN_LEDGER, "id is null");
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

static int32_t UpdateLocalUserId(const void *userId)
{
    if (userId == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    g_localNetLedger.localInfo.userId = *(int32_t *)userId;
    return SOFTBUS_OK;
}

static int32_t L1GetUserId(void *userId, uint32_t len)
{
    if (userId == NULL || len != sizeof(int32_t)) {
        return SOFTBUS_INVALID_PARAM;
    }
    *((int32_t *)userId) = g_localNetLedger.localInfo.userId;
    return SOFTBUS_OK;
}

static LocalLedgerKey g_localKeyTable[] = {
    {STRING_KEY_HICE_VERSION, VERSION_MAX_LEN, LlGetNodeSoftBusVersion, NULL},
    {STRING_KEY_DEV_UDID, UDID_BUF_LEN, LlGetDeviceUdid, UpdateLocalDeviceUdid},
    {STRING_KEY_NETWORKID, NETWORK_ID_BUF_LEN, LlGetNetworkId, UpdateLocalNetworkId},
    {STRING_KEY_OS_VERSION, OS_VERSION_BUF_LEN, LlGetOsVersion, NULL},
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
    {NUM_KEY_OS_TYPE, -1, LlGetOsType, NULL},
    {NUM_KEY_AUTH_CAP, -1, LlGetAuthCapability, NULL},
    {NUM_KEY_HB_CAP, -1, LlGetHbCapability, NULL},
    {NUM_KEY_MASTER_NODE_WEIGHT, -1, L1GetMasterNodeWeight, UpdateMasgerNodeWeight},
    {NUM_KEY_P2P_ROLE, -1, L1GetP2pRole, UpdateP2pRole},
    {NUM_KEY_STATE_VERSION, -1, LlGetStateVersion, UpdateStateVersion},
    {NUM_KEY_STA_FREQUENCY, -1, L1GetStaFrequency, UpdateStaFrequency},
    {NUM_KEY_TRANS_PROTOCOLS, sizeof(int64_t), LlGetSupportedProtocols, LlUpdateSupportedProtocols},
    {NUM_KEY_DATA_CHANGE_FLAG, sizeof(int16_t), L1GetNodeDataChangeFlag, UpdateNodeDataChangeFlag},
    {NUM_KEY_DATA_DYNAMIC_LEVEL, sizeof(uint16_t), L1GetDataDynamicLevel, UpdateDataDynamicLevel},
    {NUM_KEY_DATA_STATIC_LEVEL, sizeof(uint16_t), L1GetDataStaticLevel, UpdateDataStaticLevel},
    {NUM_KEY_DATA_SWITCH_LEVEL, sizeof(uint32_t), L1GetDataSwitchLevel, UpdateDataSwitchLevel},
    {NUM_KEY_DATA_SWITCH_LENGTH, sizeof(uint16_t), L1GetDataSwitchLength, UpdateDataSwitchLength},
    {NUM_KEY_ACCOUNT_LONG, sizeof(int64_t), LocalGetNodeAccountId, LocalUpdateNodeAccountId},
    {NUM_KEY_BLE_START_TIME, sizeof(int64_t), LocalGetNodeBleStartTime, LocalUpdateBleStartTime},
    {NUM_KEY_CONN_SUB_FEATURE_CAPA, -1, L1GetConnSubFeatureCapa, UpdateLocalConnSubFeatureCapability},
    {NUM_KEY_USERID, sizeof(int32_t), L1GetUserId, UpdateLocalUserId},
    {BYTE_KEY_IRK, LFINDER_IRK_LEN, LlGetIrk, UpdateLocalIrk},
    {BYTE_KEY_PUB_MAC, LFINDER_MAC_ADDR_LEN, LlGetPubMac, UpdateLocalPubMac},
    {BYTE_KEY_BROADCAST_CIPHER_KEY, SESSION_KEY_LENGTH, LlGetCipherInfoKey, UpdateLocalCipherInfoKey},
    {BYTE_KEY_BROADCAST_CIPHER_IV, BROADCAST_IV_LEN, LlGetCipherInfoIv, UpdateLocalCipherInfoIv},
    {NUM_KEY_STATIC_CAP_LEN, sizeof(int32_t), LlGetStaticCapLen, LlUpdateStaticCapLen},
    {NUM_KEY_DEVICE_SECURITY_LEVEL, sizeof(int32_t), LlGetDeviceSecurityLevel, LlUpdateDeviceSecurityLevel},
    {NUM_KEY_NETWORK_ID_TIMESTAMP, sizeof(int64_t), LocalGetNetworkIdTimeStamp, LocalUpdateNetworkIdTimeStamp},
    {BYTE_KEY_ACCOUNT_HASH, SHA_256_HASH_LEN, LlGetAccount, LlUpdateAccount},
    {BYTE_KEY_STATIC_CAPABILITY, STATIC_CAP_LEN, LlGetStaticCapability, LlUpdateStaticCapability},
    {BYTE_KEY_USERID_CHECKSUM, USERID_CHECKSUM_LEN, LlGetUserIdCheckSum, LlUpdateUserIdCheckSum},
    {BYTE_KEY_UDID_HASH, SHA_256_HASH_LEN, LlGetUdidHash, NULL},
    {BOOL_KEY_SCREEN_STATUS, NODE_SCREEN_STATUS_LEN, L1GetNodeScreenOnFlag, NULL},
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
    return SOFTBUS_NETWORK_NOT_FOUND;
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
    return SOFTBUS_NETWORK_NOT_FOUND;
}

int32_t LnnGetLocalBoolInfo(InfoKey key, bool *info, uint32_t len)
{
    uint32_t i;
    int32_t ret;
    if (key >= BOOL_KEY_END) {
        LNN_LOGE(LNN_LEDGER, "KEY error");
        return SOFTBUS_INVALID_PARAM;
    }
    if (info == NULL) {
        LNN_LOGE(LNN_LEDGER, "info is NULL");
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
    return SOFTBUS_NETWORK_NOT_FOUND;
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
        return SOFTBUS_STRCPY_ERR;
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
    return SOFTBUS_NETWORK_NOT_FOUND;
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
            return SOFTBUS_NETWORK_SET_LEDGER_INFO_ERR;
        }
    }
    SoftBusMutexUnlock(&g_localNetLedger.lock);
    LNN_LOGE(LNN_LEDGER, "key not exist");
    return SOFTBUS_NETWORK_NOT_FOUND;
}

static int32_t LnnFirstGetUdid(void)
{
    NodeInfo *nodeInfo = &g_localNetLedger.localInfo;
    DeviceBasicInfo *deviceInfo = &nodeInfo->deviceInfo;
    if (GetCommonDevInfo(COMM_DEVICE_KEY_UDID, deviceInfo->deviceUdid, UDID_BUF_LEN) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "COMM_DEVICE_KEY_UDID failed");
        return SOFTBUS_NETWORK_GET_DEVICE_INFO_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t LnnLoadBroadcastCipherInfo(BroadcastCipherKey *broadcastKey)
{
    if (broadcastKey == NULL) {
        LNN_LOGE(LNN_LEDGER, "broadcastKey is null.");
        return SOFTBUS_INVALID_PARAM;
    }
    if (LnnGetLocalBroadcastCipherKey(broadcastKey) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "get local info failed.");
        return SOFTBUS_NETWORK_NODE_KEY_INFO_ERR;
    }
    if (LnnSetLocalByteInfo(BYTE_KEY_BROADCAST_CIPHER_KEY,
        broadcastKey->cipherInfo.key, SESSION_KEY_LENGTH) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "set key error.");
        return SOFTBUS_NETWORK_SET_DEVICE_INFO_ERR;
    }
    if (LnnSetLocalByteInfo(BYTE_KEY_BROADCAST_CIPHER_IV,
        broadcastKey->cipherInfo.iv, BROADCAST_IV_LEN) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "set iv error.");
        return SOFTBUS_NETWORK_SET_DEVICE_INFO_ERR;
    }
    LNN_LOGI(LNN_LEDGER, "load BroadcastCipherInfo success!");
    return SOFTBUS_OK;
}

static int32_t LnnGenBroadcastCipherInfo(void)
{
    BroadcastCipherKey broadcastKey;
    int32_t ret = SOFTBUS_NETWORK_GENERATE_CIPHER_INFO_FAILED;
    (void)memset_s(&broadcastKey, sizeof(BroadcastCipherKey), 0, sizeof(BroadcastCipherKey));
    do {
        if (LnnLoadLocalBroadcastCipherKey() == SOFTBUS_OK) {
            ret = LnnLoadBroadcastCipherInfo(&broadcastKey);
            break;
        }
        if (SoftBusGenerateRandomArray(broadcastKey.cipherInfo.key, SESSION_KEY_LENGTH) != SOFTBUS_OK) {
            LNN_LOGE(LNN_LEDGER, "generate broadcast key error.");
            break;
        }
        if (SoftBusGenerateRandomArray(broadcastKey.cipherInfo.iv, BROADCAST_IV_LEN) != SOFTBUS_OK) {
            LNN_LOGE(LNN_LEDGER, "generate broadcast iv error.");
            break;
        }
        if (LnnSetLocalByteInfo(BYTE_KEY_BROADCAST_CIPHER_KEY,
            broadcastKey.cipherInfo.key, SESSION_KEY_LENGTH) != SOFTBUS_OK) {
            LNN_LOGE(LNN_LEDGER, "set key error.");
            break;
        }
        if (LnnSetLocalByteInfo(BYTE_KEY_BROADCAST_CIPHER_IV,
            broadcastKey.cipherInfo.iv, BROADCAST_IV_LEN) != SOFTBUS_OK) {
            LNN_LOGE(LNN_LEDGER, "set iv error.");
            break;
        }
        if (LnnUpdateLocalBroadcastCipherKey(&broadcastKey) != SOFTBUS_OK) {
            LNN_LOGE(LNN_LEDGER, "update local broadcast key failed");
            break;
        }
        LNN_LOGI(LNN_LEDGER, "generate BroadcastCipherInfo success!");
        ret = SOFTBUS_OK;
    } while (0);
    (void)memset_s(&broadcastKey, sizeof(BroadcastCipherKey), 0, sizeof(BroadcastCipherKey));
    return ret;
}

int32_t LnnGetLocalNumInfo(InfoKey key, int32_t *info)
{
    return LnnGetLocalInfo(key, (void*)info, sizeof(int32_t));
}

int32_t LnnSetLocalNumInfo(InfoKey key, int32_t info)
{
    return LnnSetLocalInfo(key, (void*)&info);
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

int32_t LnnGetLocalNumU16Info(InfoKey key, uint16_t *info)
{
    return LnnGetLocalInfo(key, (void*)info, sizeof(uint16_t));
}

int32_t LnnSetLocalNumU16Info(InfoKey key, uint16_t info)
{
    return LnnSetLocalInfo(key, (void*)&info);
}

int32_t LnnGetLocalNumU32Info(InfoKey key, uint32_t *info)
{
    return LnnGetLocalInfo(key, (void*)info, sizeof(uint32_t));
}

int32_t LnnSetLocalNumU32Info(InfoKey key, uint32_t info)
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
        return SOFTBUS_NETWORK_GET_LOCAL_NODE_INFO_ERR;
    }
    rc = LnnGetLocalStrInfo(STRING_KEY_NETWORKID, info->networkId, NETWORK_ID_BUF_LEN);
    if (rc != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "get local network id info failed");
        return SOFTBUS_NETWORK_GET_LOCAL_NODE_INFO_ERR;
    }
    rc = LnnGetLocalStrInfo(STRING_KEY_DEV_TYPE, type, DEVICE_TYPE_BUF_LEN);
    if (rc != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "get local device type failed");
        return SOFTBUS_NETWORK_GET_LOCAL_NODE_INFO_ERR;
    }
    rc = LnnGetLocalStrInfo(STRING_KEY_OS_VERSION, info->osVersion, OS_VERSION_BUF_LEN);
    if (rc != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "get local os version failed");
        return SOFTBUS_NETWORK_GET_LOCAL_NODE_INFO_ERR;
    }
    rc = LnnGetLocalNumInfo(NUM_KEY_OS_TYPE, &info->osType);
    if (rc != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "get local os type failed");
        return SOFTBUS_NETWORK_GET_LOCAL_NODE_INFO_ERR;
    }
    return LnnConvertDeviceTypeToId(type, &info->deviceTypeId);
}

int32_t SoftBusDumpBusCenterLocalDeviceInfo(int fd)
{
    SOFTBUS_DPRINTF(fd, "-----LocalDeviceInfo-----\n");
    NodeBasicInfo localNodeInfo;
    if (LnnGetLocalDeviceInfo(&localNodeInfo) != 0) {
        LNN_LOGE(LNN_LEDGER, "LnnGetLocalDeviceInfo failed");
        return SOFTBUS_NETWORK_GET_LOCAL_NODE_INFO_ERR;
    }
    SoftBusDumpBusCenterPrintInfo(fd, &localNodeInfo);
    return SOFTBUS_OK;
}

static void InitUserIdCheckSum(NodeInfo *nodeInfo)
{
    uint8_t userIdCheckSum[USERID_CHECKSUM_LEN] = {0};
    int32_t userId = GetActiveOsAccountIds();
    LNN_LOGI(LNN_LEDGER, "get userId:%{public}d", userId);
    nodeInfo->userId = userId;
    int32_t ret = HbBuildUserIdCheckSum(&userId, 1, userIdCheckSum, USERID_CHECKSUM_LEN);
    if (ret != SOFTBUS_OK) {
        LNN_LOGW(LNN_LEDGER, "get userIdCheckSum failed, ret=%{public}d", ret);
    }
    ret = memcpy_s(nodeInfo->userIdCheckSum, USERID_CHECKSUM_LEN, userIdCheckSum, USERID_CHECKSUM_LEN);
    if (ret != EOK) {
        LNN_LOGW(LNN_LEDGER, "memcpy_s fail, ret=%{public}d", ret);
    }
}

static void UpdateLocalAuthCapacity(NodeInfo *info)
{
    if (info->deviceInfo.deviceTypeId == TYPE_WATCH_ID) {
        info->authCapacity &= (~(1 << (uint32_t)BIT_SUPPORT_BR_DUP_BLE));
    }
}

static int32_t LnnInitLocalNodeInfo(NodeInfo *nodeInfo)
{
    int32_t ret = InitOfflineCode(nodeInfo);
    if (ret != SOFTBUS_OK) {
        return ret;
    }
    if (strcpy_s(nodeInfo->nodeAddress, sizeof(nodeInfo->nodeAddress), NODE_ADDR_LOOPBACK) != EOK) {
        LNN_LOGE(LNN_LEDGER, "fail:strncpy_s fail");
        return SOFTBUS_STRCPY_ERR;
    }
    ret = InitLocalDeviceInfo(&nodeInfo->deviceInfo);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "init local device info error");
        return ret;
    }
    UpdateLocalAuthCapacity(nodeInfo);
    ret = InitLocalVersionType(nodeInfo);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "init local version type error");
        return ret;
    }
    ret = GetDeviceSecurityLevel(&nodeInfo->deviceSecurityLevel);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "init local deviceSecurityLevel fail, deviceSecurityLevel=%{public}d",
            nodeInfo->deviceSecurityLevel);
    }
    ret = InitConnectInfo(&nodeInfo->connectInfo);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "init local connect info error");
        return ret;
    }
    ret = LnnInitLocalP2pInfo(nodeInfo);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "init local p2p info error");
        return ret;
    }
    InitUserIdCheckSum(nodeInfo);
    return SOFTBUS_OK;
}

static void GenerateStateVersion(void)
{
    uint8_t randNum = 0;
    if (SoftBusGenerateRandomArray((unsigned char *)&randNum, sizeof(uint8_t)) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "generate random num err.");
    }
    randNum = randNum % (MAX_STATE_VERSION + 1);
    g_localNetLedger.localInfo.stateVersion = randNum;
    g_localNetLedger.localInfo.isSupportSv = true;
    LNN_LOGI(LNN_LEDGER, "init local stateVersion=%{public}d", g_localNetLedger.localInfo.stateVersion);
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
    nodeInfo->heartbeatCapacity = DEFAULT_SUPPORT_HBCAPACITY;
    nodeInfo->netCapacity = LnnGetNetCapabilty();
    nodeInfo->authCapacity = GetAuthCapacity();
    nodeInfo->feature = LnnGetFeatureCapabilty();
    nodeInfo->connSubFeature = DEFAULT_CONN_SUB_FEATURE;
    if (LnnInitLocalNodeInfo(nodeInfo) != SOFTBUS_OK) {
        g_localNetLedger.status = LL_INIT_FAIL;
        return SOFTBUS_NETWORK_LEDGER_INIT_FAILED;
    }
    if (SoftBusMutexInit(&g_localNetLedger.lock, NULL) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "mutex init fail");
        g_localNetLedger.status = LL_INIT_FAIL;
        return SOFTBUS_LOCK_ERR;
    }
    int32_t ret = SoftBusRegBusCenterVarDump(
        (char *)SOFTBUS_BUSCENTER_DUMP_LOCALDEVICEINFO, &SoftBusDumpBusCenterLocalDeviceInfo);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "SoftBusRegBusCenterVarDump regist fail");
        return ret;
    }
    if (LnnFirstGetUdid() != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "first get udid fail, try again in one second");
    }
    if (LnnGenBroadcastCipherInfo() != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "generate cipher fail");
    }
    GenerateStateVersion();
    g_localNetLedger.status = LL_INIT_SUCCESS;
    return SOFTBUS_OK;
}

int32_t LnnInitLocalLedgerDelay(void)
{
    NodeInfo *nodeInfo = &g_localNetLedger.localInfo;
    DeviceBasicInfo *deviceInfo = &nodeInfo->deviceInfo;
    if (GetCommonDevInfo(COMM_DEVICE_KEY_UDID, deviceInfo->deviceUdid, UDID_BUF_LEN) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "GetCommonDevInfo: COMM_DEVICE_KEY_UDID failed");
        return SOFTBUS_NETWORK_GET_DEVICE_INFO_ERR;
    }
    int32_t ret = LnnInitOhosAccount();
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "init default ohos account failed");
        return ret;
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

int32_t LnnUpdateLocalScreenStatus(bool isScreenOn)
{
    if (SoftBusMutexLock(&g_localNetLedger.lock) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "lock mutex failed");
        return SOFTBUS_LOCK_ERR;
    }
    LnnSetScreenStatus(&g_localNetLedger.localInfo, isScreenOn);
    SoftBusMutexUnlock(&g_localNetLedger.lock);
    return SOFTBUS_OK;
}
