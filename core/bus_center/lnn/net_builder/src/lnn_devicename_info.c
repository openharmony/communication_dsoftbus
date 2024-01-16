/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "lnn_devicename_info.h"

#include <securec.h>
#include <string.h>

#include "anonymizer.h"
#include "bus_center_event.h"
#include "bus_center_manager.h"
#include "disc_interface.h"
#include "lnn_async_callback_utils.h"
#include "lnn_distributed_net_ledger.h"
#include "lnn_feature_capability.h"
#include "lnn_local_net_ledger.h"
#include "lnn_log.h"
#include "lnn_net_capability.h"
#include "lnn_network_info.h"
#include "lnn_sync_info_manager.h"
#include "lnn_sync_item_info.h"
#include "lnn_settingdata_event_monitor.h"
#include "lnn_deviceinfo_to_profile.h"
#include "lnn_ohos_account_adapter.h"
#include "softbus_adapter_mem.h"
#include "softbus_def.h"
#include "softbus_errcode.h"
#include "softbus_wifi_api_adapter.h"
#include "softbus_adapter_json.h"
#include "message_handler.h"

#define DELAY_LEN 1000
#define MAX_TRY 10
#define KEY_NICK_NAME "KEY_NICK_NAME"
#define KEY_ACCOUNT "KEY_ACCOUNT"

static int32_t g_tryGetDevnameNums = 0;

static int32_t LnnSyncDeviceName(const char *networkId)
{
    const char *deviceName = NULL;
    const NodeInfo *info = LnnGetLocalNodeInfo();
    if (info == NULL) {
        LNN_LOGE(LNN_BUILDER, "get local node info fail");
        return SOFTBUS_ERR;
    }
    deviceName = LnnGetDeviceName(&info->deviceInfo);
    if (deviceName == NULL) {
        LNN_LOGE(LNN_BUILDER, "get device name fail");
        return SOFTBUS_ERR;
    }
    if (LnnSendSyncInfoMsg(LNN_INFO_TYPE_DEVICE_NAME, networkId, (const uint8_t *)deviceName,
        strlen(deviceName) + 1, NULL) != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "send sync device name fail");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t LnnSyncDeviceNickName(const char *networkId)
{
    const NodeInfo *info = LnnGetLocalNodeInfo();
    if (info == NULL) {
        LNN_LOGE(LNN_BUILDER, "get local nodeInfo fail");
        return SOFTBUS_ERR;
    }
    int64_t accountId = GetCurrentAccount();
    JsonObj *json = JSON_CreateObject();
    if (json == NULL) {
        return SOFTBUS_ERR;
    }
    if (!JSON_AddStringToObject(json, KEY_NICK_NAME, info->deviceInfo.nickName) ||
        !JSON_AddInt64ToObject(json, KEY_ACCOUNT, accountId)) {
        LNN_LOGE(LNN_BUILDER, "sync device name fail");
        JSON_Delete(json);
        return SOFTBUS_ERR;
    }
    char *msg = JSON_PrintUnformatted(json);
    JSON_Delete(json);
    if (msg == NULL) {
        return SOFTBUS_ERR;
    }
    if (LnnSendSyncInfoMsg(LNN_INFO_TYPE_NICK_NAME, networkId, (const uint8_t *)msg,
        strlen(msg) + 1, NULL) != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "send sync nickName fail");
        JSON_Free(msg);
        return SOFTBUS_ERR;
    }
    JSON_Free(msg);
    return SOFTBUS_OK;
}

static void OnReceiveDeviceName(LnnSyncInfoType type, const char *networkId, const uint8_t *msg, uint32_t len)
{
    char udid[UDID_BUF_LEN];
    NodeBasicInfo basic;
    if (type != LNN_INFO_TYPE_DEVICE_NAME || len == 0 || networkId == NULL || msg == NULL) {
        LNN_LOGE(LNN_BUILDER, "invalid param, SyncInfoType=%{public}d", type);
        return;
    }
    if (strnlen((char *)msg, len) == len) {
        LNN_LOGE(LNN_BUILDER, "invalid msg");
        return;
    }
    char *anonyNetworkId = NULL;
    Anonymize(networkId, &anonyNetworkId);
    LNN_LOGI(LNN_BUILDER, "recv device name changed. msg=%{public}s, networkId=%{public}s",
        (char *)msg, anonyNetworkId);
    AnonymizeFree(anonyNetworkId);
    if (LnnConvertDlId(networkId, CATEGORY_NETWORK_ID, CATEGORY_UDID, udid, UDID_BUF_LEN) != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "convert networkId to udid fail");
        return;
    }
    if (!LnnSetDLDeviceInfoName(udid, (char *)msg)) {
        LNN_LOGE(LNN_BUILDER, "set peer device name fail");
    }
    (void)memset_s(&basic, sizeof(NodeBasicInfo), 0, sizeof(NodeBasicInfo));
    if (LnnGetBasicInfoByUdid(udid, &basic) != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "GetBasicInfoByUdid fail!");
        return;
    }
    LnnNotifyBasicInfoChanged(&basic, TYPE_DEVICE_NAME);
    NodeInfo nodeInfo;
    (void)memset_s(&nodeInfo, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    if (LnnGetRemoteNodeInfoById(networkId, CATEGORY_NETWORK_ID, &nodeInfo) != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "get node info fail");
        return;
    }
    UpdateProfile(&nodeInfo);
}

static void NotifyDeviceDisplayNameChange(const char *networkId, const char *udid)
{
    NodeBasicInfo basic;
    (void)memset_s(&basic, sizeof(NodeBasicInfo), 0, sizeof(NodeBasicInfo));
    if (LnnGetBasicInfoByUdid(udid, &basic) != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "GetBasicInfoByUdid fail");
        return;
    }
    LnnNotifyBasicInfoChanged(&basic, TYPE_DEVICE_NAME);
    NodeInfo nodeInfo;
    (void)memset_s(&nodeInfo, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    if (LnnGetRemoteNodeInfoById(networkId, CATEGORY_NETWORK_ID, &nodeInfo) != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "get node info fail");
        return;
    }
    UpdateProfile(&nodeInfo);
}

static void NickNameMsgProc(const char *networkId, int64_t accountId, const char *nickName)
{
    const NodeInfo *localNodeInfo = LnnGetLocalNodeInfo();
    if (localNodeInfo == NULL) {
        LNN_LOGE(LNN_BUILDER, "local devinfo nullptr");
        return;
    }
    char displayName[DEVICE_NAME_BUF_LEN] = {0};
    NodeInfo peerNodeInfo;
    (void)memset_s(&peerNodeInfo, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    if (LnnGetRemoteNodeInfoById(networkId, CATEGORY_NETWORK_ID, &peerNodeInfo) != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "get remote nodeInfo fail");
        return;
    }
    if (strcmp(peerNodeInfo.deviceInfo.nickName, nickName) == 0) {
        LNN_LOGE(LNN_BUILDER, "nickName not change, ignore this msg");
        return;
    }
    if (!LnnSetDLDeviceNickName(networkId, nickName)) {
        return;
    }
    int32_t ret = SOFTBUS_OK;
    LNN_LOGE(LNN_BUILDER, "peer unifiedDefaultName=%{public}s", peerNodeInfo.deviceInfo.unifiedDefaultName);
    if (strlen(peerNodeInfo.deviceInfo.unifiedName) != 0 &&
        strcmp(peerNodeInfo.deviceInfo.unifiedName, peerNodeInfo.deviceInfo.unifiedDefaultName) != 0) {
        ret = strcpy_s(displayName, DEVICE_NAME_BUF_LEN, peerNodeInfo.deviceInfo.unifiedName);
    } else if (strlen(nickName) == 0 || localNodeInfo->accountId == accountId) {
        ret = strcpy_s(displayName, DEVICE_NAME_BUF_LEN, peerNodeInfo.deviceInfo.unifiedDefaultName);
    } else {
        LnnGetDeviceDisplayName(nickName, peerNodeInfo.deviceInfo.unifiedDefaultName,
            displayName, DEVICE_NAME_BUF_LEN);
    }
    if (ret != SOFTBUS_OK) {
        LNN_LOGW(LNN_BUILDER, "strcpy_s fail, use default name");
    }
    LNN_LOGE(LNN_BUILDER, "peer deviceName=%{public}s", displayName);
    if (strcmp(peerNodeInfo.deviceInfo.deviceName, displayName) == 0) {
        LNN_LOGI(LNN_BUILDER, "device name not change, ignore this msg");
        return;
    }
    (void)LnnSetDLDeviceInfoName(peerNodeInfo.deviceInfo.deviceUdid, displayName);
    NotifyDeviceDisplayNameChange(networkId, peerNodeInfo.deviceInfo.deviceUdid);
}

static void OnReceiveDeviceNickName(LnnSyncInfoType type, const char *networkId, const uint8_t *msg, uint32_t len)
{
    if (msg == NULL) {
        LNN_LOGE(LNN_BUILDER, "msg is nullptr");
        return;
    }
    if (type != LNN_INFO_TYPE_NICK_NAME) {
        return;
    }
    JsonObj *json = JSON_Parse((const char *)msg, len);
    if (json == NULL) {
        LNN_LOGE(LNN_BUILDER, "parse json fail");
        return;
    }
    int64_t accountId = 0;
    char nickName[DEVICE_NAME_BUF_LEN] = {0};
    if (!JSON_GetInt64FromOject(json, KEY_ACCOUNT, &accountId) ||
        !JSON_GetStringFromOject(json, KEY_NICK_NAME, nickName, DEVICE_NAME_BUF_LEN)) {
        LNN_LOGE(LNN_BUILDER, "nickName json parse fail");
        JSON_Delete(json);
        return;
    }
    JSON_Delete(json);
    NickNameMsgProc(networkId, accountId, nickName);
}

static void HandlerGetDeviceName(const char *deviceName)
{
    int32_t infoNum = 0;
    NodeBasicInfo *info = NULL;
    char name[DEVICE_NAME_BUF_LEN] = {0};
    if (LnnGetSettingDeviceName(name, DEVICE_NAME_BUF_LEN) != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "set device name fail");
        return;
    }
    LNN_LOGD(LNN_BUILDER, "name=%{public}s", name);
    if (LnnSetLocalStrInfo(STRING_KEY_DEV_NAME, name) != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "set device name fail");
    }
    char unifiedName[DEVICE_NAME_BUF_LEN] = {0};
    if (LnnGetUnifiedDeviceName(unifiedName, DEVICE_NAME_BUF_LEN) == SOFTBUS_OK) {
        if (LnnSetLocalUnifiedName(unifiedName) != SOFTBUS_OK) {
            LNN_LOGE(LNN_BUILDER, "set device unifiedName fail");
        }
    }
    DiscDeviceInfoChanged(TYPE_LOCAL_DEVICE_NAME);
    if (LnnGetAllOnlineNodeInfo(&info, &infoNum) != SOFTBUS_OK) {
        LNN_LOGI(LNN_BUILDER, "get online node fail");
        return;
    }
    for (int32_t i = 0; i < infoNum; i++) {
        if (LnnIsLSANode(&info[i])) {
            continue;
        }
        if (LnnSyncDeviceName(info[i].networkId) != SOFTBUS_OK) {
            LNN_LOGE(LNN_BUILDER, "LnnSyncDeviceName fail");
        }
    }
    SoftBusFree(info);
}

static bool IsDeviceNeedSyncNickName(const char *networkId)
{
    NodeInfo nodeInfo;
    (void)memset_s(&nodeInfo, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    if (LnnGetRemoteNodeInfoById(networkId, CATEGORY_NETWORK_ID, &nodeInfo) != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "get node info fail");
        return false;
    }
    return IsFeatureSupport(nodeInfo.feature, BIT_SUPPORT_UNIFORM_NAME_CAPABILITY);
}

static void NotifyNickNameChange(void)
{
    NodeBasicInfo *info = NULL;
    int32_t infoNum = 0;
    if (LnnGetAllOnlineNodeInfo(&info, &infoNum) != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "get online node fail");
        return;
    }
    for (int32_t i = 0; i < infoNum; i++) {
        if (!IsDeviceNeedSyncNickName(info[i].networkId)) {
            continue;
        }
        if (LnnSyncDeviceNickName(info[i].networkId) != SOFTBUS_OK) {
            LNN_LOGE(LNN_BUILDER, "LnnSyncDeviceNickName fail");
        }
    }
    SoftBusFree(info);
}

static void HandlerGetDeviceNickName(const char *displayName)
{
    (void)displayName;
    char nickName[DEVICE_NAME_BUF_LEN] = {0};
    NodeInfo *localNodeInfo = (NodeInfo *)LnnGetLocalNodeInfo();
    if (localNodeInfo == NULL) {
        LNN_LOGE(LNN_BUILDER, "local devinfo nullptr");
        return;
    }
    char unifiedName[DEVICE_NAME_BUF_LEN] = {0};
    if (LnnGetUnifiedDeviceName(unifiedName, DEVICE_NAME_BUF_LEN) != SOFTBUS_OK) {
        return;
    }
    if (strlen(localNodeInfo->deviceInfo.unifiedName) != 0) {
        if (LnnSetLocalUnifiedName(unifiedName) != SOFTBUS_OK) {
            LNN_LOGE(LNN_BUILDER, "set device unifiedName fail");
        }
    }
    char unifiedDefault[DEVICE_NAME_BUF_LEN] = {0};
    if (LnnGetUnifiedDefaultDeviceName(unifiedDefault, DEVICE_NAME_BUF_LEN) != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "get defaultDeviceName fail");
        return;
    }
    if (strlen(unifiedDefault) != 0) {
        if (LnnSetLocalStrInfo(STRING_KEY_DEV_UNIFIED_DEFAULT_NAME, unifiedDefault) != SOFTBUS_OK) {
            LNN_LOGE(LNN_BUILDER, "set device unifiedDefaultName fail");
        }
    }
    if (LnnGetSettingNickName(unifiedDefault, unifiedName,
        nickName, DEVICE_NAME_BUF_LEN) != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "get nickName fail");
        return;
    }
    if (strlen(nickName) == 0) {
        if (strcpy_s(localNodeInfo->deviceInfo.nickName, DEVICE_NAME_BUF_LEN, "") != EOK) {
            LNN_LOGE(LNN_BUILDER, "strcpy fail");
        }
    } else {
        if (LnnSetLocalStrInfo(STRING_KEY_DEV_NICK_NAME, nickName) != SOFTBUS_OK) {
            LNN_LOGE(LNN_BUILDER, "set device nickName fail");
        }
    }
    NotifyNickNameChange();
}

static void LnnHandlerGetDeviceName(DeviceNameType type, const char *name)
{
    if (type == DEVICE_NAME_TYPE_DEV_NAME) {
        HandlerGetDeviceName(name);
    } else if (type == DEVICE_NAME_TYPE_NICK_NAME) {
        HandlerGetDeviceNickName(name);
    } else {
        LNN_LOGW(LNN_BUILDER, "invalid type=%{public}d", type);
    }
}

static void UpdataLocalFromSetting(void *p)
{
    (void)p;
    char deviceName[DEVICE_NAME_BUF_LEN] = {0};
    char unifiedName[DEVICE_NAME_BUF_LEN] = {0};
    char unifiedDefaultName[DEVICE_NAME_BUF_LEN] = {0};
    char nickName[DEVICE_NAME_BUF_LEN] = {0};
    LNN_LOGD(LNN_BUILDER, "UpdateLocalFromSetting enter");
    if (LnnGetSettingDeviceName(deviceName, DEVICE_NAME_BUF_LEN) != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "UpdataLocalFromSetting fail");
        g_tryGetDevnameNums++;
        if (g_tryGetDevnameNums < MAX_TRY) {
            LNN_LOGI(LNN_BUILDER, "g_tryGetDevnameNums=%{public}d", g_tryGetDevnameNums);
            SoftBusLooper *looper = GetLooper(LOOP_TYPE_DEFAULT);
            if (looper == NULL) {
                return;
            }
            int ret = LnnAsyncCallbackDelayHelper(looper, UpdataLocalFromSetting, NULL, DELAY_LEN);
            if (ret != SOFTBUS_OK) {
                LNN_LOGE(LNN_BUILDER, "init UpdataLocalFromSetting fail");
            }
        }
        return;
    }
    if (LnnSetLocalStrInfo(STRING_KEY_DEV_NAME, deviceName) != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "UpdataLocalFromSetting set device name fail");
    }
    if (LnnGetUnifiedDeviceName(unifiedName, DEVICE_NAME_BUF_LEN) == SOFTBUS_OK && strlen(unifiedName) != 0) {
        if (LnnSetLocalStrInfo(STRING_KEY_DEV_UNIFIED_NAME, unifiedName) != SOFTBUS_OK) {
            LNN_LOGE(LNN_BUILDER, "UpdateLocalFromSetting set unified name fail");
        }
    }
    if (LnnGetUnifiedDefaultDeviceName(unifiedDefaultName, DEVICE_NAME_BUF_LEN) == SOFTBUS_OK &&
        strlen(unifiedDefaultName) != 0) {
        if (LnnSetLocalStrInfo(STRING_KEY_DEV_UNIFIED_DEFAULT_NAME, unifiedDefaultName) != SOFTBUS_OK) {
            LNN_LOGE(LNN_BUILDER, "UpdateLocalFromSetting set default unified name fail");
        }
    }
    if (LnnGetSettingNickName(deviceName, unifiedName, nickName, DEVICE_NAME_BUF_LEN) == SOFTBUS_OK &&
        strlen(nickName) != 0) {
        if (LnnSetLocalStrInfo(STRING_KEY_DEV_NICK_NAME, nickName) != SOFTBUS_OK) {
            LNN_LOGE(LNN_BUILDER, "UpdateLocalFromSetting set nick name fail");
        }
    }
    RegisterNameMonitor();
    DiscDeviceInfoChanged(TYPE_LOCAL_DEVICE_NAME);
    LNN_LOGI(LNN_BUILDER, "UpdateLocalFromSetting done, deviceName=%{public}s, unifiedName=%{public}s, "
        "unifiedDefaultName=%{public}s, nickName=%{public}s", deviceName, unifiedName, unifiedDefaultName, nickName);
}

static void UpdateDeviceNameFromSetting(void)
{
    LnnInitGetDeviceName(LnnHandlerGetDeviceName);
}

void UpdateDeviceName(void *p)
{
    UpdateDeviceNameFromSetting();
    UpdataLocalFromSetting(p);
}

static void LnnAccountStateChangeHandler(const LnnEventBasicInfo *info)
{
    if (info == NULL || info->event != LNN_EVENT_ACCOUNT_CHANGED) {
        LNN_LOGE(LNN_BUILDER, "invalid param");
        return;
    }
    const LnnMonitorHbStateChangedEvent *event = (const LnnMonitorHbStateChangedEvent *)info;
    SoftBusAccountState accountState = (SoftBusAccountState)event->status;
    LNN_LOGD(LNN_BUILDER, "account state=%{public}d", accountState);
    HandlerGetDeviceNickName(NULL);
    return;
}

int32_t LnnInitDevicename(void)
{
    int32_t ret = LnnRegSyncInfoHandler(LNN_INFO_TYPE_DEVICE_NAME, OnReceiveDeviceName);
    if (ret != SOFTBUS_OK) {
        return ret;
    }
    if (LnnRegisterEventHandler(LNN_EVENT_ACCOUNT_CHANGED, LnnAccountStateChangeHandler) != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "regist account change evt handler fail");
        return SOFTBUS_ERR;
    }
    return LnnRegSyncInfoHandler(LNN_INFO_TYPE_NICK_NAME, OnReceiveDeviceNickName);
}

void LnnDeinitDevicename(void)
{
    (void)LnnUnregSyncInfoHandler(LNN_INFO_TYPE_DEVICE_NAME, OnReceiveDeviceName);
    LnnUnregisterEventHandler(LNN_EVENT_ACCOUNT_CHANGED, LnnAccountStateChangeHandler);
    (void)LnnUnregSyncInfoHandler(LNN_INFO_TYPE_NICK_NAME, OnReceiveDeviceNickName);
}
