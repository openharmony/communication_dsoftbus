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

#include "bus_center_event.h"
#include "bus_center_manager.h"
#include "disc_interface.h"
#include "lnn_async_callback_utils.h"
#include "lnn_distributed_net_ledger.h"
#include "lnn_feature_capability.h"
#include "lnn_local_net_ledger.h"
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
#include "softbus_log_old.h"
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
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "get local node info fail");
        return SOFTBUS_ERR;
    }
    deviceName = LnnGetDeviceName(&info->deviceInfo);
    if (deviceName == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "get device name fail");
        return SOFTBUS_ERR;
    }
    if (LnnSendSyncInfoMsg(LNN_INFO_TYPE_DEVICE_NAME, networkId, (const uint8_t *)deviceName,
        strlen(deviceName) + 1, NULL) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "send sync device name fail");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t LnnSyncDeviceNickName(const char *networkId)
{
    const NodeInfo *info = LnnGetLocalNodeInfo();
    if (info == NULL) {
        LLOGE("get local nodeInfo fail");
        return SOFTBUS_ERR;
    }
    int64_t accountId = GetCurrentAccount();
    JsonObj *json = JSON_CreateObject();
    if (json == NULL) {
        return SOFTBUS_ERR;
    }
    if (!JSON_AddStringToObject(json, KEY_NICK_NAME, info->deviceInfo.nickName) ||
        !JSON_AddInt64ToObject(json, KEY_ACCOUNT, accountId)) {
        LLOGE("sync device name fail");
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
        LLOGE("send sync nickName fail");
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
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "invalid param, SyncInfoType:%d", type);
        return;
    }
    if (strnlen((char *)msg, len) == len) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "OnReceiveDeviceName invalid msg");
        return;
    }
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "recv device name changed msg:%s, networkId:%s",
        (char *)msg, AnonymizesNetworkID(networkId));
    if (LnnConvertDlId(networkId, CATEGORY_NETWORK_ID, CATEGORY_UDID, udid, UDID_BUF_LEN) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "convert networkId to udid fail");
        return;
    }
    if (!LnnSetDLDeviceInfoName(udid, (char *)msg)) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "set peer device name fail");
    }
    (void)memset_s(&basic, sizeof(NodeBasicInfo), 0, sizeof(NodeBasicInfo));
    if (LnnGetBasicInfoByUdid(udid, &basic) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "GetBasicInfoByUdid fail!");
        return;
    }
    LnnNotifyBasicInfoChanged(&basic, TYPE_DEVICE_NAME);
    NodeInfo nodeInfo;
    (void)memset_s(&nodeInfo, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    if (LnnGetRemoteNodeInfoById(networkId, CATEGORY_NETWORK_ID, &nodeInfo) != SOFTBUS_OK) {
        LLOGE("get node info fail");
        return;
    }
    UpdateProfile(&nodeInfo);
}

static void NotifyDeviceDisplayNameChange(const char *networkId, const char *udid)
{
    NodeBasicInfo basic;
    (void)memset_s(&basic, sizeof(NodeBasicInfo), 0, sizeof(NodeBasicInfo));
    if (LnnGetBasicInfoByUdid(udid, &basic) != SOFTBUS_OK) {
        LLOGE("GetBasicInfoByUdid fail");
        return;
    }
    LnnNotifyBasicInfoChanged(&basic, TYPE_DEVICE_NAME);
    NodeInfo nodeInfo;
    (void)memset_s(&nodeInfo, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    if (LnnGetRemoteNodeInfoById(networkId, CATEGORY_NETWORK_ID, &nodeInfo) != SOFTBUS_OK) {
        LLOGE("get node info fail");
        return;
    }
    UpdateProfile(&nodeInfo);
}

static void NickNameMsgProc(const char *networkId, int64_t accountId, const char *nickName)
{
    const NodeInfo *localNodeInfo = LnnGetLocalNodeInfo();
    if (localNodeInfo == NULL) {
        LLOGE("local devinfo nullptr");
        return;
    }
    char displayName[DEVICE_NAME_BUF_LEN] = {0};
    NodeInfo peerNodeInfo;
    (void)memset_s(&peerNodeInfo, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    if (LnnGetRemoteNodeInfoById(networkId, CATEGORY_NETWORK_ID, &peerNodeInfo) != SOFTBUS_OK) {
        LLOGE("get remote nodeInfo fail");
        return;
    }
    if (strcmp(peerNodeInfo.deviceInfo.nickName, nickName) == 0) {
        LLOGE("nickName not change, ignore this msg");
        return;
    }
    if (!LnnSetDLDeviceNickName(networkId, nickName)) {
        return;
    }
    int32_t ret = SOFTBUS_OK;
    LLOGE("peer unifiedDefaultName:%s", peerNodeInfo.deviceInfo.unifiedDefaultName);
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
        LLOGW("strcpy_s fail, use default name");
    }
    LLOGE("peer deviceName:%s", displayName);
    if (strcmp(peerNodeInfo.deviceInfo.deviceName, displayName) == 0) {
        LLOGI("device name not change, ignore this msg");
        return;
    }
    (void)LnnSetDLDeviceInfoName(peerNodeInfo.deviceInfo.deviceUdid, displayName);
    NotifyDeviceDisplayNameChange(networkId, peerNodeInfo.deviceInfo.deviceUdid);
}

static void OnReceiveDeviceNickName(LnnSyncInfoType type, const char *networkId, const uint8_t *msg, uint32_t len)
{
    if (msg == NULL) {
        LLOGE("msg is nullptr");
        return;
    }
    if (type != LNN_INFO_TYPE_NICK_NAME) {
        return;
    }
    JsonObj *json = JSON_Parse((const char *)msg, len);
    if (json == NULL) {
        LLOGE("parse json fail");
        return;
    }
    int64_t accountId = 0;
    char nickName[DEVICE_NAME_BUF_LEN] = {0};
    if (!JSON_GetInt64FromOject(json, KEY_ACCOUNT, &accountId) ||
        !JSON_GetStringFromOject(json, KEY_NICK_NAME, nickName, DEVICE_NAME_BUF_LEN)) {
        LLOGE("nickName json parse fail");
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
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HandlerGetDeviceName fail");
        return;
    }
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_DBG, "HandlerGetDeviceName name is %s", name);
    if (LnnSetLocalStrInfo(STRING_KEY_DEV_NAME, name) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HandlerGetDeviceName set device name fail");
    }
    char unifiedName[DEVICE_NAME_BUF_LEN] = {0};
    if (LnnGetUnifiedDeviceName(unifiedName, DEVICE_NAME_BUF_LEN) == SOFTBUS_OK) {
        if (LnnSetLocalUnifiedName(unifiedName) != SOFTBUS_OK) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "set device unifiedName fail");
        }
    }
    DiscDeviceInfoChanged(TYPE_LOCAL_DEVICE_NAME);
    if (LnnGetAllOnlineNodeInfo(&info, &infoNum) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_INFO, "get online node fail");
        return;
    }
    for (int32_t i = 0; i < infoNum; i++) {
        if (LnnIsLSANode(&info[i])) {
            continue;
        }
        if (LnnSyncDeviceName(info[i].networkId) != SOFTBUS_OK) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "LnnSyncDeviceName fail");
        }
    }
    SoftBusFree(info);
}

static bool IsDeviceNeedSyncNickName(const char *networkId)
{
    NodeInfo nodeInfo;
    (void)memset_s(&nodeInfo, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    if (LnnGetRemoteNodeInfoById(networkId, CATEGORY_NETWORK_ID, &nodeInfo) != SOFTBUS_OK) {
        LLOGE("get node info fail");
        return false;
    }
    return IsFeatureSupport(nodeInfo.feature, BIT_SUPPORT_UNIFORM_NAME_CAPABILITY);
}

static void NotifyNickNameChange(void)
{
    NodeBasicInfo *info = NULL;
    int32_t infoNum = 0;
    if (LnnGetAllOnlineNodeInfo(&info, &infoNum) != SOFTBUS_OK) {
        LLOGE("get online node fail");
        return;
    }
    for (int32_t i = 0; i < infoNum; i++) {
        if (!IsDeviceNeedSyncNickName(info[i].networkId)) {
            continue;
        }
        if (LnnSyncDeviceNickName(info[i].networkId) != SOFTBUS_OK) {
            LLOGE("LnnSyncDeviceNickName fail");
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
        LLOGE("local devinfo nullptr");
        return;
    }
    char unifiedName[DEVICE_NAME_BUF_LEN] = {0};
    if (LnnGetUnifiedDeviceName(unifiedName, DEVICE_NAME_BUF_LEN) != SOFTBUS_OK) {
        return;
    }
    if (strlen(localNodeInfo->deviceInfo.unifiedName) != 0) {
        if (LnnSetLocalUnifiedName(unifiedName) != SOFTBUS_OK) {
            LLOGE("set device unifiedName fail");
        }
    }
    char unifiedDefault[DEVICE_NAME_BUF_LEN] = {0};
    if (LnnGetUnifiedDefaultDeviceName(unifiedDefault, DEVICE_NAME_BUF_LEN) != SOFTBUS_OK) {
        LLOGE("get defaultDeviceName fail");
        return;
    }
    if (strlen(unifiedDefault) != 0) {
        if (LnnSetLocalStrInfo(STRING_KEY_DEV_UNIFIED_DEFAULT_NAME, unifiedDefault) != SOFTBUS_OK) {
            LLOGE("set device unifiedDefaultName fail");
        }
    }
    if (LnnGetSettingNickName(unifiedDefault, unifiedName,
        nickName, DEVICE_NAME_BUF_LEN) != SOFTBUS_OK) {
        LLOGE("get nickName fail");
        return;
    }
    if (strlen(nickName) == 0) {
        if (strcpy_s(localNodeInfo->deviceInfo.nickName, DEVICE_NAME_BUF_LEN, "") != EOK) {
            LLOGE("strcpy fail");
        }
    } else {
        if (LnnSetLocalStrInfo(STRING_KEY_DEV_NICK_NAME, nickName) != SOFTBUS_OK) {
            LLOGE("set device nickName fail");
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
        LLOGW("invalid type:%d", type);
    }
}

static void UpdataLocalFromSetting(void *p)
{
    char name[DEVICE_NAME_BUF_LEN] = {0};
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "UpdataLocalFromSetting enter");
    if (LnnGetSettingDeviceName(name, DEVICE_NAME_BUF_LEN) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "UpdataLocalFromSetting fail");
        g_tryGetDevnameNums++;
        if (g_tryGetDevnameNums < MAX_TRY) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "g_tryGetDevnameNums: %d", g_tryGetDevnameNums);
            SoftBusLooper *looper = GetLooper(LOOP_TYPE_DEFAULT);
            if (looper == NULL) {
                return;
            }
            int ret = LnnAsyncCallbackDelayHelper(looper, UpdataLocalFromSetting, NULL, DELAY_LEN);
            if (ret != SOFTBUS_OK) {
                SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "init UpdataLocalFromSetting fail");
            }
        }
        return;
    }
    if (LnnSetLocalStrInfo(STRING_KEY_DEV_NAME, name) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "UpdataLocalFromSetting set device name fail");
    }
    RegisterNameMonitor();
    DiscDeviceInfoChanged(TYPE_LOCAL_DEVICE_NAME);
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
        LLOGE("invalid param");
        return;
    }
    const LnnMonitorHbStateChangedEvent *event = (const LnnMonitorHbStateChangedEvent *)info;
    SoftBusAccountState accountState = (SoftBusAccountState)event->status;
    LLOGD("account state:%d", accountState);
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
        LLOGE("regist account change evt handler fail");
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
