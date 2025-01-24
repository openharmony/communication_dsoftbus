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
#include "lnn_async_callback_utils.h"
#include "lnn_deviceinfo_to_profile.h"
#include "lnn_distributed_net_ledger.h"
#include "lnn_event_monitor_impl.h"
#include "lnn_local_net_ledger.h"
#include "lnn_log.h"
#include "lnn_network_info.h"
#include "lnn_sync_info_manager.h"
#include "lnn_sync_item_info.h"
#include "lnn_settingdata_event_monitor.h"
#include "softbus_adapter_mem.h"
#include "softbus_def.h"
#include "softbus_error_code.h"
#include "softbus_adapter_json.h"
#include "message_handler.h"

#define KEY_NICK_NAME "KEY_NICK_NAME"
#define KEY_ACCOUNT "KEY_ACCOUNT"

static int32_t LnnSyncDeviceName(const char *networkId)
{
    const char *deviceName = NULL;
    const NodeInfo *info = LnnGetLocalNodeInfo();
    if (info == NULL) {
        LNN_LOGE(LNN_BUILDER, "get local node info fail");
        return SOFTBUS_NETWORK_GET_LOCAL_NODE_INFO_ERR;
    }
    deviceName = LnnGetDeviceName(&info->deviceInfo);
    if (deviceName == NULL) {
        LNN_LOGE(LNN_BUILDER, "get device name fail");
        return SOFTBUS_NETWORK_GET_DEVICE_INFO_ERR;
    }
    SendSyncInfoParam *data = CreateSyncInfoParam(
        LNN_INFO_TYPE_DEVICE_NAME, networkId, (const uint8_t *)deviceName, strlen(deviceName) + 1, NULL);
    if (data == NULL) {
        LNN_LOGE(LNN_BUILDER, "create async info fail");
        return SOFTBUS_NETWORK_SEND_SYNC_INFO_FAILED;
    }
    if (LnnAsyncCallbackHelper(GetLooper(LOOP_TYPE_DEFAULT), LnnSendAsyncInfoMsg, (void *)data) != SOFTBUS_OK) {
        SoftBusFree(data->msg);
        SoftBusFree(data);
        LNN_LOGE(LNN_BUILDER, "send async device name fail");
        return SOFTBUS_NETWORK_SEND_SYNC_INFO_FAILED;
    }
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
    char deviceName[DEVICE_NAME_BUF_LEN + 1] = {0};
    if (strcpy_s(deviceName, DEVICE_NAME_BUF_LEN + 1, (char *)msg) != EOK) {
        LNN_LOGE(LNN_BUILDER, "strcpy fail");
        return;
    }
    char *anonyNetworkId = NULL;
    Anonymize(networkId, &anonyNetworkId);
    char *anonyDeviceName = NULL;
    Anonymize(deviceName, &anonyDeviceName);
    LNN_LOGI(LNN_BUILDER, "recv device name changed. deviceName=%{public}s, networkId=%{public}s",
        AnonymizeWrapper(anonyDeviceName), AnonymizeWrapper(anonyNetworkId));
    AnonymizeFree(anonyNetworkId);
    AnonymizeFree(anonyDeviceName);
    if (LnnConvertDlId(networkId, CATEGORY_NETWORK_ID, CATEGORY_UDID, udid, UDID_BUF_LEN) != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "convert networkId to udid fail");
        return;
    }
    if (!LnnSetDLDeviceInfoName(udid, deviceName)) {
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

static void LnnSetDisplayName(char *displayName, const char *nickName, const NodeInfo *peerNodeInfo,
    const NodeInfo *localNodeInfo, int64_t accountId)
{
    int32_t ret = EOK;
    if (strlen(peerNodeInfo->deviceInfo.unifiedName) != 0 &&
        strcmp(peerNodeInfo->deviceInfo.unifiedName, peerNodeInfo->deviceInfo.unifiedDefaultName) != 0) {
        ret = strcpy_s(displayName, DEVICE_NAME_BUF_LEN, peerNodeInfo->deviceInfo.unifiedName);
    } else if (strlen(nickName) == 0 || localNodeInfo->accountId == accountId) {
        ret = strcpy_s(displayName, DEVICE_NAME_BUF_LEN, peerNodeInfo->deviceInfo.unifiedDefaultName);
    } else {
        LnnGetDeviceDisplayName(nickName, peerNodeInfo->deviceInfo.unifiedDefaultName,
            displayName, DEVICE_NAME_BUF_LEN);
    }
    if (ret != EOK) {
        LNN_LOGW(LNN_BUILDER, "strcpy_s fail, use default name");
    }
    char *anonyDeviceName = NULL;
    Anonymize(displayName, &anonyDeviceName);
    LNN_LOGI(LNN_BUILDER, "peer deviceName=%{public}s", AnonymizeWrapper(anonyDeviceName));
    AnonymizeFree(anonyDeviceName);
}

static void NickNameMsgProc(const char *networkId, int64_t accountId, const char *nickName)
{
    const NodeInfo *localNodeInfo = LnnGetLocalNodeInfo();
    LNN_CHECK_AND_RETURN_LOGE(localNodeInfo != NULL, LNN_BUILDER, "local devinfo nullptr");
    char *anonyNickName = NULL;
    Anonymize(nickName, &anonyNickName);
    LNN_LOGI(LNN_BUILDER, "nickName is=%{public}s", AnonymizeWrapper(anonyNickName));
    AnonymizeFree(anonyNickName);
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
        LNN_LOGE(LNN_BUILDER, "set remote device nick name fail");
        return;
    }
    char *anonyUnifiedDefaultName = NULL;
    Anonymize(peerNodeInfo.deviceInfo.unifiedDefaultName, &anonyUnifiedDefaultName);
    anonyNickName = NULL;
    Anonymize(peerNodeInfo.deviceInfo.nickName, &anonyNickName);
    char *anonyUnifiedName = NULL;
    Anonymize(peerNodeInfo.deviceInfo.unifiedName, &anonyUnifiedName);
    char *anonyDeviceName = NULL;
    Anonymize(peerNodeInfo.deviceInfo.deviceName, &anonyDeviceName);
    LNN_LOGI(LNN_BUILDER, "peer unifiedDefaultName=%{public}s, nickName=%{public}s, "
        "unifiedName=%{public}s, deviceName=%{public}s",
        AnonymizeWrapper(anonyUnifiedDefaultName), AnonymizeWrapper(anonyNickName),
        AnonymizeWrapper(anonyUnifiedName), AnonymizeWrapper(anonyDeviceName));
    AnonymizeFree(anonyUnifiedDefaultName);
    AnonymizeFree(anonyNickName);
    AnonymizeFree(anonyUnifiedName);
    AnonymizeFree(anonyDeviceName);
    LnnSetDisplayName(displayName, nickName, &peerNodeInfo, localNodeInfo, accountId);
    if (strcmp(peerNodeInfo.deviceInfo.deviceName, displayName) == 0 || strlen(displayName) == 0) {
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

int32_t LnnSetLocalDeviceName(const char *displayName)
{
    if (displayName == NULL || strnlen(displayName, DEVICE_NAME_BUF_LEN) == 0 ||
        strnlen(displayName, DEVICE_NAME_BUF_LEN) == DEVICE_NAME_BUF_LEN) {
        LNN_LOGE(LNN_BUILDER, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    char localDevName[DEVICE_NAME_BUF_LEN] = {0};
    if (LnnGetLocalStrInfo(STRING_KEY_DEV_NAME, localDevName, sizeof(localDevName)) != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "get local devcice name failed");
        return SOFTBUS_NETWORK_GET_NODE_INFO_ERR;
    }
    if (strcmp(localDevName, displayName) == 0) {
        LNN_LOGI(LNN_BUILDER, "device name not change, ignore this msg");
        return SOFTBUS_OK;
    }
    if (LnnSetLocalStrInfo(STRING_KEY_DEV_NAME, displayName) != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "set local devcice name failed");
        return SOFTBUS_NETWORK_SET_NODE_INFO_ERR;
    }
    LnnNotifyLocalNetworkIdChanged();
    LnnNotifyDeviceInfoChanged(SOFTBUS_LOCAL_DEVICE_INFO_NAME_CHANGED);
    int32_t infoNum = 0;
    NodeBasicInfo *info = NULL;
    if (LnnGetAllOnlineNodeInfo(&info, &infoNum) != SOFTBUS_OK) {
        LNN_LOGI(LNN_BUILDER, "get online node fail");
        return SOFTBUS_NETWORK_GET_ALL_NODE_INFO_ERR;
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
    return SOFTBUS_OK;
}

int32_t LnnInitDevicename(void)
{
    int32_t ret = LnnRegSyncInfoHandler(LNN_INFO_TYPE_DEVICE_NAME, OnReceiveDeviceName);
    if (ret != SOFTBUS_OK) {
        return ret;
    }
    return LnnRegSyncInfoHandler(LNN_INFO_TYPE_NICK_NAME, OnReceiveDeviceNickName);
}

void LnnDeinitDevicename(void)
{
    (void)LnnUnregSyncInfoHandler(LNN_INFO_TYPE_DEVICE_NAME, OnReceiveDeviceName);
    (void)LnnUnregSyncInfoHandler(LNN_INFO_TYPE_NICK_NAME, OnReceiveDeviceNickName);
}