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

#include "bus_center_event.h"
#include "bus_center_manager.h"
#include "disc_interface.h"
#include "lnn_async_callback_utils.h"
#include "lnn_distributed_net_ledger.h"
#include "lnn_local_net_ledger.h"
#include "lnn_net_capability.h"
#include "lnn_network_info.h"
#include "lnn_sync_info_manager.h"
#include "lnn_sync_item_info.h"
#include "lnn_settingdata_event_monitor.h"
#include "softbus_adapter_mem.h"
#include "softbus_errcode.h"
#include "softbus_wifi_api_adapter.h"
#include "softbus_json_utils.h"
#include "message_handler.h"

#define DELAY_LEN 1000
#define MAX_TRY 10
static int32_t g_tryGetDevnameNums = 0;

int32_t LnnSyncDeviceName(const char *networkId)
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

static void OnReceiveDeviceName(LnnSyncInfoType type, const char *networkId, const uint8_t *msg, uint32_t len)
{
    char udid[UDID_BUF_LEN];
    NodeBasicInfo basic;
    if (type != LNN_INFO_TYPE_DEVICE_NAME) {
        return;
    }
    if (LnnConvertDlId(networkId, CATEGORY_NETWORK_ID, CATEGORY_UDID, udid, UDID_BUF_LEN) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "convert networkId to udid fail");
        return;
    }
    if (!LnnSetDLDeviceInfoName(udid, (char *)msg)) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "set peer device name fail");
    }
    (void)memset_s(&basic, sizeof(NodeBasicInfo), 0, sizeof(NodeBasicInfo));
    if (LnnGetBasicInfoByUdid(udid, &basic) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "GetBasicInfoByUdid fail!");
        return;
    }
    LnnNotifyBasicInfoChanged(&basic, TYPE_DEVICE_NAME);
}

static void HandlerGetDeviceName(void)
{
    int32_t infoNum = 0;
    NodeBasicInfo *info = NULL;
    char name[DEVICE_NAME_BUF_LEN] = {0};
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "HandlerGetDeviceName enter");
    if (LnnGetSettingDeviceName(name, DEVICE_NAME_BUF_LEN) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HandlerGetDeviceName fail");
        return;
    }

    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "HandlerGetDeviceName name is %s", name);
    if (LnnSetLocalStrInfo(STRING_KEY_DEV_NAME, name) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HandlerGetDeviceName set device name fail");
    }
    DiscDeviceInfoChanged(TYPE_LOCAL_DEVICE_NAME);
    if (LnnGetAllOnlineNodeInfo(&info, &infoNum) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_INFO, "get online node fail");
        return;
    }
    for (int32_t i = 0; i < infoNum; i++) {
        if (LnnSyncDeviceName(info[i].networkId) != SOFTBUS_OK) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "LnnSyncDeviceName fail");
        }
    }
    SoftBusFree(info);
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

void UpdateDeviceNameFromSetting(void)
{
    LnnInitGetDeviceName(HandlerGetDeviceName);
}

void UpdateDeviceName(void *p)
{
    UpdateDeviceNameFromSetting();
    UpdataLocalFromSetting(p);
}

int32_t LnnInitDevicename(void)
{
    return LnnRegSyncInfoHandler(LNN_INFO_TYPE_DEVICE_NAME, OnReceiveDeviceName);
}
