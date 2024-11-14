/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#define JSON_KEY_BATTERY_LEAVEL "BatteryLeavel"
#define JSON_KEY_IS_CHARGING "IsCharging"

#include <securec.h>
#include "lnn_battery_info.h"
#include "lnn_distributed_net_ledger.h"
#include "lnn_log.h"
#include "lnn_sync_info_manager.h"
#include "softbus_adapter_mem.h"
#include "softbus_json_utils.h"
#include "softbus_error_code.h"

int32_t LnnSyncBatteryInfo(const char *udid, int32_t level, bool isCharging)
{
    cJSON *json = cJSON_CreateObject();
    if (json == NULL) {
        LNN_LOGE(LNN_LANE, "create battery json object failed");
        return SOFTBUS_CREATE_JSON_ERR;
    }
    if (!AddNumberToJsonObject(json, JSON_KEY_BATTERY_LEAVEL, level) ||
        !AddBoolToJsonObject(json, JSON_KEY_IS_CHARGING, isCharging)) {
        LNN_LOGE(LNN_LANE, "add elect info to json failed");
        cJSON_Delete(json);
        return SOFTBUS_ADD_INFO_TO_JSON_FAIL;
    }
    char *data = cJSON_PrintUnformatted(json);
    cJSON_Delete(json);
    if (data == NULL) {
        LNN_LOGE(LNN_LANE, "format elect packet fail");
        return SOFTBUS_CREATE_JSON_ERR;
    }
    NodeInfo nodeInfo;
    (void)memset_s(&nodeInfo, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    int ret = LnnGetRemoteNodeInfoById(udid, CATEGORY_UDID, &nodeInfo);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "not target node");
        cJSON_free(data);
        return SOFTBUS_NETWORK_GET_NODE_INFO_ERR;
    }
    int32_t rc = LnnSendSyncInfoMsg(LNN_INFO_TYPE_BATTERY_INFO,
    nodeInfo.networkId, (uint8_t *)data, strlen(data) + 1, NULL);
    cJSON_free(data);
    return rc;
}

static void OnReceiveBatteryInfo(LnnSyncInfoType type, const char *networkId, const uint8_t *msg, uint32_t len)
{
    LNN_LOGD(LNN_LANE, "OnReceiveBatteryInfo");
    if (type != LNN_INFO_TYPE_BATTERY_INFO) {
        return;
    }
    cJSON *json = cJSON_ParseWithLength((char *)msg, (size_t)len);
    if (json == NULL) {
        LNN_LOGE(LNN_LANE, "parse elect msg json fail");
        return;
    }
    int32_t level = 0;
    bool isCharging = false;
    if (!GetJsonObjectNumberItem(json, JSON_KEY_BATTERY_LEAVEL, &level) ||
        !GetJsonObjectBoolItem(json, JSON_KEY_IS_CHARGING, &isCharging)) {
        LNN_LOGE(LNN_LANE, "parse master info json fail");
        cJSON_Delete(json);
        return;
    }
    cJSON_Delete(json);
    BatteryInfo battery;
    battery.batteryLevel = level;
    battery.isCharging = isCharging;
    (void)LnnSetDLBatteryInfo(networkId, &battery);
    LNN_LOGD(LNN_LANE, "update battery info");
}

int32_t  LnnInitBatteryInfo(void)
{
    return LnnRegSyncInfoHandler(LNN_INFO_TYPE_BATTERY_INFO, OnReceiveBatteryInfo);
}

void LnnDeinitBatteryInfo(void)
{
    (void)LnnUnregSyncInfoHandler(LNN_INFO_TYPE_BATTERY_INFO, OnReceiveBatteryInfo);
}