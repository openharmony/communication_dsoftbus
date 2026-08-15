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

#include "lnn_battery_info.h"

#include <securec.h>

#include "bus_center_event.h"
#include "lnn_distributed_net_ledger.h"
#include "lnn_log.h"
#include "lnn_sync_info_manager.h"
#include "softbus_adapter_mem.h"
#include "softbus_json_utils.h"
#include "softbus_utils.h"

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

#ifdef DSOFTBUS_FEATURE_MULTI_FOREGROUND_USER
typedef struct {
    ListNode node;
    uint64_t screenId;
    SoftBusMultiScreenState state;
} LnnMultiScreenStateNode;

static SoftBusList *g_multiScreenStateList = NULL;

static LnnMultiScreenStateNode *FindScreenStateNode(SoftBusList *list, uint64_t screenId)
{
    if (list == NULL) {
        return NULL;
    }
    LnnMultiScreenStateNode *item = NULL;
    LIST_FOR_EACH_ENTRY(item, &list->list, LnnMultiScreenStateNode, node) {
        if (item->screenId == screenId) {
            return item;
        }
    }
    return NULL;
}

static void MultiScreenStateChangedHandler(const LnnEventBasicInfo *info)
{
    if (info == NULL || info->event != LNN_EVENT_MULTI_SCREEN_STATE_CHANGED) {
        LNN_LOGW(LNN_LANE, "multi screen state handler get invalid param");
        return;
    }
    if (g_multiScreenStateList == NULL) {
        LNN_LOGW(LNN_LANE, "multi screen state list not init");
        return;
    }
    const LnnMultiScreenStateChangedEvent *event = (const LnnMultiScreenStateChangedEvent *)info;
    if (SoftBusMutexLock(&g_multiScreenStateList->lock) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "lock multi screen state list fail");
        return;
    }
    LnnMultiScreenStateNode *node = FindScreenStateNode(g_multiScreenStateList, (uint64_t)event->screenId);
    if (node != NULL) {
        node->state = event->status;
    } else {
        node = (LnnMultiScreenStateNode *)SoftBusCalloc(sizeof(LnnMultiScreenStateNode));
        if (node == NULL) {
            (void)SoftBusMutexUnlock(&g_multiScreenStateList->lock);
            LNN_LOGE(LNN_LANE, "calloc multi screen state node fail");
            return;
        }
        node->screenId = (uint64_t)event->screenId;
        node->state = event->status;
        ListAdd(&g_multiScreenStateList->list, &node->node);
        g_multiScreenStateList->cnt++;
    }
    unsigned int listSize = g_multiScreenStateList->cnt;
    (void)SoftBusMutexUnlock(&g_multiScreenStateList->lock);
    LNN_LOGI(LNN_LANE, "refresh multi screen state screenId=%{public}" PRId64 ", state=%{public}d, listSize=%{public}u",
        event->screenId, event->status, listSize);
}

bool LnnIsAllMultiScreenOff(void)
{
    if (g_multiScreenStateList == NULL) {
        return false;
    }
    bool allOff = true;
    if (SoftBusMutexLock(&g_multiScreenStateList->lock) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "lock multi screen state list fail");
        return false;
    }
    LnnMultiScreenStateNode *item = NULL;
    LIST_FOR_EACH_ENTRY(item, &g_multiScreenStateList->list, LnnMultiScreenStateNode, node) {
        if (item->state != SOFTBUS_MULTI_SCREEN_OFF) {
            allOff = false;
            LNN_LOGI(LNN_LANE, "screen not off, screenId=%{public}" PRIu64, item->screenId);
            break;
        }
    }
    (void)SoftBusMutexUnlock(&g_multiScreenStateList->lock);
    LNN_LOGI(LNN_LANE, "all multi screen off=%{public}d", allOff);
    return allOff;
}
#else
bool LnnIsAllMultiScreenOff(void)
{
    return false;
}
#endif

int32_t LnnInitBatteryInfo(void)
{
    int32_t rc = LnnRegSyncInfoHandler(LNN_INFO_TYPE_BATTERY_INFO, OnReceiveBatteryInfo);
    if (rc != SOFTBUS_OK) {
        return rc;
    }
#ifdef DSOFTBUS_FEATURE_MULTI_FOREGROUND_USER
    g_multiScreenStateList = CreateSoftBusList();
    if (g_multiScreenStateList == NULL) {
        LNN_LOGE(LNN_LANE, "create multi screen state list fail");
        (void)LnnUnregSyncInfoHandler(LNN_INFO_TYPE_BATTERY_INFO, OnReceiveBatteryInfo);
        return SOFTBUS_CREATE_LIST_ERR;
    }
    rc = LnnRegisterEventHandler(LNN_EVENT_MULTI_SCREEN_STATE_CHANGED, MultiScreenStateChangedHandler);
    if (rc != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "register multi screen state event handler fail, rc=%{public}d", rc);
        DestroySoftBusList(g_multiScreenStateList);
        g_multiScreenStateList = NULL;
        (void)LnnUnregSyncInfoHandler(LNN_INFO_TYPE_BATTERY_INFO, OnReceiveBatteryInfo);
        return rc;
    }
#endif
    return SOFTBUS_OK;
}

void LnnDeinitBatteryInfo(void)
{
    (void)LnnUnregSyncInfoHandler(LNN_INFO_TYPE_BATTERY_INFO, OnReceiveBatteryInfo);
#ifdef DSOFTBUS_FEATURE_MULTI_FOREGROUND_USER
    (void)LnnUnregisterEventHandler(LNN_EVENT_MULTI_SCREEN_STATE_CHANGED, MultiScreenStateChangedHandler);
    if (g_multiScreenStateList != NULL) {
        LnnMultiScreenStateNode *item = NULL;
        LnnMultiScreenStateNode *next = NULL;
        if (SoftBusMutexLock(&g_multiScreenStateList->lock) == SOFTBUS_OK) {
            LIST_FOR_EACH_ENTRY_SAFE(item, next, &g_multiScreenStateList->list, LnnMultiScreenStateNode, node) {
                ListDelete(&item->node);
                g_multiScreenStateList->cnt--;
                SoftBusFree(item);
            }
            (void)SoftBusMutexUnlock(&g_multiScreenStateList->lock);
        }
        DestroySoftBusList(g_multiScreenStateList);
        g_multiScreenStateList = NULL;
    }
#endif
}