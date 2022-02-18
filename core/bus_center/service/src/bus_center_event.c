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

#include "bus_center_event.h"

#include <stdlib.h>

#include "lnn_bus_center_ipc.h"
#include "softbus_adapter_mem.h"
#include "softbus_adapter_thread.h"
#include "softbus_errcode.h"
#include "softbus_log.h"
#include "softbus_qos.h"

typedef struct {
    ListNode node;
    LnnEventHandler handler;
} LnnEventHandlerItem;

typedef struct {
    ListNode handlers[LNN_EVENT_TYPE_MAX];
    SoftBusMutex lock;
} BusCenterEventCtrl;

static BusCenterEventCtrl g_eventCtrl;

static bool IsRepeatEventHandler(LnnEventType event, LnnEventHandler handler)
{
    LnnEventHandlerItem *item = NULL;

    LIST_FOR_EACH_ENTRY(item, &g_eventCtrl.handlers[event], LnnEventHandlerItem, node) {
        if (item->handler == handler) {
            return true;
        }
    }
    return false;
}

static LnnEventHandlerItem *CreateEventHandlerItem(LnnEventHandler handler)
{
    LnnEventHandlerItem *item = SoftBusMalloc(sizeof(LnnEventHandlerItem));

    if (item == NULL) {
        return NULL;
    }
    ListInit(&item->node);
    item->handler = handler;
    return item;
}

static void NotifyEvent(const LnnEventBasicInfo *info)
{
    LnnEventHandlerItem *item = NULL;

    if (SoftBusMutexLock(&g_eventCtrl.lock) != 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "lock failed in notify event");
        return;
    }
    LIST_FOR_EACH_ENTRY(item, &g_eventCtrl.handlers[info->event], LnnEventHandlerItem, node) {
        item->handler(info);
    }
    (void)SoftBusMutexUnlock(&g_eventCtrl.lock);
}

void LnnNotifyOnlineState(bool isOnline, NodeBasicInfo *info)
{
    LnnOnlineStateEventInfo eventInfo;

    if (info == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "para : info = null!");
        return;
    }
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "notify node %s", (isOnline == true) ? "online" : "offline");
    SetDefaultQdisc();
    LnnIpcNotifyOnlineState(isOnline, info, sizeof(NodeBasicInfo));
    eventInfo.basic.event = LNN_EVENT_NODE_ONLINE_STATE_CHANGED;
    eventInfo.isOnline = isOnline;
    eventInfo.networkId = info->networkId;
    NotifyEvent((LnnEventBasicInfo *)&eventInfo);
}

void LnnNotifyBasicInfoChanged(NodeBasicInfo *info, NodeBasicInfoType type)
{
    if (info == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "para : info = null!");
        return;
    }
    if (type == TYPE_DEVICE_NAME) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "notify peer device name changed %s", info->deviceName);
    }
    LnnIpcNotifyBasicInfoChanged(info, sizeof(NodeBasicInfo), type);
}

void LnnNotifyJoinResult(ConnectionAddr *addr, const char *networkId, int32_t retCode)
{
    if (addr == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "para : addr or networkId = null!");
        return;
    }
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "notify join LNN result :%d", retCode);
    LnnIpcNotifyJoinResult(addr, sizeof(ConnectionAddr), networkId, retCode);
}

void LnnNotifyLeaveResult(const char *networkId, int32_t retCode)
{
    if (networkId == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "para : networkId = null!");
        return;
    }
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "notify leave LNN result %d", retCode);
    LnnIpcNotifyLeaveResult(networkId, retCode);
}

void LnnNotifyLnnRelationChanged(const char *udid, ConnectionAddrType type, uint8_t relation, bool isJoin)
{
    LnnRelationChanedEventInfo info;

    info.basic.event = LNN_EVENT_RELATION_CHANGED;
    info.type = type;
    info.relation = relation;
    info.isJoin = isJoin;
    info.udid = udid;
    NotifyEvent((LnnEventBasicInfo *)&info);
}

void LnnNotifyTimeSyncResult(const char *pkgName, const TimeSyncResultInfo *info, int32_t retCode)
{
    if (pkgName == NULL || info == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "invalid paramters");
        return;
    }
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "notify time Sync result %d", retCode);
    LnnIpcNotifyTimeSyncResult(pkgName, info, sizeof(TimeSyncResultInfo), retCode);
}

void LnnNotifyMonitorEvent(const LnnMonitorEventInfo *info)
{
    if (info == NULL || info->basic.event == LNN_EVENT_TYPE_MAX) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "invalid monitr event paramter");
        return;
    }
    NotifyEvent((const LnnEventBasicInfo *)info);
}

int32_t LnnInitBusCenterEvent(void)
{
    int32_t i;

    SoftBusMutexInit(&g_eventCtrl.lock, NULL);
    for (i = 0; i < LNN_EVENT_TYPE_MAX; ++i) {
        ListInit(&g_eventCtrl.handlers[i]);
    }
    return SOFTBUS_OK;
}

void LnnDeinitBusCenterEvent(void)
{
    SoftBusMutexDestroy(&g_eventCtrl.lock);
}

int32_t LnnRegisterEventHandler(LnnEventType event, LnnEventHandler handler)
{
    LnnEventHandlerItem *item = NULL;

    if (event == LNN_EVENT_TYPE_MAX || handler == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "invalid event handler params");
        return SOFTBUS_INVALID_PARAM;
    }
    if (SoftBusMutexLock(&g_eventCtrl.lock) != 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "lock failed in register event handler");
        return SOFTBUS_LOCK_ERR;
    }
    if (IsRepeatEventHandler(event, handler)) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "event(%u) handler is already exist", event);
        (void)SoftBusMutexUnlock(&g_eventCtrl.lock);
        return SOFTBUS_INVALID_PARAM;
    }
    item = CreateEventHandlerItem(handler);
    if (item == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "create event handler item failed");
        (void)SoftBusMutexUnlock(&g_eventCtrl.lock);
        return SOFTBUS_MEM_ERR;
    }
    ListAdd(&g_eventCtrl.handlers[event], &item->node);
    (void)SoftBusMutexUnlock(&g_eventCtrl.lock);
    return SOFTBUS_OK;
}

void LnnUnregisterEventHandler(LnnEventType event, LnnEventHandler handler)
{
    LnnEventHandlerItem *item = NULL;

    if (event == LNN_EVENT_TYPE_MAX || handler == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "invalid event handler params");
        return;
    }
    if (SoftBusMutexLock(&g_eventCtrl.lock) != 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "hold lock failed in unregister event handler");
        return;
    }
    LIST_FOR_EACH_ENTRY(item, &g_eventCtrl.handlers[event], LnnEventHandlerItem, node) {
        if (item->handler == handler) {
            ListDelete(&item->node);
            SoftBusFree(item);
            break;
        }
    }
    (void)SoftBusMutexUnlock(&g_eventCtrl.lock);
}