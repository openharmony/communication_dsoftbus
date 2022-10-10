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

#include <securec.h>
#include <stdlib.h>

#include "lnn_bus_center_ipc.h"
#include "message_handler.h"
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

typedef enum {
    NOTIFY_ONLINE_STATE_CHANGED = 0,
    NOTIFY_NODE_BASIC_INFO_CHANGED,
} NotifyType;

static BusCenterEventCtrl g_eventCtrl;
static SoftBusHandler g_notifyHandler = {"NotifyHandler", NULL, NULL};

static int32_t PostMessageToHandler(SoftBusMessage *msg)
{
    if (g_notifyHandler.looper == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "NotifyHandler not initialized.");
        return SOFTBUS_NO_INIT;
    }
    if (g_notifyHandler.looper->PostMessage == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "invalid looper.");
        return SOFTBUS_ERR;
    }
    g_notifyHandler.looper->PostMessage(g_notifyHandler.looper, msg);
    return SOFTBUS_OK;
}

static void HandleOnlineStateChangedMessage(SoftBusMessage *msg)
{
    if (msg->obj == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "invalid online state message.");
        return;
    }
    bool isOnline = (bool)msg->arg1;
    LnnIpcNotifyOnlineState(isOnline, msg->obj, sizeof(NodeBasicInfo));
}

static void HandleNodeBasicInfoChangedMessage(SoftBusMessage *msg)
{
    if (msg->obj == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "invalid node basic info message.");
        return;
    }
    int32_t type = (int32_t)msg->arg1;
    LnnIpcNotifyBasicInfoChanged(msg->obj, sizeof(NodeBasicInfo), type);
}

static void HandleNotifyMessage(SoftBusMessage *msg)
{
    if (msg == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "invalid notify message.");
        return;
    }
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "handle notify message, type = %d.", msg->what);
    switch (msg->what) {
        case NOTIFY_ONLINE_STATE_CHANGED:
            HandleOnlineStateChangedMessage(msg);
            break;
        case NOTIFY_NODE_BASIC_INFO_CHANGED:
            HandleNodeBasicInfoChangedMessage(msg);
            break;
        default:
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "unknown notify message, type = %d.", msg->what);
            break;
    }
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "handle notify message done, type = %d.", msg->what);
}

static void FreeNotifyMessage(SoftBusMessage *msg)
{
    if (msg == NULL) {
        return;
    }
    if (msg->obj != NULL) {
        SoftBusFree(msg->obj);
        msg->obj = NULL;
    }
    SoftBusFree(msg);
}

static NodeBasicInfo *DupNodeBasicInfo(const NodeBasicInfo *info)
{
    if (info == NULL) {
        return NULL;
    }
    NodeBasicInfo *dupInfo = SoftBusMalloc(sizeof(NodeBasicInfo));
    if (dupInfo == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "malloc NodeBasicInfo err.");
        return NULL;
    }
    if (memcpy_s(dupInfo, sizeof(NodeBasicInfo), info, sizeof(NodeBasicInfo)) != EOK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "copy NodeBasicInfo fail.");
        SoftBusFree(dupInfo);
        return NULL;
    }
    return dupInfo;
}

static int32_t PostNotifyMessage(int32_t what, uint64_t arg, const NodeBasicInfo *info)
{
    SoftBusMessage *msg = SoftBusCalloc(sizeof(SoftBusMessage));
    if (msg == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "malloc msg err.");
        return SOFTBUS_MALLOC_ERR;
    }
    msg->what = what;
    msg->arg1 = arg;
    msg->obj = DupNodeBasicInfo(info);
    if (msg->obj == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "dup NodeBasicInfo err.");
        SoftBusFree(msg);
        return SOFTBUS_MEM_ERR;
    }
    msg->handler = &g_notifyHandler;
    msg->FreeMessage = FreeNotifyMessage;
    return PostMessageToHandler(msg);
}

static bool IsRepeatEventHandler(LnnEventType event, LnnEventHandler handler)
{
    LnnEventHandlerItem *item = NULL;

    LIST_FOR_EACH_ENTRY(item, &g_eventCtrl.handlers[event], LnnEventHandlerItem, node)
    {
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
    LIST_FOR_EACH_ENTRY(item, &g_eventCtrl.handlers[info->event], LnnEventHandlerItem, node)
    {
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
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "notify node %s %s",
        info->deviceName, (isOnline == true) ? "online" : "offline");
    SetDefaultQdisc();
    (void)PostNotifyMessage(NOTIFY_ONLINE_STATE_CHANGED, (uint64_t)isOnline, info);
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
    (void)PostNotifyMessage(NOTIFY_NODE_BASIC_INFO_CHANGED, (uint64_t)type, info);
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

void MetaNodeNotifyJoinResult(ConnectionAddr *addr, const char *networkId, int32_t retCode)
{
    if (addr == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "para : addr or networkId = null!");
        return;
    }
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "notify join MetaNode result :%d", retCode);
    MetaNodeIpcNotifyJoinResult(addr, sizeof(ConnectionAddr), networkId, retCode);
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

void MetaNodeNotifyLeaveResult(const char *networkId, int32_t retCode)
{
    if (networkId == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "para : networkId = null!");
        return;
    }
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "notify leave MetaNode result %d", retCode);
    MetaNodeIpcNotifyLeaveResult(networkId, retCode);
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

void LnnNotifyWlanStateChangeEvent(SoftBusWifiState state)
{
    if (state < SOFTBUS_WIFI_CONNECTED || state > SOFTBUS_WIFI_UNKNOWN) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "bad state %d", state);
        return;
    }
    LnnMonitorWlanStateChangedEvent event = {.basic.event = LNN_EVENT_WIFI_STATE_CHANGED, .status = state};
    NotifyEvent((const LnnEventBasicInfo *)&event);
}

void LnnNotifyScreenStateChangeEvent(SoftBusScreenState state)
{
    if (state < SOFTBUS_SCREEN_ON || state >= SOFTBUS_SCREEN_UNKNOWN) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "bad state %d", state);
        return;
    }
    LnnMonitorScreenStateChangedEvent event = {.basic.event = LNN_EVENT_SCREEN_STATE_CHANGED, .status = state};
    NotifyEvent((const LnnEventBasicInfo *)&event);
}

void LnnNotifyBtStateChangeEvent(void *state)
{
    SoftBusBtState *btState = (SoftBusBtState *)state;
    if (*btState < SOFTBUS_BLE_TURN_ON || *btState >= SOFTBUS_BT_UNKNOWN) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "bad btState %d", *btState);
        SoftBusFree(btState);
        return;
    }
    LnnMonitorBtStateChangedEvent event = {.basic.event = LNN_EVENT_BT_STATE_CHANGED, .status = (uint8_t)(*btState)};
    NotifyEvent((const LnnEventBasicInfo *)&event);
    SoftBusFree(btState);
}

void LnnNotifyBtAclStateChangeEvent(const char *btMac, SoftBusBtAclState state)
{
    if (btMac == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "invalid btMac, state = %d", state);
        return;
    }
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO,
        "notify bt acl state changed: state=%d, btMac=%s.", state, AnonymizesMac(btMac));
    LnnMonitorBtAclStateChangedEvent event = {.basic.event = LNN_EVENT_BT_ACL_STATE_CHANGED, .status = state};
    if (strcpy_s(event.btMac, sizeof(event.btMac), btMac) != EOK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "copy bt mac fail");
        return;
    }
    NotifyEvent((const LnnEventBasicInfo *)&event);
}

void LnnNotifyAddressChangedEvent(const char *ifName)
{
    LnnMonitorAddressChangedEvent event = {.basic.event = LNN_EVENT_IP_ADDR_CHANGED, .ifName = {0}};
    if (ifName != NULL) {
        int32_t ret = strcpy_s(event.ifName, sizeof(event.ifName), ifName);
        if (ret != EOK) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "copy ifName failed!ret=%d", ret);
            return;
        }
    }
    NotifyEvent((const LnnEventBasicInfo *)&event);
}

void LnnNotifyMasterNodeChanged(bool isMaster, const char *masterNodeUdid, int32_t weight)
{
    LnnMasterNodeChangedEvent event = {.basic.event = LNN_EVENT_NODE_MASTER_STATE_CHANGED,
        .isMasterNode = isMaster,
        .masterNodeUDID = masterNodeUdid,
        .weight = weight};

    NotifyEvent((const LnnEventBasicInfo *)&event);
}

void LnnNotifyNodeAddressChanged(const char *addr)
{
    if (addr == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "%s:nullptr!", __func__);
        return;
    }
    LnnNodeAddrChangedEvent eventInfo;
    (void)memset_s(&eventInfo, sizeof(eventInfo), 0, sizeof(eventInfo));
    eventInfo.basic.event = LNN_EVENT_NODE_ADDR_CHANGED;
    if (strcpy_s(eventInfo.addr, sizeof(eventInfo.addr), addr) != EOK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "%s:strcpy_s failed", __func__);
        return;
    }
    if (strcmp(addr, NODE_ADDR_LOOPBACK) == 0) {
        eventInfo.delFlag = true;
    } else {
        eventInfo.delFlag = false;
    }
    NotifyEvent((LnnEventBasicInfo *)&eventInfo);
}

int32_t LnnInitBusCenterEvent(void)
{
    int32_t i;
    SoftBusLooper *looper = CreateNewLooper("NotifyLooper");
    if (looper == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "create notify looper fail.");
        return SOFTBUS_ERR;
    }
    g_notifyHandler.looper = looper;
    g_notifyHandler.HandleMessage = HandleNotifyMessage;

    SoftBusMutexAttr mutexAttr;
    mutexAttr.type = SOFTBUS_MUTEX_RECURSIVE;
    SoftBusMutexInit(&g_eventCtrl.lock, &mutexAttr);
    for (i = 0; i < LNN_EVENT_TYPE_MAX; ++i) {
        ListInit(&g_eventCtrl.handlers[i]);
    }
    return SOFTBUS_OK;
}

void LnnDeinitBusCenterEvent(void)
{
    if (g_notifyHandler.looper != NULL) {
        DestroyLooper(g_notifyHandler.looper);
        g_notifyHandler.looper = NULL;
        g_notifyHandler.HandleMessage = NULL;
    }
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
    LIST_FOR_EACH_ENTRY(item, &g_eventCtrl.handlers[event], LnnEventHandlerItem, node)
    {
        if (item->handler == handler) {
            ListDelete(&item->node);
            SoftBusFree(item);
            break;
        }
    }
    (void)SoftBusMutexUnlock(&g_eventCtrl.lock);
}