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

#include "anonymizer.h"
#include "bus_center_decision_center.h"
#include "bus_center_manager.h"
#include "lnn_bus_center_ipc.h"
#include "lnn_cipherkey_manager.h"
#include "lnn_distributed_net_ledger.h"
#include "lnn_log.h"
#include "lnn_network_id.h"
#include "lnn_p2p_info.h"
#include "message_handler.h"
#include "softbus_adapter_crypto.h"
#include "softbus_adapter_mem.h"
#include "softbus_adapter_thread.h"
#include "softbus_def.h"
#include "softbus_errcode.h"
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
    NOTIFY_NETWORKID_UPDATE,
} NotifyType;

#define NETWORK_ID_UPDATE_DELAY_TIME (60 * 60 * 1000 * 24) // 24 hour

static BusCenterEventCtrl g_eventCtrl;
static SoftBusHandler g_notifyHandler = {"NotifyHandler", NULL, NULL};

static int32_t PostMessageToHandlerDelay(SoftBusMessage *msg, uint64_t delayMillis)
{
    if (g_notifyHandler.looper == NULL) {
        LNN_LOGE(LNN_EVENT, "NotifyHandler not initialized");
        FreeMessage(msg);
        return SOFTBUS_NO_INIT;
    }
    if (g_notifyHandler.looper->PostMessage == NULL || g_notifyHandler.looper->PostMessageDelay == NULL) {
        LNN_LOGE(LNN_EVENT, "invalid looper");
        FreeMessage(msg);
        return SOFTBUS_INVALID_PARAM;
    }
    if (delayMillis == 0) {
        g_notifyHandler.looper->PostMessage(g_notifyHandler.looper, msg);
    } else {
        g_notifyHandler.looper->PostMessageDelay(g_notifyHandler.looper, msg, delayMillis);
    }
    return SOFTBUS_OK;
}

static void RemoveNotifyMessage(int32_t what)
{
    if (g_notifyHandler.looper == NULL) {
        LNN_LOGE(LNN_EVENT, "looper not initialized, can't remove message");
        return;
    }
    if (g_notifyHandler.looper->RemoveMessage == NULL) {
        LNN_LOGE(LNN_EVENT, "removeMessage is null");
        return;
    }
    g_notifyHandler.looper->RemoveMessage(g_notifyHandler.looper, &g_notifyHandler, what);
}

static void HandleOnlineStateChangedMessage(SoftBusMessage *msg)
{
    if (msg->obj == NULL) {
        LNN_LOGE(LNN_EVENT, "invalid online state message");
        return;
    }
    bool isOnline = (bool)msg->arg1;
    LnnIpcNotifyOnlineState(isOnline, msg->obj, sizeof(NodeBasicInfo));
    LnnDCProcessOnlineState(isOnline, (NodeBasicInfo *)msg->obj);
}

static void HandleNodeBasicInfoChangedMessage(SoftBusMessage *msg)
{
    if (msg->obj == NULL) {
        LNN_LOGE(LNN_EVENT, "invalid node basic info message");
        return;
    }
    int32_t type = (int32_t)msg->arg1;
    LnnIpcNotifyBasicInfoChanged(msg->obj, sizeof(NodeBasicInfo), type);
}

static void HandleNetworkUpdateMessage(SoftBusMessage *msg)
{
    (void)msg;
    char networkId[NETWORK_ID_BUF_LEN] = {0};
    if (LnnGenLocalNetworkId(networkId, NETWORK_ID_BUF_LEN) != SOFTBUS_OK) {
        LNN_LOGE(LNN_EVENT, "generate networkid fail");
        return;
    }
    LnnSetLocalStrInfo(STRING_KEY_NETWORKID, networkId);
    LnnNotifyNetworkIdChangeEvent(networkId);
    LNN_LOGD(LNN_EVENT, "offline exceted 5min, process networkId update event");
}

static void HandleNotifyMessage(SoftBusMessage *msg)
{
    if (msg == NULL) {
        LNN_LOGE(LNN_EVENT, "invalid notify message");
        return;
    }
    LNN_LOGI(LNN_EVENT, "handle notify msgType=%{public}d", msg->what);
    switch (msg->what) {
        case NOTIFY_ONLINE_STATE_CHANGED:
            HandleOnlineStateChangedMessage(msg);
            break;
        case NOTIFY_NODE_BASIC_INFO_CHANGED:
            HandleNodeBasicInfoChangedMessage(msg);
            break;
        case NOTIFY_NETWORKID_UPDATE:
            HandleNetworkUpdateMessage(msg);
            break;
        default:
            LNN_LOGE(LNN_EVENT, "unknown notify msgType=%{public}d", msg->what);
            break;
    }
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
        LNN_LOGW(LNN_EVENT, "info is null");
        return NULL;
    }
    NodeBasicInfo *dupInfo = SoftBusMalloc(sizeof(NodeBasicInfo));
    if (dupInfo == NULL) {
        LNN_LOGE(LNN_EVENT, "malloc NodeBasicInfo err");
        return NULL;
    }
    if (memcpy_s(dupInfo, sizeof(NodeBasicInfo), info, sizeof(NodeBasicInfo)) != EOK) {
        LNN_LOGE(LNN_EVENT, "copy NodeBasicInfo fail");
        SoftBusFree(dupInfo);
        return NULL;
    }
    return dupInfo;
}

static int32_t PostNotifyMessage(int32_t what, uint64_t arg, const NodeBasicInfo *info)
{
    SoftBusMessage *msg = SoftBusCalloc(sizeof(SoftBusMessage));
    if (msg == NULL) {
        LNN_LOGE(LNN_EVENT, "malloc msg err");
        return SOFTBUS_MALLOC_ERR;
    }
    msg->what = what;
    msg->arg1 = arg;
    msg->obj = DupNodeBasicInfo(info);
    if (msg->obj == NULL) {
        LNN_LOGE(LNN_EVENT, "dup NodeBasicInfo err");
        SoftBusFree(msg);
        return SOFTBUS_MEM_ERR;
    }
    msg->handler = &g_notifyHandler;
    msg->FreeMessage = FreeNotifyMessage;
    return PostMessageToHandlerDelay(msg, 0);
}

static int32_t PostNotifyMessageDelay(int32_t what, uint64_t delayMillis)
{
    SoftBusMessage *msg = SoftBusCalloc(sizeof(SoftBusMessage));
    if (msg == NULL) {
        LNN_LOGE(LNN_EVENT, "malloc msg fail");
        return SOFTBUS_MALLOC_ERR;
    }
    msg->what = what;
    msg->handler = &g_notifyHandler;
    msg->FreeMessage = FreeNotifyMessage;
    return PostMessageToHandlerDelay(msg, delayMillis);
}

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
        LNN_LOGE(LNN_EVENT, "lock failed in notify event");
        return;
    }
    LIST_FOR_EACH_ENTRY(item, &g_eventCtrl.handlers[info->event], LnnEventHandlerItem, node) {
        item->handler(info);
    }
    (void)SoftBusMutexUnlock(&g_eventCtrl.lock);
}

void LnnNotifyDeviceVerified(const char *udid)
{
    (void)udid;
    LNN_LOGI(LNN_EVENT, "exist device joining LNN, remove networkId update event");
    RemoveNotifyMessage(NOTIFY_NETWORKID_UPDATE);
}

static void UpdateBroadcastInfo()
{
    BroadcastCipherKey broadcastKey;
    (void)memset_s(&broadcastKey, sizeof(BroadcastCipherKey), 0, sizeof(BroadcastCipherKey));
    if (LnnGetLocalBroadcastCipherKey(&broadcastKey) != SOFTBUS_OK) {
        LNN_LOGE(LNN_EVENT, "get local info failed.");
        return;
    }
    if (SoftBusGetSysTimeMs() < broadcastKey.endTime) {
        (void)memset_s(&broadcastKey, sizeof(BroadcastCipherKey), 0, sizeof(BroadcastCipherKey));
        LNN_LOGI(LNN_EVENT, "the broadcastKey don't need to update.");
        return;
    }
    if (LnnGetLocalStrInfo(STRING_KEY_DEV_UDID, broadcastKey.udid, UDID_BUF_LEN) != SOFTBUS_OK) {
        (void)memset_s(&broadcastKey, sizeof(BroadcastCipherKey), 0, sizeof(BroadcastCipherKey));
        LNN_LOGE(LNN_EVENT, "get udid fail");
        return;
    }
    if (SoftBusGenerateRandomArray(broadcastKey.cipherInfo.key, SESSION_KEY_LENGTH) != SOFTBUS_OK) {
        (void)memset_s(&broadcastKey, sizeof(BroadcastCipherKey), 0, sizeof(BroadcastCipherKey));
        LNN_LOGE(LNN_EVENT, "generate broadcast key error.");
        return;
    }
    if (SoftBusGenerateRandomArray(broadcastKey.cipherInfo.iv, BROADCAST_IV_LEN) != SOFTBUS_OK) {
        (void)memset_s(&broadcastKey, sizeof(BroadcastCipherKey), 0, sizeof(BroadcastCipherKey));
        LNN_LOGE(LNN_EVENT, "generate broadcast iv error.");
        return;
    }
    if (LnnSetLocalByteInfo(BYTE_KEY_BROADCAST_CIPHER_KEY,
        broadcastKey.cipherInfo.key, SESSION_KEY_LENGTH) != SOFTBUS_OK) {
        (void)memset_s(&broadcastKey, sizeof(BroadcastCipherKey), 0, sizeof(BroadcastCipherKey));
        LNN_LOGE(LNN_EVENT, "set key error.");
        return;
    }
    if (LnnSetLocalByteInfo(BYTE_KEY_BROADCAST_CIPHER_IV,
        broadcastKey.cipherInfo.iv, BROADCAST_IV_LEN) != SOFTBUS_OK) {
        (void)memset_s(&broadcastKey, sizeof(BroadcastCipherKey), 0, sizeof(BroadcastCipherKey));
        LNN_LOGE(LNN_EVENT, "set iv error.");
        return;
    }
    if (LnnUpdateLocalBroadcastCipherKey(&broadcastKey) != SOFTBUS_OK) {
        (void)memset_s(&broadcastKey, sizeof(BroadcastCipherKey), 0, sizeof(BroadcastCipherKey));
        LNN_LOGE(LNN_EVENT, "update local broadcast key failed");
        return;
    }
    (void)memset_s(&broadcastKey, sizeof(BroadcastCipherKey), 0, sizeof(BroadcastCipherKey));
    LNN_LOGI(LNN_EVENT, "update local broadcast key success!");
}

void LnnNotifyOnlineState(bool isOnline, NodeBasicInfo *info)
{
    LnnOnlineStateEventInfo eventInfo;

    if (info == NULL) {
        LNN_LOGW(LNN_EVENT, "info = null");
        return;
    }
    char *anonyNetworkId = NULL;
    Anonymize(info->networkId, &anonyNetworkId);
    LNN_LOGI(LNN_EVENT, "notify node. deviceName=%{public}s, isOnline=%{public}s, networkId=%{public}s",
        info->deviceName, (isOnline == true) ? "online" : "offline", anonyNetworkId);
    AnonymizeFree(anonyNetworkId);
    SetDefaultQdisc();
    (void)PostNotifyMessage(NOTIFY_ONLINE_STATE_CHANGED, (uint64_t)isOnline, info);
    eventInfo.basic.event = LNN_EVENT_NODE_ONLINE_STATE_CHANGED;
    eventInfo.isOnline = isOnline;
    eventInfo.networkId = info->networkId;
    eventInfo.uuid = "";
    eventInfo.udid = "";
    NotifyEvent((LnnEventBasicInfo *)&eventInfo);
    int32_t onlineNodeNum = 0;
    if (LnnGetAllOnlineNodeNum(&onlineNodeNum) != SOFTBUS_OK) {
        LNN_LOGE(LNN_EVENT, "get online nodeNum fail");
        return;
    }
    if (!isOnline && onlineNodeNum == 0) {
        LNN_LOGI(LNN_EVENT, "no online devices, post networkId update event");
        UpdateBroadcastInfo();
        RemoveNotifyMessage(NOTIFY_NETWORKID_UPDATE);
        (void)PostNotifyMessageDelay(NOTIFY_NETWORKID_UPDATE, NETWORK_ID_UPDATE_DELAY_TIME);
    }
    if (isOnline) {
        LNN_LOGI(LNN_EVENT, "online process, remove networkId update event");
        RemoveNotifyMessage(NOTIFY_NETWORKID_UPDATE);
    }
}

void LnnNotifyMigrate(bool isOnline, NodeBasicInfo *info)
{
    LnnOnlineStateEventInfo eventInfo;

    if (info == NULL) {
        LNN_LOGW(LNN_EVENT, "info = null");
        return;
    }
    eventInfo.basic.event = LNN_EVENT_NODE_MIGRATE;
    eventInfo.isOnline = isOnline;
    eventInfo.networkId = info->networkId;
    NotifyEvent((LnnEventBasicInfo *)&eventInfo);
}

void LnnNotifyBasicInfoChanged(NodeBasicInfo *info, NodeBasicInfoType type)
{
    if (info == NULL) {
        LNN_LOGW(LNN_EVENT, "info = null");
        return;
    }
    if (type == TYPE_DEVICE_NAME) {
        LNN_LOGI(LNN_EVENT, "notify peer device name changed. deviceName=%{public}s", info->deviceName);
    }
    (void)PostNotifyMessage(NOTIFY_NODE_BASIC_INFO_CHANGED, (uint64_t)type, info);
}

void LnnNotifyJoinResult(ConnectionAddr *addr, const char *networkId, int32_t retCode)
{
    if (addr == NULL) {
        LNN_LOGW(LNN_EVENT, "addr or networkId = null!");
        return;
    }
    LNN_LOGI(LNN_EVENT, "notify join LNN result=%{public}d", retCode);
    LnnIpcNotifyJoinResult(addr, sizeof(ConnectionAddr), networkId, retCode);
}

void LnnNotifyLeaveResult(const char *networkId, int32_t retCode)
{
    if (networkId == NULL) {
        LNN_LOGW(LNN_EVENT, "networkId = null");
        return;
    }
    LNN_LOGI(LNN_EVENT, "notify leave LNN result. retCode=%{public}d", retCode);
    LnnIpcNotifyLeaveResult(networkId, retCode);
}

void LnnNotifyLnnRelationChanged(const char *udid, ConnectionAddrType type, uint8_t relation,
    bool isJoin)
{
    LnnRelationChanedEventInfo info;

    info.basic.event = LNN_EVENT_RELATION_CHANGED;
    info.type = type;
    info.relation = relation;
    info.isJoin = isJoin;
    info.udid = udid;
    NotifyEvent((LnnEventBasicInfo *)&info);
}

void LnnNotifyTimeSyncResult(const char *pkgName, int32_t pid, const TimeSyncResultInfo *info,
    int32_t retCode)
{
    if (pkgName == NULL || info == NULL) {
        LNN_LOGW(LNN_EVENT, "invalid paramters");
        return;
    }
    LNN_LOGI(LNN_EVENT, "notify time Sync result. retCode=%{public}d", retCode);
    LnnIpcNotifyTimeSyncResult(pkgName, pid, info, sizeof(TimeSyncResultInfo), retCode);
}

void LnnNotifyWlanStateChangeEvent(SoftBusWifiState state)
{
    if (state < SOFTBUS_WIFI_CONNECTED || state > SOFTBUS_WIFI_UNKNOWN) {
        LNN_LOGE(LNN_EVENT, "bad state=%{public}d", state);
        return;
    }
    LnnMonitorWlanStateChangedEvent event = {.basic.event = LNN_EVENT_WIFI_STATE_CHANGED, .status = state};
    NotifyEvent((const LnnEventBasicInfo *)&event);
}

void LnnNotifyScreenStateChangeEvent(SoftBusScreenState state)
{
    if (state < SOFTBUS_SCREEN_ON || state >= SOFTBUS_SCREEN_UNKNOWN) {
        LNN_LOGE(LNN_EVENT, "bad state=%{public}d", state);
        return;
    }
    LnnMonitorHbStateChangedEvent event = {.basic.event = LNN_EVENT_SCREEN_STATE_CHANGED, .status = state};
    NotifyEvent((const LnnEventBasicInfo *)&event);
}

void LnnNotifyBtStateChangeEvent(void *state)
{
    SoftBusBtState *btState = (SoftBusBtState *)state;
    if (*btState < SOFTBUS_BLE_TURN_ON || *btState >= SOFTBUS_BT_UNKNOWN) {
        LNN_LOGE(LNN_EVENT, "bad btState=%{public}d", *btState);
        SoftBusFree(btState);
        return;
    }
    LnnMonitorHbStateChangedEvent event = {.basic.event = LNN_EVENT_BT_STATE_CHANGED, .status = (uint8_t)(*btState)};
    NotifyEvent((const LnnEventBasicInfo *)&event);
    SoftBusFree(btState);
}

void LnnNotifyScreenLockStateChangeEvent(SoftBusScreenLockState state)
{
    if (state < SOFTBUS_SCREEN_LOCK || state >= SOFTBUS_SCREEN_LOCK_UNKNOWN) {
        LNN_LOGE(LNN_EVENT, "bad lockState=%{public}d", state);
        return;
    }
    LnnMonitorHbStateChangedEvent event = {.basic.event = LNN_EVENT_SCREEN_LOCK_CHANGED, .status = state};
    NotifyEvent((const LnnEventBasicInfo *)&event);
}

void LnnNotifyAccountStateChangeEvent(void *state)
{
    SoftBusAccountState *accountState = (SoftBusAccountState *)state;
    if (*accountState < SOFTBUS_ACCOUNT_LOG_IN || *accountState >= SOFTBUS_ACCOUNT_UNKNOWN) {
        LNN_LOGE(LNN_EVENT, "bad accountState=%{public}d", *accountState);
        SoftBusFree(accountState);
        return;
    }
    LnnMonitorHbStateChangedEvent event = {.basic.event = LNN_EVENT_ACCOUNT_CHANGED,
        .status = (uint8_t)(*accountState)};
    NotifyEvent((const LnnEventBasicInfo *)&event);
    SoftBusFree(accountState);
}

void LnnNotifyDifferentAccountChangeEvent(void *state)
{
    SoftBusDifferentAccountState *difAccountState = (SoftBusDifferentAccountState *)state;
    if (*difAccountState < SOFTBUS_DIF_ACCOUNT_DEV_CHANGE || *difAccountState >= SOFTBUS_DIF_ACCOUNT_UNKNOWN) {
        LNN_LOGE(LNN_EVENT, "bad difAccountState=%{public}d", *difAccountState);
        SoftBusFree(difAccountState);
        return;
    }
    LnnMonitorHbStateChangedEvent event = {.basic.event = LNN_EVENT_DIF_ACCOUNT_DEV_CHANGED,
        .status = (uint8_t)(*difAccountState)};
    NotifyEvent((const LnnEventBasicInfo *)&event);
    SoftBusFree(difAccountState);
}

void LnnNotifyUserStateChangeEvent(SoftBusUserState state)
{
    if (state < SOFTBUS_USER_FOREGROUND || state >= SOFTBUS_USER_UNKNOWN) {
        LNN_LOGE(LNN_EVENT, "bad backgroundtState=%{public}d", state);
        return;
    }
    LnnMonitorHbStateChangedEvent event = {.basic.event = LNN_EVENT_USER_STATE_CHANGED, .status = state};
    NotifyEvent((const LnnEventBasicInfo *)&event);
}

void LnnNotifyNightModeStateChangeEvent(void *state)
{
    SoftBusNightModeState *nightModeState = (SoftBusNightModeState *)state;
    if (*nightModeState < SOFTBUS_NIGHT_MODE_ON || *nightModeState >= SOFTBUS_NIGHT_MODE_UNKNOWN) {
        LNN_LOGE(LNN_EVENT, "bad nightModeState=%{public}d", *nightModeState);
        SoftBusFree(nightModeState);
        return;
    }
    LnnMonitorHbStateChangedEvent event = {.basic.event = LNN_EVENT_NIGHT_MODE_CHANGED,
        .status = (uint8_t)(*nightModeState)};
    NotifyEvent((const LnnEventBasicInfo *)&event);
    SoftBusFree(nightModeState);
}

void LnnNotifyHomeGroupChangeEvent(SoftBusHomeGroupState state)
{
    LNN_LOGI(LNN_EVENT, "notify home group change");
    LnnMonitorHbStateChangedEvent event = {.basic.event = LNN_EVENT_HOME_GROUP_CHANGED, .status = (uint8_t)state};
    NotifyEvent((const LnnEventBasicInfo *)&event);
}

void LnnNotifyOOBEStateChangeEvent(SoftBusOOBEState state)
{
    if (state < SOFTBUS_OOBE_RUNNING || state >= SOFTBUS_OOBE_UNKNOWN) {
        LNN_LOGW(LNN_EVENT, "bad OOBEState=%{public}d", state);
        return;
    }
    LnnMonitorHbStateChangedEvent event = {.basic.event = LNN_EVENT_OOBE_STATE_CHANGED, .status = state};
    NotifyEvent((const LnnEventBasicInfo *)&event);
}

void LnnNotifyBtAclStateChangeEvent(const char *btMac, SoftBusBtAclState state)
{
    if (btMac == NULL) {
        LNN_LOGW(LNN_EVENT, "invalid btMac, state=%{public}d", state);
        return;
    }
    char *anonyMac = NULL;
    Anonymize(btMac, &anonyMac);
    LNN_LOGI(LNN_EVENT, "notify bt acl state changed: state=%{public}d, btMac=%{public}s.", state, anonyMac);
    AnonymizeFree(anonyMac);
    LnnMonitorBtAclStateChangedEvent event = {.basic.event = LNN_EVENT_BT_ACL_STATE_CHANGED, .status = state};
    if (strcpy_s(event.btMac, sizeof(event.btMac), btMac) != EOK) {
        LNN_LOGE(LNN_EVENT, "copy bt mac fail");
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
            LNN_LOGE(LNN_EVENT, "copy ifName failed! ret=%{public}d", ret);
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

void LnnNotifyNodeAddressChanged(const char *addr, const char *networkId, bool isLocal)
{
    if (addr == NULL) {
        return;
    }

    LnnNodeAddrChangedEvent eventInfo;
    (void)memset_s(&eventInfo, sizeof(eventInfo), 0, sizeof(eventInfo));
    eventInfo.basic.event = LNN_EVENT_NODE_ADDR_CHANGED;
    if (strcpy_s(eventInfo.addr, sizeof(eventInfo.addr), addr) != EOK ||
        strcpy_s(eventInfo.networkId, NETWORK_ID_BUF_LEN, networkId) != EOK) {
        return;
    }
    if (strcmp(addr, NODE_ADDR_LOOPBACK) == 0) {
        eventInfo.delFlag = true;
    } else {
        eventInfo.delFlag = false;
    }
    eventInfo.isLocal = isLocal;
    NotifyEvent((LnnEventBasicInfo *)&eventInfo);
}

void LnnNotifyHBRepeat(void)
{
    LnnEventBasicInfo event;
    event.event = LNN_EVENT_NODE_HB_REPEAT_CYCLE;

    NotifyEvent(&event);
}

void LnnNotifyNetworkStateChanged(SoftBusNetworkState state)
{
    if (state < SOFTBUS_WIFI_NETWORKD_ENABLE || state >= SOFTBUS_NETWORKD_UNKNOWN) {
        LNN_LOGW(LNN_EVENT, "bad network state=%{public}d", state);
        return;
    }
    LnnMonitorHbStateChangedEvent event = {.basic.event = LNN_EVENT_NETWORK_STATE_CHANGED, .status = state};
    NotifyEvent((const LnnEventBasicInfo *)&event);
}

void LnnNotifySingleOffLineEvent(const ConnectionAddr *addr, NodeBasicInfo *basicInfo)
{
    if (addr == NULL || basicInfo == NULL) {
        LNN_LOGW(LNN_EVENT, "addr or basicInfo is null");
        return;
    }
    LnnSingleNetworkOffLineEvent event = {.basic.event = LNN_EVENT_SINGLE_NETWORK_OFFLINE, .type = addr->type};
    event.basic.event = LNN_EVENT_SINGLE_NETWORK_OFFLINE;
    event.type = addr->type;
    event.udid = "";
    event.uuid = "";
    event.networkId = basicInfo->networkId;
    NotifyEvent((const LnnEventBasicInfo *)&event);
}

void LnnNotifyNetworkIdChangeEvent(const char *networkId)
{
    if (networkId == NULL) {
        LNN_LOGW(LNN_EVENT, "networkId is null");
        return;
    }
    LnnNetworkIdChangedEvent eventInfo;
    (void)memset_s(&eventInfo, sizeof(eventInfo), 0, sizeof(eventInfo));
    eventInfo.basic.event = LNN_EVENT_NETWORKID_CHANGED;
    if (strcpy_s(eventInfo.networkId, NETWORK_ID_BUF_LEN, networkId) != EOK) {
        return;
    }
    NotifyEvent((LnnEventBasicInfo *)&eventInfo);
}

int32_t LnnInitBusCenterEvent(void)
{
    int32_t i;
    SoftBusLooper *looper = CreateNewLooper("NotifyLooper");
    if (looper == NULL) {
        LNN_LOGE(LNN_EVENT, "create notify looper fail");
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
        LNN_LOGW(LNN_EVENT, "invalid event handler params");
        return SOFTBUS_INVALID_PARAM;
    }
    if (SoftBusMutexLock(&g_eventCtrl.lock) != 0) {
        LNN_LOGE(LNN_EVENT, "lock failed in register event handler");
        return SOFTBUS_LOCK_ERR;
    }
    if (IsRepeatEventHandler(event, handler)) {
        LNN_LOGE(LNN_EVENT, "handler is already exist. event=%{public}u", event);
        (void)SoftBusMutexUnlock(&g_eventCtrl.lock);
        return SOFTBUS_INVALID_PARAM;
    }
    item = CreateEventHandlerItem(handler);
    if (item == NULL) {
        LNN_LOGE(LNN_EVENT, "create event handler item failed");
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
    LnnEventHandlerItem *next = NULL;

    if (event == LNN_EVENT_TYPE_MAX || handler == NULL) {
        LNN_LOGW(LNN_EVENT, "invalid event handler params");
        return;
    }
    if (SoftBusMutexLock(&g_eventCtrl.lock) != 0) {
        LNN_LOGE(LNN_EVENT, "hold lock failed in unregister event handler");
        return;
    }
    LIST_FOR_EACH_ENTRY_SAFE(item, next, &g_eventCtrl.handlers[event], LnnEventHandlerItem, node) {
        if (item->handler == handler) {
            ListDelete(&item->node);
            SoftBusFree(item);
            break;
        }
    }
    (void)SoftBusMutexUnlock(&g_eventCtrl.lock);
}
