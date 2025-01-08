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
#include "bus_center_event.h"
#include "bus_center_manager.h"
#include "lnn_bus_center_ipc.h"
#include "lnn_cipherkey_manager.h"
#include "lnn_connId_callback_manager.h"
#include "lnn_device_info_recovery.h"
#include "lnn_distributed_net_ledger.h"
#include "lnn_log.h"
#include "lnn_network_id.h"
#include "lnn_p2p_info.h"
#include "lnn_connection_addr_utils.h"
#include "message_handler.h"
#include "softbus_adapter_crypto.h"
#include "softbus_adapter_mem.h"
#include "softbus_adapter_thread.h"
#include "softbus_def.h"
#include "softbus_error_code.h"
#include "softbus_qos.h"

typedef struct {
    ListNode node;
    LnnEventHandler handler;
} LnnEventHandlerItem;

typedef struct {
    ListNode handlers[LNN_EVENT_TYPE_MAX];
    uint32_t regCnt[LNN_EVENT_TYPE_MAX];
    SoftBusMutex lock;
} BusCenterEventCtrl;

typedef enum {
    NOTIFY_ONLINE_STATE_CHANGED = 0,
    NOTIFY_NODE_BASIC_INFO_CHANGED,
    NOTIFY_NODE_STATUS_CHANGED,
    NOTIFY_NETWORKID_UPDATE,
    NOTIFY_LOCAL_NETWORKID_UPDATE,
    NOTIFY_DEVICE_TRUSTED_CHANGED,
    NOTIFY_STATE_SESSION,
} NotifyType;

#define NETWORK_ID_UPDATE_DELAY_TIME (60 * 60 * 1000 * 24) // 24 hour
#define NETWORK_ID_MAX_TTL (7 * 60 * 60 * 1000 * 24) // 7 * 24 hour
#define NETWORK_ID_MIN_UPDATE_DELAY_TIME (5 * 60 * 1000) // 5min

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

static void HandleDeviceTrustedChangedMessage(SoftBusMessage *msg)
{
    if (msg->obj == NULL) {
        LNN_LOGE(LNN_EVENT, "invalid online state message");
        return;
    }
    int32_t type = (int32_t)msg->arg1;
    uint32_t msgLen = (uint32_t)msg->arg2;
    (void)LnnIpcNotifyDeviceTrustedChange(type, (const char*)msg->obj, msgLen);
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

static void HandleNodeStatusChangedMessage(SoftBusMessage *msg)
{
    if (msg->obj == NULL) {
        LNN_LOGE(LNN_EVENT, "invalid node status message");
        return;
    }
    int32_t type = (int32_t)msg->arg1;
    LnnIpcNotifyNodeStatusChanged(msg->obj, sizeof(NodeStatus), type);
}

static void HandleLocalNetworkIdChangedMessage(void)
{
    LnnIpcLocalNetworkIdChanged();
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
    LnnNotifyLocalNetworkIdChanged();
    LnnUpdateAuthExchangeUdid();
    LNN_LOGD(LNN_EVENT, "offline exceted 5min, process networkId update event");
}

static void HandleStateSessionMessage(SoftBusMessage *msg)
{
    if (msg->obj == NULL) {
        LNN_LOGE(LNN_EVENT, "invalid state session message");
        return;
    }
    int32_t retCode = (int32_t)msg->arg1;
    InvokeCallbackForJoinExt((const char *)msg->obj, retCode);
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
        case NOTIFY_NODE_STATUS_CHANGED:
            HandleNodeStatusChangedMessage(msg);
            break;
        case NOTIFY_LOCAL_NETWORKID_UPDATE:
            HandleLocalNetworkIdChangedMessage();
            break;
        case NOTIFY_NETWORKID_UPDATE:
            HandleNetworkUpdateMessage(msg);
            break;
        case NOTIFY_DEVICE_TRUSTED_CHANGED:
            HandleDeviceTrustedChangedMessage(msg);
            break;
        case NOTIFY_STATE_SESSION:
            HandleStateSessionMessage(msg);
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

static NodeStatus *DupNodeStatus(const NodeStatus *nodeStatus)
{
    if (nodeStatus == NULL) {
        LNN_LOGW(LNN_EVENT, "nodeStatus is null");
        return NULL;
    }
    NodeStatus *dupInfo = SoftBusCalloc(sizeof(NodeStatus));
    if (dupInfo == NULL) {
        LNN_LOGE(LNN_EVENT, "malloc NodeStatus err");
        return NULL;
    }
    if (memcpy_s(dupInfo, sizeof(NodeStatus), nodeStatus, sizeof(NodeStatus)) != EOK) {
        LNN_LOGE(LNN_EVENT, "copy NodeStatus fail");
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

static int32_t PostNotifyNodeStatusMessage(int32_t what, uint64_t arg, const NodeStatus *info)
{
    SoftBusMessage *msg = SoftBusCalloc(sizeof(SoftBusMessage));
    if (msg == NULL) {
        LNN_LOGE(LNN_EVENT, "malloc msg err");
        return SOFTBUS_MALLOC_ERR;
    }
    msg->what = what;
    msg->arg1 = arg;
    msg->obj = DupNodeStatus(info);
    if (msg->obj == NULL) {
        LNN_LOGE(LNN_EVENT, "dup NodeStatus err");
        SoftBusFree(msg);
        return SOFTBUS_MEM_ERR;
    }
    msg->handler = &g_notifyHandler;
    msg->FreeMessage = FreeNotifyMessage;
    return PostMessageToHandlerDelay(msg, 0);
}

static char *DupDeviceTrustedChangeMsg(const char *msg)
{
    if (msg == NULL) {
        LNN_LOGW(LNN_EVENT, "msg is null");
        return NULL;
    }
    int32_t len = strlen(msg) + 1;
    char *dupMsg = SoftBusCalloc(len);
    if (dupMsg == NULL) {
        LNN_LOGE(LNN_EVENT, "malloc dupMsg err");
        return NULL;
    }
    if (strcpy_s(dupMsg, len, msg) != EOK) {
        LNN_LOGE(LNN_EVENT, "copy dupMsg fail");
        SoftBusFree(dupMsg);
        return NULL;
    }
    return dupMsg;
}

static int32_t PostNotifyDeviceTrustedChangeMessage(int32_t what, int32_t type, const char *notifyMsg, uint32_t msgLen)
{
    SoftBusMessage *msg = SoftBusCalloc(sizeof(SoftBusMessage));
    if (msg == NULL) {
        LNN_LOGE(LNN_EVENT, "malloc msg err");
        return SOFTBUS_MALLOC_ERR;
    }
    msg->what = what;
    msg->arg1 = (uint64_t)type;
    msg->arg2 = (uint64_t)msgLen;
    msg->obj = DupDeviceTrustedChangeMsg(notifyMsg);
    if (msg->obj == NULL) {
        LNN_LOGE(LNN_EVENT, "dup notifyMsg err");
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

static char *DupUdid(char *udid)
{
    if (udid == NULL) {
        LNN_LOGW(LNN_EVENT, "udid is null");
        return NULL;
    }
    int32_t len = strlen(udid) + 1;
    char *dupMsg = SoftBusCalloc(len);
    if (dupMsg == NULL) {
        LNN_LOGE(LNN_EVENT, "malloc dupMsg err");
        return NULL;
    }
    if (strcpy_s(dupMsg, len, udid) != EOK) {
        LNN_LOGE(LNN_EVENT, "copy dupMsg fail");
        SoftBusFree(dupMsg);
        return NULL;
    }
    return dupMsg;
}

static int32_t PostNotifyMessageWithUdid(int32_t what, char *udid, uint64_t arg1)
{
    SoftBusMessage *msg = SoftBusCalloc(sizeof(SoftBusMessage));
    if (msg == NULL) {
        LNN_LOGE(LNN_EVENT, "malloc msg fail");
        return SOFTBUS_MALLOC_ERR;
    }
    msg->what = what;
    msg->arg1 = arg1;
    msg->obj = DupUdid(udid);
    msg->handler = &g_notifyHandler;
    msg->FreeMessage = FreeNotifyMessage;
    return PostMessageToHandlerDelay(msg, 0);
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
    uint32_t i = 0;

    if (SoftBusMutexLock(&g_eventCtrl.lock) != 0) {
        LNN_LOGE(LNN_EVENT, "lock failed in notify event");
        return;
    }
    uint32_t count = g_eventCtrl.regCnt[info->event];
    LnnEventHandler *handlesArray = (LnnEventHandler *)SoftBusCalloc(sizeof(LnnEventHandlerItem) * count);
    if (handlesArray == NULL) {
        LNN_LOGE(LNN_EVENT, "malloc failed");
        (void)SoftBusMutexUnlock(&g_eventCtrl.lock);
        return;
    }
    LIST_FOR_EACH_ENTRY(item, &g_eventCtrl.handlers[info->event], LnnEventHandlerItem, node) {
        handlesArray[i] = item->handler;
        i++;
    }
    (void)SoftBusMutexUnlock(&g_eventCtrl.lock);

    /* process handles out of lock */
    for (i = 0; i < count; i++) {
        if (handlesArray[i] != NULL) {
            handlesArray[i](info);
        }
    }
    SoftBusFree(handlesArray);
}

void LnnNotifyDeviceVerified(const char *udid)
{
    (void)udid;
    LNN_LOGI(LNN_EVENT, "exist device joining LNN, remove networkId update event");
    RemoveNotifyMessage(NOTIFY_NETWORKID_UPDATE);
}

static uint64_t GetNetworkIdUpdateTime()
{
    int64_t networkIdTimestamp = 0;
    int64_t nowTime = 0;
    uint64_t delayTime = 0;
    nowTime = (int64_t)SoftBusGetSysTimeMs();
    if (LnnGetLocalNum64Info(NUM_KEY_NETWORK_ID_TIMESTAMP, &networkIdTimestamp) != SOFTBUS_OK) {
        LNN_LOGE(LNN_EVENT, "get local networkIdTimestamp fail");
        return NETWORK_ID_UPDATE_DELAY_TIME;
    }
    int64_t diff = networkIdTimestamp + NETWORK_ID_MAX_TTL - nowTime;
    if (diff <= NETWORK_ID_MIN_UPDATE_DELAY_TIME) {
        delayTime = NETWORK_ID_MIN_UPDATE_DELAY_TIME;
    } else if (diff <= NETWORK_ID_UPDATE_DELAY_TIME) {
        delayTime = (uint64_t)diff;
    } else {
        delayTime = NETWORK_ID_UPDATE_DELAY_TIME;
    }
    LNN_LOGI(LNN_EVENT, "networkId update delayTime=%{public}" PRId64 ", nowTime=%{public}" PRId64
        ", networkIdTimestamp=%{public}" PRId64, delayTime, nowTime, networkIdTimestamp);
    return delayTime;
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
    char *anonyDeviceName = NULL;
    Anonymize(info->deviceName, &anonyDeviceName);
    LNN_LOGI(LNN_EVENT, "notify node. deviceName=%{public}s, isOnline=%{public}s, networkId=%{public}s",
        AnonymizeWrapper(anonyDeviceName), (isOnline == true) ? "online" : "offline",
        AnonymizeWrapper(anonyNetworkId));
    AnonymizeFree(anonyNetworkId);
    AnonymizeFree(anonyDeviceName);
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
        RemoveNotifyMessage(NOTIFY_NETWORKID_UPDATE);
        (void)PostNotifyMessageDelay(NOTIFY_NETWORKID_UPDATE, GetNetworkIdUpdateTime());
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
        char *anonyDeviceName = NULL;
        Anonymize(info->deviceName, &anonyDeviceName);
        LNN_LOGI(LNN_EVENT, "notify peer device name changed. deviceName=%{public}s",
            AnonymizeWrapper(anonyDeviceName));
        AnonymizeFree(anonyDeviceName);
    }
    (void)PostNotifyMessage(NOTIFY_NODE_BASIC_INFO_CHANGED, (uint64_t)type, info);
}

void LnnNotifyNodeStatusChanged(NodeStatus *info, NodeStatusType type)
{
    if (info == NULL) {
        LNN_LOGW(LNN_EVENT, "info = null");
        return;
    }
    (void)PostNotifyNodeStatusMessage(NOTIFY_NODE_STATUS_CHANGED, (uint64_t)type, info);
}

void LnnNotifyLocalNetworkIdChanged(void)
{
    (void)PostNotifyMessageDelay(NOTIFY_LOCAL_NETWORKID_UPDATE, 0);
}

void LnnNotifyStateForSession(char *udid, int32_t retCode)
{
    if (udid == NULL) {
        LNN_LOGE(LNN_EVENT, "udid is null");
        return;
    }
    (void)PostNotifyMessageWithUdid(NOTIFY_STATE_SESSION, udid, retCode);
}

void LnnNotifyDeviceTrustedChange(int32_t type, const char *msg, uint32_t msgLen)
{
    if (msg == NULL || msgLen == 0) {
        LNN_LOGE(LNN_EVENT, "msg is null");
        return;
    }
    PostNotifyDeviceTrustedChangeMessage(NOTIFY_DEVICE_TRUSTED_CHANGED, type, msg, msgLen);
}

void LnnNotifyHichainProofException(
    const char *proofInfo, uint32_t proofLen, uint16_t deviceTypeId, int32_t errCode)
{
    (void)LnnIpcNotifyHichainProofException(proofInfo, proofLen, deviceTypeId, errCode);
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

void LnnNotifyWlanStateChangeEvent(void *state)
{
    if (state == NULL) {
        LNN_LOGE(LNN_EVENT, "state is empty");
        return;
    }
    SoftBusWifiState *wifiState = (SoftBusWifiState *)state;
    if (*wifiState < SOFTBUS_WIFI_CONNECTED || *wifiState > SOFTBUS_WIFI_UNKNOWN) {
        LNN_LOGE(LNN_EVENT, "bad wifiState=%{public}d", *wifiState);
        SoftBusFree(wifiState);
        return;
    }
    LnnMonitorWlanStateChangedEvent event = {.basic.event = LNN_EVENT_WIFI_STATE_CHANGED,
        .status = (uint8_t)(*wifiState)};
    NotifyEvent((const LnnEventBasicInfo *)&event);
    SoftBusFree(wifiState);
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

void LnnNotifyVapInfoChangeEvent(int32_t preferChannel)
{
    LnnLaneVapChangeEvent event = {.basic.event = LNN_EVENT_LANE_VAP_CHANGE, .vapPreferChannel = preferChannel};
    NotifyEvent((const LnnEventBasicInfo *)&event);
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

void LnnNotifyDataShareStateChangeEvent(SoftBusDataShareState state)
{
    if (state < SOFTBUS_DATA_SHARE_READY || state >= SOFTBUS_DATA_SHARE_UNKNOWN) {
        LNN_LOGE(LNN_EVENT, "bad lockState=%{public}d", state);
        return;
    }
    LnnMonitorHbStateChangedEvent event = {.basic.event = LNN_EVENT_DATA_SHARE_STATE_CHANGE, .status = state};
    NotifyEvent((const LnnEventBasicInfo *)&event);
}

void LnnNotifyAccountStateChangeEvent(SoftBusAccountState state)
{
    if (state < SOFTBUS_ACCOUNT_LOG_IN || state >= SOFTBUS_ACCOUNT_UNKNOWN) {
        LNN_LOGE(LNN_EVENT, "bad accountState=%{public}d", state);
        return;
    }
    LnnMonitorHbStateChangedEvent event = {.basic.event = LNN_EVENT_ACCOUNT_CHANGED,
        .status = (uint8_t)state};
    NotifyEvent((const LnnEventBasicInfo *)&event);
}

void LnnNotifyUserSwitchEvent(SoftBusUserSwitchState state)
{
    if (state < SOFTBUS_USER_SWITCHED || state >= SOFTBUS_USER_SWITCH_UNKNOWN) {
        LNN_LOGE(LNN_EVENT, "bad userSwitchState=%{public}d", state);
        return;
    }
    LnnMonitorHbStateChangedEvent event = {.basic.event = LNN_EVENT_USER_SWITCHED,
        .status = (uint8_t)state};
    NotifyEvent((const LnnEventBasicInfo *)&event);
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
    LNN_LOGI(LNN_EVENT, "notify OOBE state change");
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
    LNN_LOGI(LNN_EVENT, "notify bt acl state changed: state=%{public}d, btMac=%{public}s.",
        state, AnonymizeWrapper(anonyMac));
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
    NodeInfo info;
    (void)memset_s(&info, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    if (LnnGetRemoteNodeInfoById(basicInfo->networkId, CATEGORY_NETWORK_ID, &info) == SOFTBUS_OK) {
        if ((LnnHasDiscoveryType(&info, DISCOVERY_TYPE_WIFI) &&
            LnnConvAddrTypeToDiscType(addr->type) == DISCOVERY_TYPE_WIFI)) {
            LNN_LOGI(LNN_EVENT, "Two-way WIFI LNN not completely offline, not need to report offline");
            return;
        }
    }
    LnnSingleNetworkOffLineEvent event = {.basic.event = LNN_EVENT_SINGLE_NETWORK_OFFLINE, .type = addr->type};
    event.basic.event = LNN_EVENT_SINGLE_NETWORK_OFFLINE;
    event.type = addr->type;
    event.udid = "";
    event.uuid = "";
    event.networkId = basicInfo->networkId;
    NotifyEvent((const LnnEventBasicInfo *)&event);
}

void LnnNotifyLpReportEvent(SoftBusLpEventType type)
{
    if (type < SOFTBUS_MSDP_MOVEMENT_AND_STATIONARY || type >= SOFTBUS_LP_EVENT_UNKNOWN) {
        LNN_LOGW(LNN_EVENT, "bad lp event type=%{public}d", type);
        return;
    }
    LnnLpReportEvent event = {.basic.event = LNN_EVENT_LP_EVENT_REPORT, .type = type};
    NotifyEvent((const LnnEventBasicInfo *) &event);
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

void LnnNotifyOnlineNetType(const char *networkId, ConnectionAddrType addrType)
{
    if (networkId == NULL) {
        LNN_LOGW(LNN_EVENT, "networkId is null");
        return;
    }
    LnnNodeNetTypeInfo eventInfo;
    (void)memset_s(&eventInfo, sizeof(eventInfo), 0, sizeof(eventInfo));
    char *anonyNetworkId = NULL;
    Anonymize(networkId, &anonyNetworkId);
    LNN_LOGI(LNN_EVENT, "notify online netType, networkId=%{public}s", AnonymizeWrapper(anonyNetworkId));
    AnonymizeFree(anonyNetworkId);
    eventInfo.basic.event = LNN_EVENT_NODE_NET_TYPE;
    eventInfo.addrType = addrType;
    eventInfo.networkId = networkId;
    NotifyEvent((LnnEventBasicInfo *)&eventInfo);
}

void LnnNotifyDeviceInfoChanged(SoftBusDeviceInfoState state)
{
    if (state < SOFTBUS_LOCAL_DEVICE_INFO_ACOUNT_CHANGED || state >= SOFTBUS_LOCAL_DEVICE_INFO_UNKNOWN) {
        LNN_LOGW(LNN_EVENT, "bad deviceInfo state=%{public}d", state);
        return;
    }
    LNN_LOGI(LNN_EVENT, "notify deviceInfo state change");
    LnnDeviceInfoChangeEvent event = {.basic.event = LNN_EVENT_DEVICE_INFO_CHANGED, .status = state};
    NotifyEvent((const LnnEventBasicInfo *)&event);
}

void LnnNotifyNetlinkStateChangeEvent(NetManagerIfNameState state, const char *ifName)
{
    LNN_LOGD(LNN_EVENT, "notify net link state change");
    if (state < SOFTBUS_NETMANAGER_IFNAME_START || state >= SOFTBUS_NETMANAGER_IFNAME_UNKNOWN) {
        LNN_LOGW(LNN_EVENT, "bad OOBEState=%{public}d", state);
        return;
    }
    LnnMonitorNetlinkStateInfo event = {.basic.event = LNN_EVENT_NET_LINK_STATE_CHANGE, .status = state};
    if (ifName != NULL) {
        int32_t ret = strcpy_s(event.ifName, sizeof(event.ifName), ifName);
        if (ret != EOK) {
            LNN_LOGE(LNN_EVENT, "copy ifName failed with ret=%{public}d", ret);
            return;
        }
    }
    NotifyEvent((const LnnEventBasicInfo *)&event);
}

int32_t LnnInitBusCenterEvent(void)
{
    int32_t i;
    SoftBusLooper *looper = CreateNewLooper("Notify_Lp");
    if (looper == NULL) {
        LNN_LOGE(LNN_EVENT, "create notify looper fail");
        return SOFTBUS_LOOPER_ERR;
    }
    g_notifyHandler.looper = looper;
    g_notifyHandler.HandleMessage = HandleNotifyMessage;

    SoftBusMutexAttr mutexAttr;
    mutexAttr.type = SOFTBUS_MUTEX_RECURSIVE;
    SoftBusMutexInit(&g_eventCtrl.lock, &mutexAttr);
    for (i = 0; i < LNN_EVENT_TYPE_MAX; ++i) {
        ListInit(&g_eventCtrl.handlers[i]);
        g_eventCtrl.regCnt[i] = 0;
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
    g_eventCtrl.regCnt[event]++;
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
            if (g_eventCtrl.regCnt[event] > 0) {
                g_eventCtrl.regCnt[event]--;
            }
            break;
        }
    }
    (void)SoftBusMutexUnlock(&g_eventCtrl.lock);
}
