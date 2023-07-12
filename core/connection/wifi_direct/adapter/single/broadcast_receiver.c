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

#include "broadcast_receiver.h"
#include <string.h>
#include "securec.h"
#include "softbus_log.h"
#include "softbus_error_code.h"
#include "softbus_adapter_mem.h"
#include "wifi_direct_p2p_adapter.h"
#include "utils/wifi_direct_work_queue.h"

#define LOG_LABEL "[WifiDirect] BroadcastReceiver: "

struct ActionListenerNode {
    ListNode node;
    BroadcastListener listener;
    char name[32];
};

static void RegisterBroadcastListener(const enum BroadcastReceiverAction *actionArray, size_t actionSize,
                                      const char *name, BroadcastListener listener)
{
    struct BroadcastReceiver *broadcastReceiver = GetBroadcastReceiver();
    for (size_t i = 0; i < actionSize; i++) {
        struct ActionListenerNode *actionListenerNode =
            (struct ActionListenerNode *)SoftBusCalloc(sizeof(*actionListenerNode));
        CONN_CHECK_AND_RETURN_LOG(actionListenerNode, LOG_LABEL "alloc action listener node failed");
        enum BroadcastReceiverAction action = actionArray[i];

        ListInit(&actionListenerNode->node);
        actionListenerNode->listener = listener;
        strcpy_s(actionListenerNode->name, sizeof(actionListenerNode->name), name);
        ListTailInsert(&broadcastReceiver->listeners[action], &actionListenerNode->node);
    }
}

static void DispatchWorkHandler(void *data)
{
    struct BroadcastParam *param = (struct BroadcastParam *)data;
    struct BroadcastReceiver *broadcastReceiver = GetBroadcastReceiver();
    struct ListNode *actionListenerList = &broadcastReceiver->listeners[param->action];
    struct ActionListenerNode *actionListenerNode = NULL;
    LIST_FOR_EACH_ENTRY(actionListenerNode, actionListenerList, struct ActionListenerNode, node) {
        if (actionListenerNode->listener) {
            actionListenerNode->listener(param->action, param);
        }
    }

    if (param->action == WIFI_P2P_CONNECTION_CHANGED_ACTION && param->changedInfo.groupInfo != NULL) {
        SoftBusFree(param->changedInfo.groupInfo);
    }
    SoftBusFree(param);
}

static struct BroadcastReceiver g_broadcastReceiver = {
    .registerBroadcastListener = RegisterBroadcastListener,
    .isInited = false,
};

struct BroadcastReceiver* GetBroadcastReceiver(void)
{
    return &g_broadcastReceiver;
}

static void P2pStateChangeHandler(P2pState state)
{
    struct BroadcastParam *param = (struct BroadcastParam *)SoftBusCalloc(sizeof(struct BroadcastParam));
    CONN_CHECK_AND_RETURN_LOG(param, LOG_LABEL "alloc failed");
    param->action = WIFI_P2P_STATE_CHANGED_ACTION;
    param->p2pState = state;
    if (CallMethodAsync(DispatchWorkHandler, param, 0) != SOFTBUS_OK) {
        SoftBusFree(param);
    }
}

static void P2pConnectionChangeHandler(const WifiP2pLinkedInfo info)
{
    struct BroadcastParam *param = (struct BroadcastParam *)SoftBusCalloc(sizeof(struct BroadcastParam));
    CONN_CHECK_AND_RETURN_LOG(param, LOG_LABEL "alloc failed");
    param->action = WIFI_P2P_CONNECTION_CHANGED_ACTION;
    (void)memcpy_s(&param->changedInfo.p2pLinkInfo, sizeof(WifiP2pLinkedInfo), &info, sizeof(WifiP2pLinkedInfo));
    param->changedInfo.groupInfo = NULL;
    (void)GetWifiDirectP2pAdapter()->getGroupInfo(&param->changedInfo.groupInfo);
    if (CallMethodAsync(DispatchWorkHandler, param, 0) != SOFTBUS_OK) {
        if (param->changedInfo.groupInfo) {
            SoftBusFree(param->changedInfo.groupInfo);
        }
        SoftBusFree(param);
    }
}

static void WifiDirectOnWifiConnectionChanged(int state, WifiLinkedInfo *info)
{
    CLOGI(LOG_LABEL "state: %d, freq: %d, connect state: %d", state, info->frequency, info->connState);
    struct BroadcastParam *param = (struct BroadcastParam *)SoftBusCalloc(sizeof(struct BroadcastParam));
    CONN_CHECK_AND_RETURN_LOG(param, LOG_LABEL "alloc failed");
    param->action = WIFI_CFG_CHANGED_ACTION;
    param->wifiConnectChangedState = state;
    if (CallMethodAsync(DispatchWorkHandler, param, 0) != SOFTBUS_OK) {
        SoftBusFree(param);
    }
}

static WifiEvent g_event = {
    .OnWifiConnectionChanged = WifiDirectOnWifiConnectionChanged,
};

int32_t BroadcastReceiverInit(void)
{
    for (size_t i = 0; i < BROADCAST_RECEIVER_ACTION_MAX; i++) {
        ListInit(g_broadcastReceiver.listeners + i);
    }

    WifiErrorCode ret = RegisterP2pStateChangedCallback(P2pStateChangeHandler);
    if (ret != WIFI_SUCCESS) {
        CLOGE(LOG_LABEL "RegisterP2pStateChangedCallback failed, error code=%d", ret);
        return SOFTBUS_ERR;
    }

    ret = RegisterP2pConnectionChangedCallback(P2pConnectionChangeHandler);
    if (ret != WIFI_SUCCESS) {
        CLOGE(LOG_LABEL "RegisterP2pConnectionChangedCallback failed, error code=%d", ret);
        return SOFTBUS_ERR;
    }

    (void)UnRegisterWifiEvent(&g_event);
    ret = RegisterWifiEvent(&g_event);
    CONN_CHECK_AND_RETURN_RET_LOG(ret == WIFI_SUCCESS, ret,
        LOG_LABEL "register wifi event failed, error code=%d", ret);

    g_broadcastReceiver.isInited = true;
    return SOFTBUS_OK;
}