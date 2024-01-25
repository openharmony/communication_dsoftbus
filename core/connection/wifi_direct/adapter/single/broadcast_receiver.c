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
#include "conn_log.h"
#include "softbus_error_code.h"
#include "softbus_adapter_mem.h"
#include "wifi_direct_p2p_adapter.h"
#include "utils/wifi_direct_work_queue.h"

struct ActionListenerNode {
    ListNode node;
    BroadcastListener listener;
    char name[32];
    enum ListenerPriority priority;
};

static void RegisterBroadcastListener(const enum BroadcastReceiverAction *actionArray, size_t actionSize,
                                      const char *name, enum ListenerPriority priority, BroadcastListener listener)
{
    struct BroadcastReceiver *broadcastReceiver = GetBroadcastReceiver();
    for (size_t i = 0; i < actionSize; i++) {
        struct ActionListenerNode *actionListenerNode =
            (struct ActionListenerNode *)SoftBusCalloc(sizeof(*actionListenerNode));
        CONN_CHECK_AND_RETURN_LOGE(actionListenerNode, CONN_WIFI_DIRECT, "alloc action listener node failed");
        enum BroadcastReceiverAction action = actionArray[i];

        ListInit(&actionListenerNode->node);
        actionListenerNode->priority = priority;
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
    for (int32_t priority = LISTENER_PRIORITY_HIGH; priority >= LISTENER_PRIORITY_LOW; priority--) {
        LIST_FOR_EACH_ENTRY(actionListenerNode, actionListenerList, struct ActionListenerNode, node) {
            if (actionListenerNode->priority == priority && actionListenerNode->listener) {
                actionListenerNode->listener(param->action, param);
            }
        }
    }

    if (param->action == WIFI_P2P_CONNECTION_CHANGED_ACTION && param->p2pParam.groupInfo != NULL) {
        SoftBusFree(param->p2pParam.groupInfo);
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

static void WifiDirectP2pStateChangeCallback(P2pState state)
{
    struct BroadcastParam *param = (struct BroadcastParam *)SoftBusCalloc(sizeof(struct BroadcastParam));
    CONN_CHECK_AND_RETURN_LOGE(param != NULL, CONN_WIFI_DIRECT, "alloc failed");

    param->action = WIFI_P2P_STATE_CHANGED_ACTION;
    param->p2pParam.p2pState = state;

    if (CallMethodAsync(DispatchWorkHandler, param, 0) != SOFTBUS_OK) {
        SoftBusFree(param);
    }
}

static void WifiDirectP2pConnectionChangeCallback(const WifiP2pLinkedInfo info)
{
    struct BroadcastParam *param = (struct BroadcastParam *)SoftBusCalloc(sizeof(struct BroadcastParam));
    CONN_CHECK_AND_RETURN_LOGE(param != NULL, CONN_WIFI_DIRECT, "alloc failed");

    param->action = WIFI_P2P_CONNECTION_CHANGED_ACTION;
    param->p2pParam.p2pLinkInfo = info;
    param->p2pParam.groupInfo = NULL;
    (void)GetWifiDirectP2pAdapter()->getGroupInfo(&param->p2pParam.groupInfo);

    if (CallMethodAsync(DispatchWorkHandler, param, 0) != SOFTBUS_OK) {
        if (param->p2pParam.groupInfo != NULL) {
            SoftBusFree(param->p2pParam.groupInfo);
        }
        SoftBusFree(param);
    }
}

int32_t BroadcastReceiverInit(void)
{
    CONN_LOGI(CONN_INIT, "init enter");
    for (size_t i = 0; i < BROADCAST_RECEIVER_ACTION_MAX; i++) {
        ListInit(g_broadcastReceiver.listeners + i);
    }

    WifiErrorCode ret = RegisterP2pStateChangedCallback(WifiDirectP2pStateChangeCallback);
    CONN_CHECK_AND_RETURN_RET_LOGW(ret == WIFI_SUCCESS, SOFTBUS_ERR, CONN_INIT,
        "register p2p state change callback failed, ret=%{public}d", ret);

    ret = RegisterP2pConnectionChangedCallback(WifiDirectP2pConnectionChangeCallback);
    CONN_CHECK_AND_RETURN_RET_LOGW(ret == WIFI_SUCCESS, SOFTBUS_ERR, CONN_INIT,
        "register p2p connection change callback failed, ret=%{public}d", ret);

    g_broadcastReceiver.isInited = true;
    return SOFTBUS_OK;
}