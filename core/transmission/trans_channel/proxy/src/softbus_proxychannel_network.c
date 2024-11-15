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

#include "softbus_proxychannel_network.h"

#include <securec.h>
#include "softbus_def.h"
#include "softbus_error_code.h"
#include "softbus_proxychannel_manager.h"
#include "softbus_transmission_interface.h"
#include "trans_log.h"

#define MAX_LISTENER_CNT 2

typedef struct {
    char sessionName[SESSION_NAME_SIZE_MAX];
    INetworkingListener listener;
} INetworkingListenerEntry;

static INetworkingListenerEntry g_listeners[MAX_LISTENER_CNT] = { 0 };

static INetworkingListenerEntry *FindListenerEntry(const char *sessionName)
{
    for (int32_t i = 0; i < MAX_LISTENER_CNT; i++) {
        if (strcmp(sessionName, g_listeners[i].sessionName) == 0) {
            return &g_listeners[i];
        }
    }
    return NULL;
}

int32_t NotifyNetworkingChannelOpened(
    const char *sessionName, int32_t channelId, const AppInfo *appInfo, unsigned char isServer)
{
    INetworkingListenerEntry *entry = FindListenerEntry(sessionName);
    if (entry == NULL || entry->listener.onChannelOpened == NULL) {
        TRANS_LOGE(TRANS_CTRL, "net onChannelOpened is null");
        return SOFTBUS_NO_INIT;
    }

    if (entry->listener.onChannelOpened(channelId, appInfo->peerData.deviceId, isServer) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "notify channel open fail");
        return SOFTBUS_TRANS_CHANNEL_OPEN_FAILED;
    }

    return SOFTBUS_OK;
}

void NotifyNetworkingChannelOpenFailed(const char *sessionName, int32_t channelId, const char *networkId)
{
    INetworkingListenerEntry *entry = FindListenerEntry(sessionName);
    if (entry == NULL || entry->listener.onChannelOpenFailed == NULL) {
        TRANS_LOGE(TRANS_CTRL, "net onChannelOpenFailed is null");
        return;
    }
    entry->listener.onChannelOpenFailed(channelId, networkId);
}

void NotifyNetworkingChannelClosed(const char *sessionName, int32_t channelId)
{
    INetworkingListenerEntry *entry = FindListenerEntry(sessionName);
    if (entry == NULL || entry->listener.onChannelClosed == NULL) {
        TRANS_LOGE(TRANS_CTRL, "net onChannelClosed is null");
        return;
    }
    entry->listener.onChannelClosed(channelId);
}

void NotifyNetworkingMsgReceived(const char *sessionName, int32_t channelId, const char *data, uint32_t len)
{
    INetworkingListenerEntry *entry = FindListenerEntry(sessionName);
    if (entry == NULL || entry->listener.onMessageReceived == NULL) {
        return;
    }
    entry->listener.onMessageReceived(channelId, data, len);
}

int TransRegisterNetworkingChannelListener(const char *sessionName, const INetworkingListener *listener)
{
    int32_t unuse = -1;
    for (int32_t i = 0; i < MAX_LISTENER_CNT; i++) {
        if (strlen(g_listeners[i].sessionName) == 0) {
            unuse = i;
            break;
        }
        if (strcmp(sessionName, g_listeners[i].sessionName) == 0) {
            return SOFTBUS_OK;
        }
    }
    if (unuse == -1) {
        TRANS_LOGE(TRANS_CTRL, "exceed max listener registered. maxlisten=%{public}d", MAX_LISTENER_CNT);
        return SOFTBUS_TRANS_REGISTER_LISTENER_FAILED;
    }

    if (strcpy_s(g_listeners[unuse].sessionName, SESSION_NAME_SIZE_MAX, sessionName) != EOK) {
        TRANS_LOGE(TRANS_CTRL, "strcpy_s session name failed");
        return SOFTBUS_STRCPY_ERR;
    }
    g_listeners[unuse].listener = *listener;
    TRANS_LOGI(TRANS_CTRL, "register net listener ok");
    return SOFTBUS_OK;
}
