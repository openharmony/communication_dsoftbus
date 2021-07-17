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

#include "softbus_errcode.h"
#include "softbus_log.h"
#include "softbus_transmission_interface.h"

static INetworkingListener g_netChanlistener = {0};

int32_t NotifyNetworkingChannelOpened(int32_t chanId, const AppInfo *appInfo, unsigned char isServer)
{
    if (g_netChanlistener.onChannelOpened == NULL) {
        LOG_ERR("net onChannelOpened is null");
        return SOFTBUS_ERR;
    }

    if (g_netChanlistener.onChannelOpened(chanId, appInfo->peerData.deviceId, isServer) != SOFTBUS_OK) {
        LOG_ERR("notify channel open fail");
        return SOFTBUS_ERR;
    }

    return SOFTBUS_OK;
}

void NotifyNetworkingChannelOpenFailed(int32_t channelId, const char *networkId)
{
    if (g_netChanlistener.onChannelOpenFailed == NULL) {
        LOG_ERR("net onChannelOpenFailed is null");
        return;
    }
    g_netChanlistener.onChannelOpenFailed(channelId, networkId);
}

void NotifyNetworkingChannelClosed(int32_t chanId)
{
    if (g_netChanlistener.onChannelClosed == NULL) {
        LOG_ERR("net onChannelClosed is null");
        return;
    }
    g_netChanlistener.onChannelClosed(chanId);
}

void NotifyNetworkingMsgReceived(int32_t chanId, const char *data, uint32_t len)
{
    if (g_netChanlistener.onMessageReceived == NULL) {
        return;
    }
    g_netChanlistener.onMessageReceived(chanId, data, len);
}


int32_t TransRegisterNetworkingChannelListener(const INetworkingListener *listener)
{
    if (memcpy_s(&g_netChanlistener, sizeof(INetworkingListener),
        listener, sizeof(INetworkingListener)) != EOK) {
        return SOFTBUS_ERR;
    }

    LOG_INFO("register net listener ok");
    return SOFTBUS_OK;
}
