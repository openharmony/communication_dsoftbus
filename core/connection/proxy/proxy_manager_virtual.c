/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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
#include "proxy_manager.h"

#include "softbus_error_code.h"

static uint32_t GenerateRequestId(void)
{
    return 0;
}

static int32_t OpenProxyChannel(ProxyChannelParam *param, const OpenProxyChannelCallback *callback)
{
    (void)param;
    (void)callback;
    return SOFTBUS_CONN_PROXY_NOT_SUPPORT_ERR;
}

static int32_t RegisterProxyChannelListener(ProxyConnectListener *listener)
{
    (void)listener;
    return SOFTBUS_CONN_PROXY_NOT_SUPPORT_ERR;
}

static struct ProxyConnection *GetProxyChannelByChannelId(uint32_t channelId)
{
    (void)channelId;
    return NULL;
}

static ProxyChannelManager g_proxyChannelManager = {
    .generateRequestId = GenerateRequestId,
    .openProxyChannel = OpenProxyChannel,
    .registerProxyChannelListener = RegisterProxyChannelListener,

    .getConnectionById = GetProxyChannelByChannelId,
    .proxyChannelRequestInfo = NULL,
    .proxyConnectionList = NULL,
};

ProxyChannelManager *GetProxyChannelManager(void)
{
    return &g_proxyChannelManager;
}

int32_t ProxyChannelManagerInit(void)
{
    return SOFTBUS_OK;
}