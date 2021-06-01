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

#include "softbus_interface.h"

#include "softbus_def.h"
#include "softbus_errcode.h"
#include "softbus_log.h"
#include "softbus_permission.h"
#include "softbus_server.h"
#include "system_ability_definition.h"

using namespace OHOS;

static sptr<ISoftBusClient> GetClientProxy(const char *pkgName)
{
    sptr<SoftBusServer> softbusServer = SoftBusServer::GetInstance();
    if (softbusServer == nullptr) {
        LOG_ERR("softbusServer is nullptr!\n");
        return nullptr;
    }
    sptr<ISoftBusClient> clientProxy = softbusServer->GetSoftbusClientProxy(pkgName);
    return clientProxy;
}

static int ClientIpcOnDeviceFound(const char *pkgName, const void *device)
{
    sptr<ISoftBusClient> clientProxy = GetClientProxy(pkgName);
    if (clientProxy == nullptr) {
        LOG_ERR("softbus client proxy is nullptr!\n");
        return SOFTBUS_ERR;
    }
    clientProxy->OnDeviceFound(device);
    return SOFTBUS_OK;
}

static int ClientIpcOnDiscoverFailed(const char *pkgName, int subscribeId, int failReason)
{
    sptr<ISoftBusClient> clientProxy = GetClientProxy(pkgName);
    if (clientProxy == nullptr) {
        LOG_ERR("softbus client proxy is nullptr!\n");
        return SOFTBUS_ERR;
    }
    clientProxy->OnDiscoverFailed(subscribeId, failReason);
    return SOFTBUS_OK;
}

static int ClientIpcOnDiscoverySuccess(const char *pkgName, int subscribeId)
{
    sptr<ISoftBusClient> clientProxy = GetClientProxy(pkgName);
    if (clientProxy == nullptr) {
        LOG_ERR("softbus client proxy is nullptr!\n");
        return SOFTBUS_ERR;
    }
    clientProxy->OnDiscoverySuccess(subscribeId);
    return SOFTBUS_OK;
}

static int ClientIpcOnPublishSuccess(const char *pkgName, int publishId)
{
    sptr<ISoftBusClient> clientProxy = GetClientProxy(pkgName);
    if (clientProxy == nullptr) {
        LOG_ERR("softbus client proxy is nullptr!\n");
        return SOFTBUS_ERR;
    }
    clientProxy->OnPublishSuccess(publishId);
    return SOFTBUS_OK;
}

static int ClientIpcOnPublishFail(const char *pkgName, int publishId, int reason)
{
    sptr<ISoftBusClient> clientProxy = GetClientProxy(pkgName);
    if (clientProxy == nullptr) {
        LOG_ERR("softbus client proxy is nullptr!\n");
        return SOFTBUS_ERR;
    }
    clientProxy->OnPublishFail(publishId, reason);
    return SOFTBUS_OK;
}

static int ClientIpcOnChannelOpened(const char *pkgName, const char *sessionName, const ChannelInfo *channel)
{
    sptr<ISoftBusClient> clientProxy = GetClientProxy(pkgName);
    if (clientProxy == nullptr) {
        LOG_ERR("softbus client proxy is nullptr!\n");
        return SOFTBUS_ERR;
    }
    clientProxy->OnChannelOpened(pkgName, sessionName, channel);
    return SOFTBUS_OK;
}

static int ClientIpcOnChannelOpenFailed(const char *pkgName, int32_t channelId)
{
    sptr<ISoftBusClient> clientProxy = GetClientProxy(pkgName);
    if (clientProxy == nullptr) {
        LOG_ERR("softbus client proxy is nullptr!\n");
        return SOFTBUS_ERR;
    }
    clientProxy->OnChannelOpenFailed(pkgName, channelId);
    return SOFTBUS_OK;
}

static int ClientIpcOnChannelClosed(const char *pkgName, int32_t channelId)
{
    sptr<ISoftBusClient> clientProxy = GetClientProxy(pkgName);
    if (clientProxy == nullptr) {
        LOG_ERR("softbus client proxy is nullptr!\n");
        return SOFTBUS_ERR;
    }
    clientProxy->OnChannelClosed(pkgName, channelId);
    return SOFTBUS_OK;
}

static int ClientIpcOnChannelMsgReceived(const char *pkgName, int32_t channelId, const void *data,
    uint32_t len, int32_t type)
{
    sptr<ISoftBusClient> clientProxy = GetClientProxy(pkgName);
    if (clientProxy == nullptr) {
        LOG_ERR("softbus client proxy is nullptr!\n");
        return SOFTBUS_ERR;
    }
    clientProxy->OnChannelMsgReceived(pkgName, channelId, data, len, type);
    return SOFTBUS_OK;
}

static int ClientOnJoinLNNResult(const char *pkgName, void *addr, uint32_t addrTypeLen,
    const char *networkId, int32_t retCode)
{
    if (pkgName == nullptr) {
        LOG_ERR("pkgName is null");
        return SOFTBUS_ERR;
    }
    sptr<ISoftBusClient> clientProxy = GetClientProxy(pkgName);
    if (clientProxy == nullptr) {
        LOG_ERR("softbus client proxy is nullptr!\n");
        return SOFTBUS_ERR;
    }
    return clientProxy->OnJoinLNNResult(addr, addrTypeLen, networkId, retCode);
}

static int ClientOnLeaveLNNResult(const char *pkgName, const char *networkId, int32_t retCode)
{
    if (pkgName == nullptr) {
        LOG_ERR("pkgName is null");
        return SOFTBUS_ERR;
    }
    sptr<ISoftBusClient> clientProxy = GetClientProxy(pkgName);
    if (clientProxy == nullptr) {
        LOG_ERR("softbus client proxy is nullptr!\n");
        return SOFTBUS_ERR;
    }
    return clientProxy->OnLeaveLNNResult(networkId, retCode);
}

static int ClinetOnNodeOnlineStateChanged(bool isOnline, void *info, uint32_t infoTypeLen)
{
    sptr<SoftBusServer> softbusServer = SoftBusServer::GetInstance();
    if (softbusServer == nullptr) {
        LOG_ERR("softbusServer is nullptr!\n");
        return SOFTBUS_ERR;
    }
    std::map<std::string, sptr<ISoftBusClient>> proxyMap;
    softbusServer->GetSoftbusClientProxyMap(proxyMap);
    for (auto proxy : proxyMap) {
        if (!CheckBusCenterPermission(proxy.first.c_str())) {
            continue;
        }
        proxy.second->OnNodeOnlineStateChanged(isOnline, info, infoTypeLen);
    }
    return SOFTBUS_OK;
}

static int ClinetOnNodeBasicInfoChanged(void *info, uint32_t infoTypeLen, int32_t type)
{
    sptr<SoftBusServer> softbusServer = SoftBusServer::GetInstance();
    if (softbusServer == nullptr) {
        LOG_ERR("softbusServer is nullptr!\n");
        return SOFTBUS_ERR;
    }
    std::map<std::string, sptr<ISoftBusClient>> proxyMap;
    softbusServer->GetSoftbusClientProxyMap(proxyMap);
    for (auto proxy : proxyMap) {
        if (!CheckBusCenterPermission(proxy.first.c_str())) {
            continue;
        }
        proxy.second->OnNodeBasicInfoChanged(info, infoTypeLen, type);
    }
    return SOFTBUS_OK;
}

static struct ClientProvideInterface g_clientProvideInterface = {
    .onDeviceFound = ClientIpcOnDeviceFound,
    .onDiscoverySuccess = ClientIpcOnDiscoverySuccess,
    .onDiscoverFailed = ClientIpcOnDiscoverFailed,
    .onPublishSuccess = ClientIpcOnPublishSuccess,
    .onPublishFail = ClientIpcOnPublishFail,
    .onChannelOpened = ClientIpcOnChannelOpened,
    .onChannelOpenFailed = ClientIpcOnChannelOpenFailed,
    .onChannelClosed = ClientIpcOnChannelClosed,
    .onChannelMsgReceived = ClientIpcOnChannelMsgReceived,
    .onJoinLNNResult = ClientOnJoinLNNResult,
    .onLeaveLNNResult = ClientOnLeaveLNNResult,
    .onNodeOnlineStateChanged = ClinetOnNodeOnlineStateChanged,
    .onNodeBasicInfoChanged = ClinetOnNodeBasicInfoChanged,
};

struct ClientProvideInterface *GetClientProvideInterface(void)
{
    return &g_clientProvideInterface;
}