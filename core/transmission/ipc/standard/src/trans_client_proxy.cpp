/*
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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

#include "trans_client_proxy.h"

#include <chrono>
#include <future>

#include "softbus_client_info_manager.h"
#include "softbus_def.h"
#include "softbus_errcode.h"
#include "softbus_trans_def.h"
#include "trans_client_proxy_standard.h"
#include "trans_log.h"

using namespace OHOS;

constexpr int32_t IPC_OPT_TIMEOUT_S = 10; /* Calling IPC timeout for 10 seconds*/

static sptr<TransClientProxy> GetClientProxy(const char *pkgName, int32_t pid)
{
    if (pkgName == nullptr) {
        TRANS_LOGE(TRANS_SDK, "pkgName is null");
        return nullptr;
    }
    sptr<IRemoteObject> clientObject = SoftbusClientInfoManager::GetInstance().GetSoftbusClientProxy(pkgName, pid);
    sptr<TransClientProxy> clientProxy = new (std::nothrow) TransClientProxy(clientObject);
    return clientProxy;
}

int32_t InformPermissionChange(int32_t state, const char *pkgName, int32_t pid)
{
    if (pkgName == nullptr) {
        TRANS_LOGE(TRANS_SDK, "pkgName is null");
        return SOFTBUS_ERR;
    }
    sptr<TransClientProxy> clientProxy = GetClientProxy(pkgName, pid);
    if (clientProxy == nullptr) {
        TRANS_LOGE(TRANS_SDK, "softbus client proxy is nullptr!");
        return SOFTBUS_ERR;
    }
    return clientProxy->OnClientPermissonChange(pkgName, state);
}

static void CallProxyOnChannelOpened(sptr<TransClientProxy> clientProxy, const char *sessionName,
    const ChannelInfo *channel, int32_t *ret)
{
    *ret = clientProxy->OnChannelOpened(sessionName, channel);
}

int32_t ClientIpcOnChannelOpened(const char *pkgName, const char *sessionName,
    const ChannelInfo *channel, int32_t pid)
{
    sptr<TransClientProxy> clientProxy = GetClientProxy(pkgName, pid);
    if (clientProxy == nullptr) {
        TRANS_LOGE(TRANS_SDK, "softbus client proxy is nullptr!");
        return SOFTBUS_ERR;
    }

    int32_t ret = SOFTBUS_ERR;
    std::future<void> task = std::async([clientProxy, sessionName, channel, &ret]() {
        CallProxyOnChannelOpened(clientProxy, sessionName, channel, &ret);
    });
    if (task.wait_for(std::chrono::seconds(IPC_OPT_TIMEOUT_S)) != std::future_status::ready) {
        TRANS_LOGE(TRANS_SDK, "CallProxyOnChannelOpened timeout!");
        return SOFTBUS_ERR;
    }
    return ret;
}

int32_t ClientIpcOnChannelOpenFailed(ChannelMsg *data, int32_t errCode)
{
    if (data == nullptr) {
        TRANS_LOGE(TRANS_SDK, "ClientIpcOnChannelOpenFailed data is nullptr!");
        return SOFTBUS_ERR;
    }
    sptr<TransClientProxy> clientProxy = GetClientProxy(data->msgPkgName, data->msgPid);
    if (clientProxy == nullptr) {
        TRANS_LOGE(TRANS_SDK, "softbus client proxy is nullptr!");
        return SOFTBUS_ERR;
    }
    clientProxy->OnChannelOpenFailed(data->msgChannelId, data->msgChannelType, errCode);
    return SOFTBUS_OK;
}

int32_t ClientIpcOnChannelLinkDown(ChannelMsg *data, const char *networkId, const char *peerIp, int32_t routeType)
{
    if (data == nullptr || networkId == nullptr) {
        TRANS_LOGE(TRANS_SDK, "ClientIpcOnChannelLinkDown data or networkId is nullptr!");
        return SOFTBUS_ERR;
    }
    (void)peerIp;
    sptr<TransClientProxy> clientProxy = GetClientProxy(data->msgPkgName, data->msgPid);
    if (clientProxy == nullptr) {
        TRANS_LOGE(TRANS_SDK, "softbus client proxy is nullptr!");
        return SOFTBUS_ERR;
    }
    clientProxy->OnChannelLinkDown(networkId, routeType);
    return SOFTBUS_OK;
}

static void CallProxyOnChannelClosed(sptr<TransClientProxy> clientProxy, ChannelMsg *data)
{
    clientProxy->OnChannelClosed(data->msgChannelId, data->msgChannelType);
}

int32_t ClientIpcOnChannelClosed(ChannelMsg *data)
{
    if (data == nullptr) {
        TRANS_LOGE(TRANS_SDK, "ClientIpcOnChannelClosed data is nullptr!");
        return SOFTBUS_ERR;
    }
    sptr<TransClientProxy> clientProxy = GetClientProxy(data->msgPkgName, data->msgPid);
    if (clientProxy == nullptr) {
        TRANS_LOGE(TRANS_SDK, "softbus client proxy is nullptr!");
        return SOFTBUS_ERR;
    }
    std::future<void> task = std::async([clientProxy, data]() {
        CallProxyOnChannelClosed(clientProxy, data);
    });
    if (task.wait_for(std::chrono::seconds(IPC_OPT_TIMEOUT_S)) != std::future_status::ready) {
        TRANS_LOGE(TRANS_SDK, "CallProxyOnChannelClosed timeout!");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int32_t ClientIpcOnChannelMsgReceived(ChannelMsg *data, TransReceiveData *receiveData)
{
    if (data == nullptr || receiveData == nullptr) {
        TRANS_LOGE(TRANS_SDK, "ClientIpcOnChannelMsgReceived data or receiveData is nullptr!");
        return SOFTBUS_ERR;
    }
    sptr<TransClientProxy> clientProxy = GetClientProxy(data->msgPkgName, data->msgPid);
    if (clientProxy == nullptr) {
        TRANS_LOGE(TRANS_SDK, "softbus client proxy is nullptr!");
        return SOFTBUS_ERR;
    }
    clientProxy->OnChannelMsgReceived(data->msgChannelId, data->msgChannelType,
        receiveData->data, receiveData->dataLen, receiveData->dataType);
    return SOFTBUS_OK;
}

int32_t ClientIpcOnChannelQosEvent(const char *pkgName, const QosParam *param)
{
    sptr<TransClientProxy> clientProxy = GetClientProxy(pkgName, param->pid);
    if (clientProxy == nullptr) {
        TRANS_LOGE(TRANS_SDK, "softbus client proxy is nullptr!");
        return SOFTBUS_ERR;
    }
    clientProxy->OnChannelQosEvent(param->channelId, param->channelType, param->eventId,
        param->tvCount, param->tvList);
    return SOFTBUS_OK;
}
