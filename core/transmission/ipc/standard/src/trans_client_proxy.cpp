/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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

#include <unistd.h>

#include "softbus_access_token_adapter.h"
#include "softbus_client_info_manager.h"
#include "softbus_def.h"
#include "softbus_error_code.h"
#include "softbus_trans_def.h"
#include "trans_client_proxy_standard.h"
#include "trans_log.h"

using namespace OHOS;

static sptr<TransClientProxy> GetClientProxy(const char *pkgName, int32_t pid)
{
    if (pkgName == nullptr) {
        TRANS_LOGE(TRANS_CTRL, "pkgName is null");
        return nullptr;
    }
    sptr<IRemoteObject> clientObject = SoftbusClientInfoManager::GetInstance().GetSoftbusClientProxy(pkgName, pid);
    sptr<TransClientProxy> clientProxy = new (std::nothrow) TransClientProxy(clientObject);
    return clientProxy;
}

int32_t InformPermissionChange(int32_t state, const char *pkgName, int32_t pid)
{
    if (pkgName == nullptr) {
        TRANS_LOGE(TRANS_CTRL, "pkgName is null");
        return SOFTBUS_INVALID_PKGNAME;
    }
    sptr<TransClientProxy> clientProxy = GetClientProxy(pkgName, pid);
    if (clientProxy == nullptr) {
        TRANS_LOGE(TRANS_CTRL, "softbus client proxy is nullptr!");
        return SOFTBUS_TRANS_GET_CLIENT_PROXY_NULL;
    }
    return clientProxy->OnClientPermissonChange(pkgName, state);
}

void RegisterPermissionChangeCallback(void)
{
    SoftBusRegisterPermissionChangeCb(InformPermissionChange);
}

int32_t ClientIpcOnChannelOpened(const char *pkgName, const char *sessionName,
    const ChannelInfo *channel, int32_t pid)
{
    if (pid == getpid()) {
        ISessionListener object;
        if (SoftbusClientInfoManager::GetInstance().GetSoftbusInnerObject(pkgName, &object) != SOFTBUS_OK) {
            return SOFTBUS_NOT_FIND;
        }
        return object.OnSessionOpened(channel->channelId, SOFTBUS_OK);
    }
    sptr<TransClientProxy> clientProxy = GetClientProxy(pkgName, pid);
    if (clientProxy == nullptr) {
        TRANS_LOGE(TRANS_CTRL, "softbus client proxy is nullptr!");
        return SOFTBUS_TRANS_GET_CLIENT_PROXY_NULL;
    }
    return clientProxy->OnChannelOpened(sessionName, channel);
}

int32_t ClientIpcOnChannelBind(ChannelMsg *data)
{
    if (data == nullptr) {
        TRANS_LOGE(TRANS_CTRL, "ClientIpcOnChannelBind data is nullptr!");
        return SOFTBUS_INVALID_PARAM;
    }
    if (data->msgPid == getpid()) {
        TRANS_LOGI(TRANS_CTRL, "check msgPid success!");
        return SOFTBUS_OK;
    }
    sptr<TransClientProxy> clientProxy = GetClientProxy(data->msgPkgName, data->msgPid);
    if (clientProxy == nullptr) {
        TRANS_LOGE(TRANS_CTRL, "softbus client proxy is nullptr, msgPkgName=%{public}s, msgPid=%{public}d",
            data->msgPkgName, data->msgPid);
        return SOFTBUS_TRANS_GET_CLIENT_PROXY_NULL;
    }
    return clientProxy->OnChannelBind(data->msgChannelId, data->msgChannelType);
}

int32_t ClientIpcOnChannelOpenFailed(ChannelMsg *data, int32_t errCode)
{
    if (data == nullptr) {
        TRANS_LOGE(TRANS_CTRL, "ClientIpcOnChannelOpenFailed data is nullptr!");
        return SOFTBUS_INVALID_PARAM;
    }
    if (data->msgPid == getpid()) {
        ISessionListener object;
        if (SoftbusClientInfoManager::GetInstance().GetSoftbusInnerObject(data->msgPkgName, &object) != SOFTBUS_OK) {
            return SOFTBUS_NOT_FIND;
        }
        return object.OnSessionOpened(data->msgChannelId, errCode);
    }
    sptr<TransClientProxy> clientProxy = GetClientProxy(data->msgPkgName, data->msgPid);
    if (clientProxy == nullptr) {
        TRANS_LOGE(TRANS_CTRL, "softbus client proxy is nullptr!");
        return SOFTBUS_TRANS_GET_CLIENT_PROXY_NULL;
    }
    clientProxy->OnChannelOpenFailed(data->msgChannelId, data->msgChannelType, errCode);
    return SOFTBUS_OK;
}

int32_t ClientIpcOnChannelLinkDown(ChannelMsg *data, const char *networkId, const char *peerIp, int32_t routeType)
{
    if (data == nullptr || networkId == nullptr) {
        TRANS_LOGE(TRANS_CTRL, "ClientIpcOnChannelLinkDown data or networkId is nullptr!");
        return SOFTBUS_INVALID_PARAM;
    }
    (void)peerIp;
    sptr<TransClientProxy> clientProxy = GetClientProxy(data->msgPkgName, data->msgPid);
    if (clientProxy == nullptr) {
        TRANS_LOGE(TRANS_CTRL, "softbus client proxy is nullptr!");
        return SOFTBUS_TRANS_GET_CLIENT_PROXY_NULL;
    }
    clientProxy->OnChannelLinkDown(networkId, routeType);
    return SOFTBUS_OK;
}

int32_t ClientIpcOnChannelClosed(ChannelMsg *data)
{
    if (data == nullptr) {
        TRANS_LOGE(TRANS_CTRL, "ClientIpcOnChannelClosed data is nullptr!");
        return SOFTBUS_TRANS_GET_CLIENT_PROXY_NULL;
    }
    if (data->msgPid == getpid()) {
        ISessionListener object;
        if (SoftbusClientInfoManager::GetInstance().GetSoftbusInnerObject(data->msgPkgName, &object) != SOFTBUS_OK) {
            return SOFTBUS_NOT_FIND;
        }
        object.OnSessionClosed(data->msgChannelId);
        return SOFTBUS_OK;
    }
    sptr<TransClientProxy> clientProxy = GetClientProxy(data->msgPkgName, data->msgPid);
    if (clientProxy == nullptr) {
        TRANS_LOGE(TRANS_CTRL, "softbus client proxy is nullptr!");
        return SOFTBUS_TRANS_GET_CLIENT_PROXY_NULL;
    }
    int32_t ret = clientProxy->OnChannelClosed(data->msgChannelId, data->msgChannelType, data->msgMessageType);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "OnChannelClosed failed, ret=%{public}d", ret);
        return ret;
    }
    return SOFTBUS_OK;
}

int32_t ClientIpcSetChannelInfo(
    const char *pkgName, const char *sessionName, int32_t sessionId, const TransInfo *transInfo, int32_t pid)
{
    if (pkgName == nullptr || sessionName == nullptr || transInfo == nullptr) {
        TRANS_LOGE(TRANS_CTRL, "Invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    sptr<TransClientProxy> clientProxy = GetClientProxy(pkgName, pid);
    if (clientProxy == nullptr) {
        TRANS_LOGE(TRANS_CTRL, "Softbus client proxy is nullptr!, pkgName=%{public}s pid=%{public}d", pkgName, pid);
        return SOFTBUS_TRANS_GET_CLIENT_PROXY_NULL;
    }
    int32_t ret = clientProxy->SetChannelInfo(sessionName, sessionId, transInfo->channelId, transInfo->channelType);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "SetChannelInfo failed, ret=%{public}d", ret);
        return ret;
    }
    return SOFTBUS_OK;
}

int32_t ClientIpcOnChannelMsgReceived(ChannelMsg *data, TransReceiveData *receiveData)
{
    if (data == nullptr || receiveData == nullptr) {
        TRANS_LOGE(TRANS_CTRL, "ClientIpcOnChannelMsgReceived data or receiveData is nullptr!");
        return SOFTBUS_INVALID_PARAM;
    }
    if (data->msgPid == getpid()) {
        ISessionListener object;
        if (SoftbusClientInfoManager::GetInstance().GetSoftbusInnerObject(data->msgPkgName, &object) != SOFTBUS_OK) {
            return SOFTBUS_NOT_FIND;
        }
        object.OnBytesReceived(data->msgChannelId, receiveData->data, receiveData->dataLen);
        return SOFTBUS_OK;
    }
    sptr<TransClientProxy> clientProxy = GetClientProxy(data->msgPkgName, data->msgPid);
    if (clientProxy == nullptr) {
        TRANS_LOGE(TRANS_CTRL, "softbus client proxy is nullptr!");
        return SOFTBUS_TRANS_GET_CLIENT_PROXY_NULL;
    }
    clientProxy->OnChannelMsgReceived(data->msgChannelId, data->msgChannelType,
        receiveData->data, receiveData->dataLen, receiveData->dataType);
    return SOFTBUS_OK;
}

int32_t ClientIpcOnChannelQosEvent(const char *pkgName, const QosParam *param)
{
    sptr<TransClientProxy> clientProxy = GetClientProxy(pkgName, param->pid);
    if (clientProxy == nullptr) {
        TRANS_LOGE(TRANS_CTRL, "softbus client proxy is nullptr!");
        return SOFTBUS_TRANS_GET_CLIENT_PROXY_NULL;
    }
    clientProxy->OnChannelQosEvent(param->channelId, param->channelType, param->eventId,
        param->tvCount, param->tvList);
    return SOFTBUS_OK;
}

int32_t ClientIpcOnTransLimitChange(const char *pkgName, int32_t pid, int32_t channelId, uint8_t tos)
{
    if (pkgName == nullptr) {
        TRANS_LOGE(TRANS_SDK, "invalid param.");
        return SOFTBUS_INVALID_PARAM;
    }
    sptr<TransClientProxy> clientProxy = GetClientProxy(pkgName, pid);
    if (clientProxy == nullptr) {
        TRANS_LOGE(TRANS_SDK, "softbus client proxy is nullptr!");
        return SOFTBUS_TRANS_GET_CLIENT_PROXY_NULL;
    }
    
    return clientProxy->OnClientTransLimitChange(channelId, tos);
}

int32_t CheckServiceIsRegistered(const char *pkgName, int32_t pid)
{
    if (pkgName == nullptr) {
        TRANS_LOGE(TRANS_SDK, "invalid param.");
        return SOFTBUS_INVALID_PARAM;
    }
    sptr<IRemoteObject> clientObject = SoftbusClientInfoManager::GetInstance().GetSoftbusClientProxy(pkgName, pid);
    if (clientObject == nullptr) {
        char *anonymizePkgName = nullptr;
        Anonymize(pkgName, &anonymizePkgName);
        TRANS_LOGE(TRANS_SDK, "softbus client proxy is nullptr! pkgname=%{public}s, pid=%{public}d",
            AnonymizeWrapper(anonymizePkgName), pid);
        AnonymizeFree(anonymizePkgName);
        return SOFTBUS_TRANS_GET_CLIENT_PROXY_NULL;
    }
    return SOFTBUS_OK;
}

int32_t ClientIpcChannelOnQos(ChannelMsg *data, QoSEvent event, const QosTV *qos, uint32_t count)
{
    if (data == nullptr || data->msgPkgName == nullptr || qos == nullptr || count == 0 || count >= QOS_TYPE_BUTT) {
        TRANS_LOGE(TRANS_SDK, "invalid param.");
        return SOFTBUS_INVALID_PARAM;
    }
    sptr<TransClientProxy> clientProxy = GetClientProxy(data->msgPkgName, data->msgPid);
    if (clientProxy == nullptr) {
        TRANS_LOGE(TRANS_SDK, "softbus client proxy is nullptr!");
        return SOFTBUS_TRANS_GET_CLIENT_PROXY_NULL;
    }

    return clientProxy->OnClientChannelOnQos(data->msgChannelId, data->msgChannelType, event, qos, count);
}

int32_t ClientIpcCheckCollabRelation(const char *pkgName, int32_t pid,
    const CollabInfo *sourceInfo, const CollabInfo *sinkInfo, const TransInfo *transInfo)
{
    if (pkgName == nullptr || sourceInfo == nullptr || sinkInfo == nullptr || transInfo == nullptr) {
        TRANS_LOGE(TRANS_SDK, "invalid param.");
        return SOFTBUS_INVALID_PARAM;
    }
    sptr<TransClientProxy> clientProxy = GetClientProxy(pkgName, pid);
    if (clientProxy == nullptr) {
        TRANS_LOGE(TRANS_SDK, "softbus client proxy is nullptr!");
        return SOFTBUS_TRANS_GET_CLIENT_PROXY_NULL;
    }
    
    return clientProxy->OnCheckCollabRelation(sourceInfo, sinkInfo, transInfo->channelId, transInfo->channelType);
}
