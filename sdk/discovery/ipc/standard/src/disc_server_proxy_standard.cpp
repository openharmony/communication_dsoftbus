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

#include "disc_server_proxy_standard.h"

#include "ipc_skeleton.h"
#include "system_ability_definition.h"

#include "discovery_service.h"
#include "message_parcel.h"
#include "softbus_errcode.h"
#include "softbus_ipc_def.h"
#include "softbus_log.h"

namespace OHOS {
static uint32_t g_getSystemAbilityId = 2;
static sptr<IRemoteObject> GetSystemAbility()
{
    MessageParcel data;
    data.WriteInt32(SOFTBUS_SERVER_SA_ID);
    MessageParcel reply;
    MessageOption option;
    sptr<IRemoteObject> samgr = IPCSkeleton::GetContextObject();
    int32_t err = samgr->SendRequest(g_getSystemAbilityId, data, reply, option);
    if (err != 0) {
        LOG_ERR("Get GetSystemAbility failed!\n");
        return nullptr;
    }
    return reply.ReadRemoteObject();
}

int32_t DiscServerProxy::StartDiscovery(const char *pkgName, const SubscribeInfo *subInfo)
{
    sptr<IRemoteObject> remote = GetSystemAbility();
    if (remote == nullptr) {
        SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_ERROR, "remote is nullptr!");
        return SOFTBUS_ERR;
    }

    MessageParcel data;

    data.WriteCString(pkgName);
    data.WriteInt32(subInfo->subscribeId);
    data.WriteInt32(subInfo->mode);
    data.WriteInt32(subInfo->medium);
    data.WriteInt32(subInfo->freq);
    data.WriteBool(subInfo->isSameAccount);
    data.WriteBool(subInfo->isWakeRemote);
    data.WriteCString(subInfo->capability);
    data.WriteUint32(subInfo->dataLen);
    if (subInfo->dataLen != 0) {
        data.WriteCString((char *)subInfo->capabilityData);
    }
    MessageParcel reply;
    MessageOption option;
    int32_t err = remote->SendRequest(SERVER_START_DISCOVERY, data, reply, option);
    if (err != 0) {
        SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_ERROR, "StartDiscovery send request failed!");
        return SOFTBUS_ERR;
    }
    int32_t serverRet = 0;
    int32_t ret = reply.ReadInt32(serverRet);
    if (!ret) {
        SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_ERROR, "StartDiscovery read serverRet failed!");
        return SOFTBUS_ERR;
    }
    return serverRet;
}

int32_t DiscServerProxy::StopDiscovery(const char *pkgName, int subscribeId)
{
    sptr<IRemoteObject> remote = GetSystemAbility();
    if (remote == nullptr) {
        SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_ERROR, "remote is nullptr!");
        return SOFTBUS_ERR;
    }

    MessageParcel data;

    data.WriteCString(pkgName);
    data.WriteInt32(subscribeId);

    MessageParcel reply;
    MessageOption option;
    int32_t err = remote->SendRequest(SERVER_STOP_DISCOVERY, data, reply, option);
    SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_ERROR, "StopDiscovery send request ret = %d!", err);
    if (err != 0) {
        SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_ERROR, "StopDiscovery send request failed!");
        return SOFTBUS_ERR;
    }
    int32_t serverRet = 0;
    int32_t ret = reply.ReadInt32(serverRet);
    if (!ret) {
        SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_ERROR, "StopDiscovery read serverRet failed!");
        return SOFTBUS_ERR;
    }
    return serverRet;
}

int32_t DiscServerProxy::PublishService(const char *pkgName, const PublishInfo *pubInfo)
{
    sptr<IRemoteObject> remote = GetSystemAbility();
    if (remote == nullptr) {
        SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_ERROR, "remote is nullptr!");
        return SOFTBUS_ERR;
    }

    MessageParcel data;

    data.WriteCString(pkgName);
    data.WriteInt32(pubInfo->publishId);
    data.WriteInt32(pubInfo->mode);
    data.WriteInt32(pubInfo->medium);
    data.WriteInt32(pubInfo->freq);
    data.WriteCString(pubInfo->capability);
    data.WriteUint32(pubInfo->dataLen);
    if (pubInfo->dataLen != 0) {
        data.WriteCString((char *)pubInfo->capabilityData);
    }
    MessageParcel reply;
    MessageOption option;
    int32_t err = remote->SendRequest(SERVER_PUBLISH_SERVICE, data, reply, option);
    SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_ERROR, "PublishService send request ret = %d!", err);
    if (err != 0) {
        SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_ERROR, "PublishService send request failed!");
        return SOFTBUS_ERR;
    }
    int32_t serverRet = 0;
    int32_t ret = reply.ReadInt32(serverRet);
    if (!ret) {
        SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_ERROR, "PublishService read serverRet failed!");
        return SOFTBUS_ERR;
    }
    return serverRet;
}

int32_t DiscServerProxy::UnPublishService(const char *pkgName, int publishId)
{
    sptr<IRemoteObject> remote = GetSystemAbility();
    if (remote == nullptr) {
        SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_ERROR, "remote is nullptr!");
        return SOFTBUS_ERR;
    }

    MessageParcel data;

    data.WriteCString(pkgName);
    data.WriteInt32(publishId);

    MessageParcel reply;
    MessageOption option;
    int32_t err = remote->SendRequest(SERVER_UNPUBLISH_SERVICE, data, reply, option);
    SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_ERROR, "UnPublishService send request ret = %d!", err);
    if (err != 0) {
        SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_ERROR, "UnPublishService send request failed!");
        return SOFTBUS_ERR;
    }
    int32_t serverRet = 0;
    int32_t ret = reply.ReadInt32(serverRet);
    if (!ret) {
        SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_ERROR, "UnPublishService read serverRet failed!");
        return SOFTBUS_ERR;
    }
    return serverRet;
}

int32_t DiscServerProxy::SoftbusRegisterService(const char *clientPkgName, const sptr<IRemoteObject>& object)
{
    return SOFTBUS_OK;
}

int32_t DiscServerProxy::CreateSessionServer(const char *pkgName, const char *sessionName)
{
    return SOFTBUS_OK;
}

int32_t DiscServerProxy::RemoveSessionServer(const char *pkgName, const char *sessionName)
{
    return SOFTBUS_OK;
}

int32_t DiscServerProxy::OpenSession(const SessionParam* param, TransInfo* info)
{
    return SOFTBUS_OK;
}

int32_t DiscServerProxy::OpenAuthSession(const char *sessionName, const ConnectionAddr *addrInfo)
{
    return SOFTBUS_OK;
}

int32_t DiscServerProxy::NotifyAuthSuccess(int32_t channelId)
{
    return SOFTBUS_OK;
}

int32_t DiscServerProxy::CloseChannel(int32_t channelId, int32_t channelType)
{
    return SOFTBUS_OK;
}

int32_t DiscServerProxy::SendMessage(int32_t channelId, int32_t channelType, const void *data,
    uint32_t len, int32_t msgType)
{
    return SOFTBUS_OK;
}

int32_t DiscServerProxy::JoinLNN(const char *pkgName, void *addr, uint32_t addrTypeLen)
{
    return SOFTBUS_OK;
}

int32_t DiscServerProxy::LeaveLNN(const char *pkgName, const char *networkId)
{
    return SOFTBUS_OK;
}

int32_t DiscServerProxy::GetAllOnlineNodeInfo(const char *pkgName, void **info, uint32_t infoTypeLen, int *infoNum)
{
    return SOFTBUS_OK;
}

int32_t DiscServerProxy::GetLocalDeviceInfo(const char *pkgName, void *info, uint32_t infoTypeLen)
{
    return SOFTBUS_OK;
}
int32_t DiscServerProxy::GetNodeKeyInfo(const char *pkgName, const char *networkId, int key, unsigned char *buf,
    uint32_t len)
{
    return SOFTBUS_OK;
}

int32_t DiscServerProxy::StartTimeSync(const char *pkgName, const char *targetNetworkId, int32_t accuracy,
    int32_t period)
{
    return SOFTBUS_OK;
}

int32_t DiscServerProxy::StopTimeSync(const char *pkgName, const char *targetNetworkId)
{
    return SOFTBUS_OK;
}
}
