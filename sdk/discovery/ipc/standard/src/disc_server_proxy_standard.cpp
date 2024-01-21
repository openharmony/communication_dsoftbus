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

#include "disc_server_proxy_standard.h"

#include "ipc_skeleton.h"
#include "disc_log.h"
#include "discovery_service.h"
#include "message_parcel.h"
#include "softbus_errcode.h"
#include "softbus_server_ipc_interface_code.h"

namespace OHOS {
static uint32_t g_getSystemAbilityId = 2;
const std::u16string SAMANAGER_INTERFACE_TOKEN = u"ohos.samgr.accessToken";
static sptr<IRemoteObject> GetSystemAbility()
{
    MessageParcel data;

    if (!data.WriteInterfaceToken(SAMANAGER_INTERFACE_TOKEN)) {
        DISC_LOGE(DISC_SDK, "Write Interface token failed!");
        return nullptr;
    }
    if (!data.WriteInt32(SOFTBUS_SERVER_SA_ID_INNER)) {
        DISC_LOGE(DISC_SDK, "Write inner failed!");
        return nullptr;
    }
    MessageParcel reply;
    MessageOption option;
    sptr<IRemoteObject> samgr = IPCSkeleton::GetContextObject();
    if (samgr == nullptr) {
        DISC_LOGE(DISC_SDK, "samgr failed!");
        return nullptr;
    }
    int32_t err = samgr->SendRequest(g_getSystemAbilityId, data, reply, option);
    if (err != 0) {
        DISC_LOGE(DISC_SDK, "GetSystemAbility failed!");
        return nullptr;
    }
    return reply.ReadRemoteObject();
}

int32_t DiscServerProxy::StartDiscovery(const char *pkgName, const SubscribeInfo *subInfo)
{
    sptr<IRemoteObject> remote = GetSystemAbility();
    if (remote == nullptr) {
        DISC_LOGE(DISC_ABILITY, "remote is nullptr!");
        return SOFTBUS_ERR;
    }

    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        DISC_LOGE(DISC_SDK, "StartDiscovery faceToken failed!");
        return SOFTBUS_ERR;
    }
    if (!data.WriteCString(pkgName)) {
        DISC_LOGE(DISC_SDK, "StartDiscovery pkgName failed!");
        return SOFTBUS_ERR;
    }
    if (!data.WriteInt32(subInfo->subscribeId)) {
        DISC_LOGE(DISC_SDK, "StartDiscovery subInfo subscribeId failed!");
        return SOFTBUS_ERR;
    }
    if (!data.WriteInt32(subInfo->mode)) {
        DISC_LOGE(DISC_SDK, "StartDiscovery subInfo mode failed!");
        return SOFTBUS_ERR;
    }
    if (!data.WriteInt32(subInfo->medium)) {
        DISC_LOGE(DISC_SDK, "StartDiscovery subInfo medium failed!");
        return SOFTBUS_ERR;
    }
    if (!data.WriteInt32(subInfo->freq)) {
        DISC_LOGE(DISC_SDK, "StartDiscovery subInfo freq failed!");
        return SOFTBUS_ERR;
    }
    if (!data.WriteBool(subInfo->isSameAccount)) {
        DISC_LOGE(DISC_SDK, "StartDiscovery subInfo isSameAccount failed!");
        return SOFTBUS_ERR;
    }
    if (!data.WriteBool(subInfo->isWakeRemote)) {
        DISC_LOGE(DISC_SDK, "StartDiscovery subInfo isWakeRemote failed!");
        return SOFTBUS_ERR;
    }
    if (!data.WriteCString(subInfo->capability)) {
        DISC_LOGE(DISC_SDK, "StartDiscovery subInfo capability failed!");
        return SOFTBUS_ERR;
    }
    if (!data.WriteUint32(subInfo->dataLen)) {
        DISC_LOGE(DISC_SDK, "StartDiscovery subInfo dataLen failed!");
        return SOFTBUS_ERR;
    }
    if (subInfo->dataLen != 0) {
        data.WriteCString((char *)subInfo->capabilityData);
    }
    MessageParcel reply;
    MessageOption option;
    int32_t err = remote->SendRequest(SERVER_START_DISCOVERY, data, reply, option);
    if (err != 0) {
        DISC_LOGE(DISC_SDK, "StartDiscovery send request failed!");
        return SOFTBUS_ERR;
    }
    int32_t serverRet = 0;
    int32_t ret = reply.ReadInt32(serverRet);
    if (!ret) {
        DISC_LOGE(DISC_SDK, "StartDiscovery read serverRet failed!");
        return SOFTBUS_ERR;
    }
    return serverRet;
}

int32_t DiscServerProxy::StopDiscovery(const char *pkgName, int subscribeId)
{
    sptr<IRemoteObject> remote = GetSystemAbility();
    if (remote == nullptr) {
        DISC_LOGE(DISC_ABILITY, "remote is nullptr!");
        return SOFTBUS_ERR;
    }

    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        DISC_LOGE(DISC_SDK, "StopDiscovery failed!");
        return SOFTBUS_ERR;
    }
    if (!data.WriteCString(pkgName)) {
        DISC_LOGE(DISC_SDK, "StopDiscovery pkgName failed!");
        return SOFTBUS_ERR;
    }
    if (!data.WriteInt32(subscribeId)) {
        DISC_LOGE(DISC_SDK, "StopDiscovery subscribeId failed!");
        return SOFTBUS_ERR;
    }

    MessageParcel reply;
    MessageOption option;
    int32_t err = remote->SendRequest(SERVER_STOP_DISCOVERY, data, reply, option);
    DISC_LOGI(DISC_ABILITY, "StopDiscovery send request ret=%{public}d!", err);
    if (err != 0) {
        DISC_LOGE(DISC_SDK, "StopDiscovery send request failed!");
        return SOFTBUS_ERR;
    }
    int32_t serverRet = 0;
    int32_t ret = reply.ReadInt32(serverRet);
    if (!ret) {
        DISC_LOGE(DISC_SDK, "StopDiscovery read serverRet failed!");
        return SOFTBUS_ERR;
    }
    return serverRet;
}

int32_t DiscServerProxy::PublishService(const char *pkgName, const PublishInfo *pubInfo)
{
    sptr<IRemoteObject> remote = GetSystemAbility();
    if (remote == nullptr) {
        DISC_LOGE(DISC_ABILITY, "remote is nullptr!");
        return SOFTBUS_ERR;
    }

    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        DISC_LOGE(DISC_SDK, "PublishService write InterfaceToken failed!");
        return SOFTBUS_ERR;
    }
    if (!data.WriteCString(pkgName)) {
        DISC_LOGE(DISC_SDK, "PublishService write pkgName failed!");
        return SOFTBUS_ERR;
    }
    if (!data.WriteInt32(pubInfo->publishId)) {
        DISC_LOGE(DISC_SDK, "PublishService write publishId failed!");
        return SOFTBUS_ERR;
    }
    if (!data.WriteInt32(pubInfo->mode)) {
        DISC_LOGE(DISC_SDK, "PublishService write mode failed!");
        return SOFTBUS_ERR;
    }
    if (!data.WriteInt32(pubInfo->medium)) {
        DISC_LOGE(DISC_SDK, "PublishService write medium failed!");
        return SOFTBUS_ERR;
    }
    if (!data.WriteInt32(pubInfo->freq)) {
        DISC_LOGE(DISC_SDK, "PublishService write freq failed!");
        return SOFTBUS_ERR;
    }
    if (!data.WriteCString(pubInfo->capability)) {
        DISC_LOGE(DISC_SDK, "PublishService write capability failed!");
        return SOFTBUS_ERR;
    }
    if (!data.WriteUint32(pubInfo->dataLen)) {
        DISC_LOGE(DISC_SDK, "PublishService write dataLen failed!");
        return SOFTBUS_ERR;
    }
    if (pubInfo->dataLen != 0) {
        data.WriteCString((char *)pubInfo->capabilityData);
    }
    MessageParcel reply;
    MessageOption option;
    int32_t err = remote->SendRequest(SERVER_PUBLISH_SERVICE, data, reply, option);
    DISC_LOGI(DISC_ABILITY, "PublishService send request ret=%{public}d!", err);
    if (err != 0) {
        DISC_LOGE(DISC_SDK, "PublishService send request failed!");
        return SOFTBUS_ERR;
    }
    int32_t serverRet = 0;
    int32_t ret = reply.ReadInt32(serverRet);
    if (!ret) {
        DISC_LOGE(DISC_SDK, "PublishService read serverRet failed!");
        return SOFTBUS_ERR;
    }
    return serverRet;
}

int32_t DiscServerProxy::UnPublishService(const char *pkgName, int publishId)
{
    sptr<IRemoteObject> remote = GetSystemAbility();
    if (remote == nullptr) {
        DISC_LOGE(DISC_ABILITY, "remote is nullptr!");
        return SOFTBUS_ERR;
    }

    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        DISC_LOGE(DISC_SDK, "UnPublishService failed!");
        return SOFTBUS_ERR;
    }
    if (!data.WriteCString(pkgName)) {
        DISC_LOGE(DISC_SDK, "UnPublishService pkgName failed!");
        return SOFTBUS_ERR;
    }
    if (!data.WriteInt32(publishId)) {
        DISC_LOGE(DISC_SDK, "UnPublishService publishId failed!");
        return SOFTBUS_ERR;
    }

    MessageParcel reply;
    MessageOption option;
    int32_t err = remote->SendRequest(SERVER_UNPUBLISH_SERVICE, data, reply, option);
    DISC_LOGI(DISC_SDK, "UnPublishService send request ret=%{public}d!", err);
    if (err != 0) {
        DISC_LOGE(DISC_SDK, "UnPublishService send request failed!");
        return SOFTBUS_ERR;
    }
    int32_t serverRet = 0;
    int32_t ret = reply.ReadInt32(serverRet);
    if (!ret) {
        DISC_LOGE(DISC_SDK, "UnPublishService read serverRet failed!");
        return SOFTBUS_ERR;
    }
    return serverRet;
}

int32_t DiscServerProxy::SoftbusRegisterService(const char *clientPkgName, const sptr<IRemoteObject>& object)
{
    (void)clientPkgName;
    (void)object;
    return SOFTBUS_OK;
}

int32_t DiscServerProxy::CreateSessionServer(const char *pkgName, const char *sessionName)
{
    (void)pkgName;
    (void)sessionName;
    return SOFTBUS_OK;
}

int32_t DiscServerProxy::RemoveSessionServer(const char *pkgName, const char *sessionName)
{
    (void)pkgName;
    (void)sessionName;
    return SOFTBUS_OK;
}

int32_t DiscServerProxy::OpenSession(const SessionParam *param, TransInfo *info)
{
    (void)param;
    (void)info;
    return SOFTBUS_OK;
}

int32_t DiscServerProxy::OpenAuthSession(const char *sessionName, const ConnectionAddr *addrInfo)
{
    (void)sessionName;
    (void)addrInfo;
    return SOFTBUS_OK;
}

int32_t DiscServerProxy::NotifyAuthSuccess(int32_t channelId, int32_t channelType)
{
    (void)channelId;
    (void)channelType;
    return SOFTBUS_OK;
}

int32_t DiscServerProxy::CloseChannel(int32_t channelId, int32_t channelType)
{
    (void)channelId;
    (void)channelType;
    return SOFTBUS_OK;
}

int32_t DiscServerProxy::SendMessage(int32_t channelId, int32_t channelType, const void *data,
    uint32_t len, int32_t msgType)
{
    (void)channelId;
    (void)channelType;
    (void)data;
    (void)len;
    (void)msgType;
    return SOFTBUS_OK;
}

int32_t DiscServerProxy::JoinLNN(const char *pkgName, void *addr, uint32_t addrTypeLen)
{
    (void)pkgName;
    (void)addr;
    (void)addrTypeLen;
    return SOFTBUS_OK;
}

int32_t DiscServerProxy::LeaveLNN(const char *pkgName, const char *networkId)
{
    (void)pkgName;
    (void)networkId;
    return SOFTBUS_OK;
}

int32_t DiscServerProxy::GetAllOnlineNodeInfo(const char *pkgName, void **info, uint32_t infoTypeLen, int *infoNum)
{
    (void)pkgName;
    (void)info;
    (void)infoTypeLen;
    (void)infoNum;
    return SOFTBUS_OK;
}

int32_t DiscServerProxy::GetLocalDeviceInfo(const char *pkgName, void *info, uint32_t infoTypeLen)
{
    (void)pkgName;
    (void)info;
    (void)infoTypeLen;
    return SOFTBUS_OK;
}

int32_t DiscServerProxy::GetNodeKeyInfo(const char *pkgName, const char *networkId, int key, unsigned char *buf,
    uint32_t len)
{
    (void)pkgName;
    (void)networkId;
    (void)key;
    (void)buf;
    (void)len;
    return SOFTBUS_OK;
}

int32_t DiscServerProxy::SetNodeDataChangeFlag(const char *pkgName, const char *networkId, uint16_t dataChangeFlag)
{
    (void)pkgName;
    (void)networkId;
    (void)dataChangeFlag;
    return SOFTBUS_OK;
}

int32_t DiscServerProxy::StartTimeSync(const char *pkgName, const char *targetNetworkId, int32_t accuracy,
    int32_t period)
{
    (void)pkgName;
    (void)targetNetworkId;
    (void)accuracy;
    (void)period;
    return SOFTBUS_OK;
}

int32_t DiscServerProxy::StopTimeSync(const char *pkgName, const char *targetNetworkId)
{
    (void)pkgName;
    (void)targetNetworkId;
    return SOFTBUS_OK;
}

int32_t DiscServerProxy::QosReport(int32_t channelId, int32_t chanType, int32_t appType, int32_t quality)
{
    (void)channelId;
    (void)chanType;
    (void)appType;
    (void)quality;
    return SOFTBUS_OK;
}

int32_t DiscServerProxy::StreamStats(int32_t channelId, int32_t channelType, const StreamSendStats *data)
{
    (void)channelId;
    (void)channelType;
    (void)data;
    return SOFTBUS_OK;
}

int32_t DiscServerProxy::RippleStats(int32_t channelId, int32_t channelType, const TrafficStats *data)
{
    (void)channelId;
    (void)channelType;
    (void)data;
    return SOFTBUS_OK;
}

int32_t DiscServerProxy::EvaluateQos(const char *peerNetworkId, TransDataType dataType, const QosTV *qos,
    uint32_t qosCount)
{
    (void)peerNetworkId;
    (void)dataType;
    (void)qos;
    (void)qosCount;
    return SOFTBUS_OK;
}
} // namespace OHOS