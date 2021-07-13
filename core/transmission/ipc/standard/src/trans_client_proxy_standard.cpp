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

#include "trans_client_proxy_standard.h"

#include "message_parcel.h"
#include "softbus_def.h"
#include "softbus_errcode.h"
#include "softbus_ipc_def.h"
#include "softbus_log.h"

namespace OHOS {
int32_t TransClientProxy::OnChannelOpened(const char *sessionName, const ChannelInfo *channel)
{
    // 需要区分udp channel，返回监听port，待补充
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        LOG_ERR("remote is nullptr");
        return SOFTBUS_ERR;
    }
    MessageParcel data;
    if (!data.WriteCString(sessionName)) {
        LOG_ERR("write addr type length failed");
        return SOFTBUS_ERR;
    }
    if (!data.WriteInt32(channel->channelId)) {
        LOG_ERR("write addr type length failed");
        return SOFTBUS_ERR;
    }
    if (!data.WriteInt32(channel->channelType)) {
        LOG_ERR("write addr type length failed");
        return SOFTBUS_ERR;
    }
    if (!data.WriteFileDescriptor(channel->fd)) {
        LOG_ERR("write addr type length failed");
        return SOFTBUS_ERR;
    }
    if (!data.WriteBool(channel->isServer)) {
        LOG_ERR("write addr type length failed");
        return SOFTBUS_ERR;
    }
    if (!data.WriteBool(channel->isEnabled)) {
        LOG_ERR("write addr type length failed");
        return SOFTBUS_ERR;
    }
    if (!data.WriteInt32(channel->peerUid)) {
        LOG_ERR("write peerUid failed");
        return SOFTBUS_ERR;
    }
    if (!data.WriteInt32(channel->peerPid)) {
        LOG_ERR("write peerPid failed");
        return SOFTBUS_ERR;
    }
    if (!data.WriteCString(channel->groupId)) {
        LOG_ERR("write addr failed");
        return SOFTBUS_ERR;
    }
    if (!data.WriteUint32(channel->keyLen)) {
        LOG_ERR("write addr type length failed");
        return SOFTBUS_ERR;
    }
    if (!data.WriteRawData(channel->sessionKey, channel->keyLen)) {
        LOG_ERR("write addr failed");
        return SOFTBUS_ERR;
    }
    if (!data.WriteCString(channel->peerSessionName)) {
        LOG_ERR("write addr failed");
        return SOFTBUS_ERR;
    }
    if (!data.WriteCString(channel->peerDeviceId)) {
        LOG_ERR("write addr failed");
        return SOFTBUS_ERR;
    }

    MessageParcel reply;
    MessageOption option;
    if (remote->SendRequest(CLIENT_ON_CHANNEL_OPENED, data, reply, option) != 0) {
        LOG_ERR("OnChannelOpened send request failed");
        return SOFTBUS_ERR;
    }
    int32_t serverRet;
    if (!reply.ReadInt32(serverRet)) {
        LOG_ERR("OnChannelOpened read serverRet failed");
        return SOFTBUS_ERR;
    }
    return serverRet;
}

int32_t TransClientProxy::OnChannelOpenFailed(int32_t channelId, int32_t channelType)
{
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        LOG_ERR("remote is nullptr");
        return SOFTBUS_ERR;
    }

    MessageParcel data;
    if (!data.WriteInt32(channelId)) {
        LOG_ERR("write channel id failed");
        return SOFTBUS_ERR;
    }
    if (!data.WriteInt32(channelType)) {
        LOG_ERR("write channel type failed");
        return SOFTBUS_ERR;
    }
    MessageParcel reply;
    MessageOption option;
    if (remote->SendRequest(CLIENT_ON_CHANNEL_OPENFAILED, data, reply, option) != 0) {
        LOG_ERR("OnChannelOpenFailed send request failed");
        return SOFTBUS_ERR;
    }
    int32_t serverRet;
    if (!reply.ReadInt32(serverRet)) {
        LOG_ERR("OnChannelOpenFailed read serverRet failed");
        return SOFTBUS_ERR;
    }
    return serverRet;
}

int32_t TransClientProxy::OnChannelClosed(int32_t channelId, int32_t channelType)
{
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        LOG_ERR("remote is nullptr");
        return SOFTBUS_ERR;
    }

    MessageParcel data;
    if (!data.WriteInt32(channelId)) {
        LOG_ERR("write channel id failed");
        return SOFTBUS_ERR;
    }
    if (!data.WriteInt32(channelType)) {
        LOG_ERR("write channel type failed");
        return SOFTBUS_ERR;
    }
    MessageParcel reply;
    MessageOption option;
    if (remote->SendRequest(CLIENT_ON_CHANNEL_CLOSED, data, reply, option) != 0) {
        LOG_ERR("OnChannelClosed send request failed");
        return SOFTBUS_ERR;
    }
    int32_t serverRet;
    if (!reply.ReadInt32(serverRet)) {
        LOG_ERR("OnChannelClosed read serverRet failed");
        return SOFTBUS_ERR;
    }
    return serverRet;
}

int32_t TransClientProxy::OnChannelMsgReceived(int32_t channelId, const void *dataInfo,
    uint32_t len, int32_t type)
{
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        LOG_ERR("remote is nullptr");
        return SOFTBUS_ERR;
    }

    MessageParcel data;
    if (!data.WriteInt32(channelId)) {
        LOG_ERR("write channel id failed");
        return SOFTBUS_ERR;
    }
    if (!data.WriteUint32(len)) {
        LOG_ERR("write data len failed");
        return SOFTBUS_ERR;
    }
    if (!data.WriteRawData(dataInfo, len)) {
        LOG_ERR("write (dataInfo, len) failed");
        return SOFTBUS_ERR;
    }
    if (!data.WriteInt32(type)) {
        LOG_ERR("write data type failed");
        return SOFTBUS_ERR;
    }

    MessageParcel reply;
    MessageOption option;
    if (remote->SendRequest(CLIENT_ON_CHANNEL_MSGRECEIVED, data, reply, option) != 0) {
        LOG_ERR("OnChannelMsgReceived send request failed");
        return SOFTBUS_ERR;
    }
    int32_t serverRet;
    if (!reply.ReadInt32(serverRet)) {
        LOG_ERR("OnChannelMsgReceived read serverRet failed");
        return SOFTBUS_ERR;
    }
    return serverRet;
}

void TransClientProxy::OnDeviceFound(const DeviceInfo *device)
{
}

void TransClientProxy::OnDiscoverFailed(int subscribeId, int failReason)
{
}

void TransClientProxy::OnDiscoverySuccess(int subscribeId)
{
}

void TransClientProxy::OnPublishSuccess(int publishId)
{
}

void TransClientProxy::OnPublishFail(int publishId, int reason)
{
}

int32_t TransClientProxy::OnJoinLNNResult(void *addr, uint32_t addrTypeLen, const char *networkId, int retCode)
{
    return SOFTBUS_OK;
}

int32_t TransClientProxy::OnLeaveLNNResult(const char *networkId, int retCode)
{
    return SOFTBUS_OK;
}

int32_t TransClientProxy::OnNodeOnlineStateChanged(bool isOnline, void *info, uint32_t infoTypeLen)
{
    return SOFTBUS_OK;
}

int32_t TransClientProxy::OnNodeBasicInfoChanged(void *info, uint32_t infoTypeLen, int32_t type)
{
    return SOFTBUS_OK;
}
} // namespace OHOS