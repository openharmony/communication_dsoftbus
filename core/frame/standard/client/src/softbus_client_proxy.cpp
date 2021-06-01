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

#include "softbus_client_proxy.h"

#include "discovery_service.h"
#include "message_parcel.h"
#include "softbus_def.h"
#include "softbus_errcode.h"
#include "softbus_interface.h"
#include "softbus_log.h"

namespace OHOS {
int32_t SoftBusClientProxy::OnChannelOpened(const char *pkgName, const char *sessionName, const void *info)
{
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        LOG_ERR("remote is nullptr");
        return SOFTBUS_ERR;
    }

    ChannelInfo *channel = (ChannelInfo *)info;
    MessageParcel data;
    if (!data.WriteCString(pkgName)) {
        LOG_ERR("write addr type length failed");
        return SOFTBUS_ERR;
    }

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

int32_t SoftBusClientProxy::OnChannelOpenFailed(const char *pkgName, int32_t channelId)
{
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        LOG_ERR("remote is nullptr");
        return SOFTBUS_ERR;
    }

    MessageParcel data;
    if (!data.WriteCString(pkgName)) {
        LOG_ERR("write addr type length failed");
        return SOFTBUS_ERR;
    }
    if (!data.WriteInt32(channelId)) {
        LOG_ERR("write channel id failed");
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

int32_t SoftBusClientProxy::OnChannelClosed(const char *pkgName, int32_t channelId)
{
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        LOG_ERR("remote is nullptr");
        return SOFTBUS_ERR;
    }

    MessageParcel data;
    if (!data.WriteCString(pkgName)) {
        LOG_ERR("write addr type length failed");
        return SOFTBUS_ERR;
    }
    if (!data.WriteInt32(channelId)) {
        LOG_ERR("write channel id failed");
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

int32_t SoftBusClientProxy::OnChannelMsgReceived(const char *pkgName, int32_t channelId, const void *dataInfo,
    uint32_t len, int32_t type)
{
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        LOG_ERR("remote is nullptr");
        return SOFTBUS_ERR;
    }

    MessageParcel data;
    if (!data.WriteCString(pkgName)) {
        LOG_ERR("write pkgName failed");
        return SOFTBUS_ERR;
    }
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

void SoftBusClientProxy::OnDeviceFound(const void *device)
{
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        LOG_ERR("remote is nullptr");
        return;
    }

    DeviceInfo *deviceInfo = (DeviceInfo *)device;
    MessageParcel data;
    data.WriteBuffer(deviceInfo, sizeof(DeviceInfo));

    MessageParcel reply;
    MessageOption option;
    int32_t err = remote->SendRequest(CLIENT_DISCOVERY_DEVICE_FOUND, data, reply, option);
    if (err != 0) {
        LOG_ERR("OnDeviceFound send request failed");
        return;
    }
}

void SoftBusClientProxy::OnDiscoverFailed(int subscribeId, int failReason)
{
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        LOG_ERR("remote is nullptr");
        return;
    }

    MessageParcel data;
    data.WriteInt32(subscribeId);
    data.WriteInt32(failReason);

    MessageParcel reply;
    MessageOption option;
    int32_t err = remote->SendRequest(CLIENT_DISCOVERY_FAIL, data, reply, option);
    if (err != 0) {
        LOG_ERR("OnDiscoverFailed send request failed");
        return;
    }
}

void SoftBusClientProxy::OnDiscoverySuccess(int subscribeId)
{
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        LOG_ERR("remote is nullptr");
        return;
    }

    MessageParcel data;
    data.WriteInt32(subscribeId);

    MessageParcel reply;
    MessageOption option;
    int32_t err = remote->SendRequest(CLIENT_DISCOVERY_SUCC, data, reply, option);
    if (err != 0) {
        LOG_ERR("OnDiscoverySuccess send request failed");
        return;
    }
}

void SoftBusClientProxy::OnPublishSuccess(int publishId)
{
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        LOG_ERR("remote is nullptr");
        return;
    }

    MessageParcel data;
    data.WriteInt32(publishId);

    MessageParcel reply;
    MessageOption option;
    int32_t err = remote->SendRequest(CLIENT_PUBLISH_SUCC, data, reply, option);
    if (err != 0) {
        LOG_ERR("OnPublishSuccess send request failed");
        return;
    }
}

void SoftBusClientProxy::OnPublishFail(int publishId, int reason)
{
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        LOG_ERR("remote is nullptr");
        return;
    }

    MessageParcel data;
    data.WriteInt32(publishId);
    data.WriteInt32(reason);

    MessageParcel reply;
    MessageOption option;
    int32_t err = remote->SendRequest(CLIENT_PUBLISH_FAIL, data, reply, option);
    if (err != 0) {
        LOG_ERR("OnPublishFail send request failed");
        return;
    }
}

int32_t SoftBusClientProxy::OnJoinLNNResult(void *addr, uint32_t addrTypeLen, const char *networkId, int retCode)
{
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        LOG_ERR("remote is nullptr");
        return SOFTBUS_ERR;
    }
    if (addr == nullptr || (retCode == 0 && networkId == nullptr)) {
        LOG_ERR("invalid parameters");
        return SOFTBUS_ERR;
    }
    MessageParcel data;
    if (!data.WriteUint32(addrTypeLen)) {
        LOG_ERR("write addr type length failed");
        return SOFTBUS_ERR;
    }
    if (!data.WriteRawData(addr, addrTypeLen)) {
        LOG_ERR("write addr failed");
        return SOFTBUS_ERR;
    }
    if (!data.WriteInt32(retCode)) {
        LOG_ERR("write retCode failed");
        return SOFTBUS_ERR;
    }
    if (retCode == 0 && !data.WriteCString(networkId)) {
        LOG_ERR("write networkId failed");
        return SOFTBUS_ERR;
    }
    MessageParcel reply;
    MessageOption option;
    if (remote->SendRequest(CLIENT_ON_JOIN_RESULT, data, reply, option) != 0) {
        LOG_ERR("OnJoinLNNResult send request failed");
        return SOFTBUS_ERR;
    }
    int32_t serverRet;
    if (!reply.ReadInt32(serverRet)) {
        LOG_ERR("SoftbusLeaveLNN read serverRet failed");
        return SOFTBUS_ERR;
    }
    return serverRet;
}

int32_t SoftBusClientProxy::OnLeaveLNNResult(const char *networkId, int retCode)
{
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        LOG_ERR("remote is nullptr");
        return SOFTBUS_ERR;
    }
    if (networkId == nullptr) {
        LOG_ERR("invalid parameters");
        return SOFTBUS_ERR;
    }
    MessageParcel data;
    if (!data.WriteCString(networkId)) {
        LOG_ERR("write networkId failed");
        return SOFTBUS_ERR;
    }
    if (!data.WriteInt32(retCode)) {
        LOG_ERR("write retCode failed");
        return SOFTBUS_ERR;
    }
    MessageParcel reply;
    MessageOption option;
    if (remote->SendRequest(CLIENT_ON_LEAVE_RESULT, data, reply, option) != 0) {
        LOG_ERR("OnLeaveLNNResult send request failed");
        return SOFTBUS_ERR;
    }
    int32_t serverRet;
    if (!reply.ReadInt32(serverRet)) {
        LOG_ERR("OnLeaveLNNResult read serverRet failed");
        return SOFTBUS_ERR;
    }
    return serverRet;
}

int32_t SoftBusClientProxy::OnNodeOnlineStateChanged(bool isOnline, void *info, uint32_t infoTypeLen)
{
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        LOG_ERR("remote is nullptr");
        return SOFTBUS_ERR;
    }
    if (info == nullptr) {
        LOG_ERR("invalid parameters");
        return SOFTBUS_ERR;
    }
    MessageParcel data;
    if (!data.WriteBool(isOnline)) {
        LOG_ERR("write online state failed");
        return SOFTBUS_ERR;
    }
    if (!data.WriteUint32(infoTypeLen)) {
        LOG_ERR("write info type length failed");
        return SOFTBUS_ERR;
    }
    if (!data.WriteRawData(info, infoTypeLen)) {
        LOG_ERR("write node info failed");
        return SOFTBUS_ERR;
    }
    MessageParcel reply;
    MessageOption option;
    if (remote->SendRequest(CLIENT_ON_NODE_ONLINE_STATE_CHANGED, data, reply, option) != 0) {
        LOG_ERR("OnNodeOnlineStateChanged send request failed");
        return SOFTBUS_ERR;
    }
    int32_t serverRet;
    if (!reply.ReadInt32(serverRet)) {
        LOG_ERR("OnNodeOnlineStateChanged read serverRet failed");
        return SOFTBUS_ERR;
    }
    return serverRet;
}

int32_t SoftBusClientProxy::OnNodeBasicInfoChanged(void *info, uint32_t infoTypeLen, int32_t type)
{
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        LOG_ERR("remote is nullptr");
        return SOFTBUS_ERR;
    }
    if (info == nullptr) {
        LOG_ERR("invalid parameters");
        return SOFTBUS_ERR;
    }
    MessageParcel data;
    LOG_ERR("OnNodeBasicInfoChanged type: %d", type);
    if (!data.WriteInt32(type)) {
        LOG_ERR("write type failed");
        return SOFTBUS_ERR;
    }
    if (!data.WriteUint32(infoTypeLen)) {
        LOG_ERR("write info type length failed");
        return SOFTBUS_ERR;
    }
    if (!data.WriteRawData(info, infoTypeLen)) {
        LOG_ERR("write node info failed");
        return SOFTBUS_ERR;
    }
    MessageParcel reply;
    MessageOption option;
    if (remote->SendRequest(CLIENT_ON_NODE_BASIC_INFO_CHANGED, data, reply, option) != 0) {
        LOG_ERR("OnNodeBasicInfoChanged send request failed");
        return SOFTBUS_ERR;
    }
    int32_t serverRet;
    if (!reply.ReadInt32(serverRet)) {
        LOG_ERR("OnNodeBasicInfoChanged read serverRet failed");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}
} // namespace OHOS