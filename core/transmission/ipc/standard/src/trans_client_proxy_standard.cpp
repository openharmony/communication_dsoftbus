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
int32_t TransClientProxy::OnClientPermissonChange(const char *pkgName, int32_t state)
{
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "remote is nullptr");
        return SOFTBUS_ERR;
    }
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "write InterfaceToken failed!");
        return SOFTBUS_ERR;
    }
    if (!data.WriteInt32(state)) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "write PermStateChangeType failed");
        return SOFTBUS_ERR;
    }
    if (!data.WriteCString(pkgName)) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "write pkgName failed");
        return SOFTBUS_ERR;
    }
    MessageParcel reply;
    MessageOption option = { MessageOption::TF_ASYNC };
    if (remote->SendRequest(CLIENT_ON_PERMISSION_CHANGE, data, reply, option) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "DataSyncPermissionChange send request failed");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int32_t TransClientProxy::OnChannelOpened(const char *sessionName, const ChannelInfo *channel)
{
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "remote is nullptr");
        return SOFTBUS_ERR;
    }
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "write InterfaceToken failed!");
        return SOFTBUS_ERR;
    }
    if (!data.WriteCString(sessionName)) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "write addr type length failed");
        return SOFTBUS_ERR;
    }
    if (!data.WriteInt32(channel->channelId)) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "write addr type length failed");
        return SOFTBUS_ERR;
    }
    if (!data.WriteInt32(channel->channelType)) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "write addr type length failed");
        return SOFTBUS_ERR;
    }
    if (channel->channelType == CHANNEL_TYPE_TCP_DIRECT) {
        if (!data.WriteFileDescriptor(channel->fd)) {
            SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "write addr type length failed");
            return SOFTBUS_ERR;
        }
    }
    if (!data.WriteBool(channel->isServer)) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "write addr type length failed");
        return SOFTBUS_ERR;
    }
    if (!data.WriteBool(channel->isEnabled)) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "write addr type length failed");
        return SOFTBUS_ERR;
    }
    if (!data.WriteInt32(channel->peerUid)) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "write peerUid failed");
        return SOFTBUS_ERR;
    }
    if (!data.WriteInt32(channel->peerPid)) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "write peerPid failed");
        return SOFTBUS_ERR;
    }
    if (!data.WriteCString(channel->groupId)) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "write addr failed");
        return SOFTBUS_ERR;
    }
    if (!data.WriteUint32(channel->keyLen)) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "write addr type length failed");
        return SOFTBUS_ERR;
    }
    if (!data.WriteRawData(channel->sessionKey, channel->keyLen)) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "write addr failed");
        return SOFTBUS_ERR;
    }
    if (!data.WriteCString(channel->peerSessionName)) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "write addr failed");
        return SOFTBUS_ERR;
    }
    if (!data.WriteCString(channel->peerDeviceId)) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "write addr failed");
        return SOFTBUS_ERR;
    }
    data.WriteInt32(channel->businessType);
    if (channel->channelType == CHANNEL_TYPE_UDP) {
        data.WriteCString(channel->myIp);
        data.WriteInt32(channel->streamType);
        data.WriteBool(channel->isUdpFile);
        if (!channel->isServer) {
            data.WriteInt32(channel->peerPort);
            data.WriteCString(channel->peerIp);
        }
    }
    data.WriteInt32(channel->routeType);
    data.WriteInt32(channel->encrypt);
    data.WriteInt32(channel->algorithm);
    data.WriteInt32(channel->crc);

    MessageParcel reply;
    MessageOption option;
    if (remote->SendRequest(CLIENT_ON_CHANNEL_OPENED, data, reply, option) != 0) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "OnChannelOpened send request failed");
        return SOFTBUS_ERR;
    }
    int32_t serverRet;
    if (!reply.ReadInt32(serverRet)) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "OnChannelOpened read serverRet failed");
        return SOFTBUS_ERR;
    }
    return serverRet;
}

int32_t TransClientProxy::OnChannelOpenFailed(int32_t channelId, int32_t channelType, int32_t errCode)
{
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "remote is nullptr");
        return SOFTBUS_ERR;
    }

    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "write InterfaceToken failed!");
        return SOFTBUS_ERR;
    }
    if (!data.WriteInt32(channelId)) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "write channel id failed");
        return SOFTBUS_ERR;
    }
    if (!data.WriteInt32(channelType)) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "write channel type failed");
        return SOFTBUS_ERR;
    }
    if (!data.WriteInt32(errCode)) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "write error code failed");
        return SOFTBUS_ERR;
    }
    MessageParcel reply;
    MessageOption option = { MessageOption::TF_ASYNC };
    if (remote->SendRequest(CLIENT_ON_CHANNEL_OPENFAILED, data, reply, option) != 0) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "OnChannelOpenFailed send request failed");
        return SOFTBUS_ERR;
    }

    return SOFTBUS_OK;
}

int32_t TransClientProxy::OnChannelLinkDown(const char *networkId, int32_t routeType)
{
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "remote is nullptr");
        return SOFTBUS_ERR;
    }
    if (networkId == nullptr) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "invalid parameters");
        return SOFTBUS_ERR;
    }
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "write InterfaceToken failed!");
        return SOFTBUS_ERR;
    }
    if (!data.WriteCString(networkId)) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "write networkId failed");
        return SOFTBUS_ERR;
    }
    if (!data.WriteInt32(routeType)) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "write routeType failed");
        return SOFTBUS_ERR;
    }
    MessageParcel reply;
    MessageOption option;
    if (remote->SendRequest(CLIENT_ON_CHANNEL_LINKDOWN, data, reply, option) != 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "OnChannelLinkDwon send request failed");
        return SOFTBUS_ERR;
    }
    int32_t serverRet;
    if (!reply.ReadInt32(serverRet)) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "OnChannelLinkDwon read serverRet failed");
        return SOFTBUS_ERR;
    }
    return serverRet;
}

int32_t TransClientProxy::OnChannelClosed(int32_t channelId, int32_t channelType)
{
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "remote is nullptr");
        return SOFTBUS_ERR;
    }

    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "write InterfaceToken failed!");
        return SOFTBUS_ERR;
    }
    if (!data.WriteInt32(channelId)) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "write channel id failed");
        return SOFTBUS_ERR;
    }
    if (!data.WriteInt32(channelType)) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "write channel type failed");
        return SOFTBUS_ERR;
    }
    MessageParcel reply;
    MessageOption option;
    if (remote->SendRequest(CLIENT_ON_CHANNEL_CLOSED, data, reply, option) != 0) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "OnChannelClosed send request failed");
        return SOFTBUS_ERR;
    }
    int32_t serverRet;
    if (!reply.ReadInt32(serverRet)) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "OnChannelClosed read serverRet failed");
        return SOFTBUS_ERR;
    }
    return serverRet;
}

int32_t TransClientProxy::OnChannelMsgReceived(int32_t channelId, int32_t channelType, const void *dataInfo,
    uint32_t len, int32_t type)
{
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "remote is nullptr");
        return SOFTBUS_ERR;
    }

    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "write InterfaceToken failed!");
        return SOFTBUS_ERR;
    }
    if (!data.WriteInt32(channelId)) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "write channel id failed");
        return SOFTBUS_ERR;
    }
    if (!data.WriteInt32(channelType)) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "write channel type failed");
        return SOFTBUS_ERR;
    }
    if (!data.WriteUint32(len)) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "write data len failed");
        return SOFTBUS_ERR;
    }
    if (!data.WriteRawData(dataInfo, len)) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "write (dataInfo, len) failed");
        return SOFTBUS_ERR;
    }
    if (!data.WriteInt32(type)) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "write data type failed");
        return SOFTBUS_ERR;
    }

    MessageParcel reply;
    MessageOption option(MessageOption::TF_ASYNC);
    if (remote->SendRequest(CLIENT_ON_CHANNEL_MSGRECEIVED, data, reply, option) != 0) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "OnChannelMsgReceived send request failed");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int32_t TransClientProxy::OnChannelQosEvent(int32_t channelId, int32_t channelType, int32_t eventId, int32_t tvCount,
    const QosTv *tvList)
{
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "remote is nullptr");
        return SOFTBUS_ERR;
    }

    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "write InterfaceToken failed!");
        return SOFTBUS_ERR;
    }
    if (!data.WriteInt32(channelId)) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "write channel id failed");
        return SOFTBUS_ERR;
    }
    if (!data.WriteInt32(channelType)) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "write channel type failed");
        return SOFTBUS_ERR;
    }
    if (!data.WriteInt32(eventId)) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "write channel type failed");
        return SOFTBUS_ERR;
    }
    if (!data.WriteInt32(tvCount)) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "write tv count failed");
        return SOFTBUS_ERR;
    }
    if (!data.WriteRawData(tvList, sizeof(QosTv) * tvCount)) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "write tv list failed");
        return SOFTBUS_ERR;
    }

    MessageParcel reply;
    MessageOption option;
    if (remote->SendRequest(CLIENT_ON_CHANNEL_QOSEVENT, data, reply, option) != 0) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "OnChannelQosEvent send request failed");
        return SOFTBUS_ERR;
    }
    int32_t serverRet;
    if (!reply.ReadInt32(serverRet)) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "OnChannelQosEvent read serverRet failed");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

void TransClientProxy::OnDeviceFound(const DeviceInfo *device)
{
    (void)device;
}

void TransClientProxy::OnDiscoverFailed(int subscribeId, int failReason)
{
    (void)subscribeId;
    (void)failReason;
}

void TransClientProxy::OnDiscoverySuccess(int subscribeId)
{
    (void)subscribeId;
}

void TransClientProxy::OnPublishSuccess(int publishId)
{
    (void)publishId;
}

void TransClientProxy::OnPublishFail(int publishId, int reason)
{
    (void)publishId;
    (void)reason;
}

int32_t TransClientProxy::OnJoinLNNResult(void *addr, uint32_t addrTypeLen, const char *networkId, int retCode)
{
    (void)addr;
    (void)addrTypeLen;
    (void)networkId;
    (void)retCode;
    return SOFTBUS_OK;
}

int32_t TransClientProxy::OnJoinMetaNodeResult(void *addr, uint32_t addrTypeLen, const char *networkId, int retCode)
{
    (void)addr;
    (void)addrTypeLen;
    (void)networkId;
    (void)retCode;
    return SOFTBUS_OK;
}

int32_t TransClientProxy::OnLeaveLNNResult(const char *networkId, int retCode)
{
    (void)networkId;
    (void)retCode;
    return SOFTBUS_OK;
}

int32_t TransClientProxy::OnLeaveMetaNodeResult(const char *networkId, int retCode)
{
    (void)networkId;
    (void)retCode;
    return SOFTBUS_OK;
}

int32_t TransClientProxy::OnNodeOnlineStateChanged(bool isOnline, void *info, uint32_t infoTypeLen)
{
    (void)isOnline;
    (void)info;
    (void)infoTypeLen;
    return SOFTBUS_OK;
}

int32_t TransClientProxy::OnNodeBasicInfoChanged(void *info, uint32_t infoTypeLen, int32_t type)
{
    (void)info;
    (void)infoTypeLen;
    (void)type;
    return SOFTBUS_OK;
}

int32_t TransClientProxy::OnTimeSyncResult(const void *info, uint32_t infoTypeLen, int32_t retCode)
{
    (void)info;
    (void)infoTypeLen;
    (void)retCode;
    return SOFTBUS_OK;
}

void TransClientProxy::OnPublishLNNResult(int32_t publishId, int32_t reason)
{
    (void)publishId;
    (void)reason;
}

void TransClientProxy::OnRefreshLNNResult(int32_t refreshId, int32_t reason)
{
    (void)refreshId;
    (void)reason;
}

void TransClientProxy::OnRefreshDeviceFound(const void *device, uint32_t deviceLen)
{
    (void)device;
    (void)deviceLen;
}
} // namespace OHOS