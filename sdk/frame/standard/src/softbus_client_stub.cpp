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

#include "softbus_client_stub.h"
#include "client_trans_session_manager.h"
#include "client_bus_center_manager.h"
#include "client_disc_manager.h"
#include "client_trans_channel_callback.h"
#include "ipc_skeleton.h"
#include "ipc_types.h"
#include "message_parcel.h"
#include "securec.h"
#include "softbus_def.h"
#include "softbus_errcode.h"
#include "softbus_ipc_def.h"
#include "softbus_log.h"

namespace OHOS {
SoftBusClientStub::SoftBusClientStub()
{
    memberFuncMap_[CLIENT_DISCOVERY_DEVICE_FOUND] =
        &SoftBusClientStub::OnDeviceFoundInner;
    memberFuncMap_[CLIENT_DISCOVERY_SUCC] =
        &SoftBusClientStub::OnDiscoverySuccessInner;
    memberFuncMap_[CLIENT_DISCOVERY_FAIL] =
        &SoftBusClientStub::OnDiscoverFailedInner;
    memberFuncMap_[CLIENT_PUBLISH_SUCC] =
        &SoftBusClientStub::OnPublishSuccessInner;
    memberFuncMap_[CLIENT_PUBLISH_FAIL] =
        &SoftBusClientStub::OnPublishFailInner;
    memberFuncMap_[CLIENT_ON_CHANNEL_OPENED] =
        &SoftBusClientStub::OnChannelOpenedInner;
    memberFuncMap_[CLIENT_ON_CHANNEL_OPENFAILED] =
        &SoftBusClientStub::OnChannelOpenFailedInner;
    memberFuncMap_[CLIENT_ON_CHANNEL_LINKDOWN] =
        &SoftBusClientStub::OnChannelLinkDownInner;
    memberFuncMap_[CLIENT_ON_CHANNEL_CLOSED] =
        &SoftBusClientStub::OnChannelClosedInner;
    memberFuncMap_[CLIENT_ON_CHANNEL_MSGRECEIVED] =
        &SoftBusClientStub::OnChannelMsgReceivedInner;
    memberFuncMap_[CLIENT_ON_CHANNEL_QOSEVENT] =
        &SoftBusClientStub::OnChannelQosEventInner;
    memberFuncMap_[CLIENT_ON_JOIN_RESULT] =
        &SoftBusClientStub::OnJoinLNNResultInner;
    memberFuncMap_[CLIENT_ON_JOIN_METANODE_RESULT] =
        &SoftBusClientStub::OnJoinMetaNodeResultInner;
    memberFuncMap_[CLIENT_ON_LEAVE_RESULT] =
        &SoftBusClientStub::OnLeaveLNNResultInner;
    memberFuncMap_[CLIENT_ON_LEAVE_METANODE_RESULT] =
        &SoftBusClientStub::OnLeaveMetaNodeResultInner;
    memberFuncMap_[CLIENT_ON_NODE_ONLINE_STATE_CHANGED] =
        &SoftBusClientStub::OnNodeOnlineStateChangedInner;
    memberFuncMap_[CLIENT_ON_NODE_BASIC_INFO_CHANGED] =
        &SoftBusClientStub::OnNodeBasicInfoChangedInner;
    memberFuncMap_[CLIENT_ON_TIME_SYNC_RESULT] =
        &SoftBusClientStub::OnTimeSyncResultInner;
    memberFuncMap_[CLIENT_ON_PUBLISH_LNN_RESULT] =
        &SoftBusClientStub::OnPublishLNNResultInner;
    memberFuncMap_[CLIENT_ON_REFRESH_LNN_RESULT] =
        &SoftBusClientStub::OnRefreshLNNResultInner;
    memberFuncMap_[CLIENT_ON_REFRESH_DEVICE_FOUND] =
        &SoftBusClientStub::OnRefreshDeviceFoundInner;
    memberFuncMap_[CLIENT_ON_PERMISSION_CHANGE] =
        &SoftBusClientStub::OnClientPermissonChangeInner;
}

int32_t SoftBusClientStub::OnRemoteRequest(uint32_t code,
    MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_INFO, "SoftBusClientStub::OnReceived, code = %u", code);
    if (data.ReadInterfaceToken() != GetDescriptor()) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "SoftBusClientStub: ReadInterfaceToken faild!");
        return SOFTBUS_ERR;
    }
    auto itFunc = memberFuncMap_.find(code);
    if (itFunc != memberFuncMap_.end()) {
        auto memberFunc = itFunc->second;
        if (memberFunc != nullptr) {
            return (this->*memberFunc)(data, reply);
        }
    }
    SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_INFO, "SoftBusClientStub: default case, need check.");
    return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
}

int32_t SoftBusClientStub::OnClientPermissonChangeInner(MessageParcel &data, MessageParcel &reply)
{
    int32_t state;
    if (!data.ReadInt32(state)) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "OnClientPermissonChangeInner read state failed!");
        return SOFTBUS_ERR;
    }
    const char *pkgName = data.ReadCString();
    if (pkgName == nullptr) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "OnClientPermissonChangeInner read pkgName failed!");
        return SOFTBUS_ERR;
    }
    PermissionStateChange(pkgName, state);
    return SOFTBUS_OK;
}

int32_t SoftBusClientStub::OnDeviceFoundInner(MessageParcel &data, MessageParcel &reply)
{
    const unsigned char *info = data.ReadBuffer(sizeof(DeviceInfo));
    if (info == nullptr) {
        return SOFTBUS_ERR;
    }
    DeviceInfo deviceInfo;
    if (memcpy_s(&deviceInfo, sizeof(DeviceInfo), info, sizeof(DeviceInfo)) != EOK) {
        return SOFTBUS_ERR;
    }
    OnDeviceFound(&deviceInfo);
    return SOFTBUS_OK;
}

int32_t SoftBusClientStub::OnDiscoverFailedInner(MessageParcel &data, MessageParcel &reply)
{
    int subscribeId = data.ReadInt32();
    int failReason = data.ReadInt32();
    OnDiscoverFailed(subscribeId, failReason);
    return SOFTBUS_OK;
}

int32_t SoftBusClientStub::OnDiscoverySuccessInner(MessageParcel &data, MessageParcel &reply)
{
    int subscribeId = data.ReadInt32();
    OnDiscoverySuccess(subscribeId);
    return SOFTBUS_OK;
}

int32_t SoftBusClientStub::OnPublishSuccessInner(MessageParcel &data, MessageParcel &reply)
{
    int publishId = data.ReadInt32();
    OnPublishSuccess(publishId);
    return SOFTBUS_OK;
}

int32_t SoftBusClientStub::OnPublishFailInner(MessageParcel &data, MessageParcel &reply)
{
    int publishId = data.ReadInt32();
    int failReason = data.ReadInt32();
    OnPublishFail(publishId, failReason);
    return SOFTBUS_OK;
}

void SoftBusClientStub::OnDeviceFound(const DeviceInfo *device)
{
    DiscClientOnDeviceFound(device);
}

void SoftBusClientStub::OnDiscoverFailed(int subscribeId, int failReason)
{
    DiscClientOnDiscoverFailed(subscribeId, (DiscoveryFailReason)failReason);
}

void SoftBusClientStub::OnDiscoverySuccess(int subscribeId)
{
    DiscClientOnDiscoverySuccess(subscribeId);
}

void SoftBusClientStub::OnPublishSuccess(int publishId)
{
    DiscClientOnPublishSuccess(publishId);
}

void SoftBusClientStub::OnPublishFail(int publishId, int reason)
{
    DiscClientOnPublishFail(publishId, (PublishFailReason)reason);
}

int32_t SoftBusClientStub::OnChannelOpened(const char *sessionName, const ChannelInfo *info)
{
    return TransOnChannelOpened(sessionName, info);
}

int32_t SoftBusClientStub::OnChannelOpenFailed(int32_t channelId, int32_t channelType, int32_t errCode)
{
    return TransOnChannelOpenFailed(channelId, channelType, errCode);
}

int32_t SoftBusClientStub::OnChannelLinkDown(const char *networkId, int32_t routeType)
{
    return TransOnChannelLinkDown(networkId, routeType);
}

int32_t SoftBusClientStub::OnChannelClosed(int32_t channelId, int32_t channelType)
{
    return TransOnChannelClosed(channelId, channelType);
}

int32_t SoftBusClientStub::OnChannelMsgReceived(int32_t channelId, int32_t channelType, const void *data,
    uint32_t len, int32_t type)
{
    return TransOnChannelMsgReceived(channelId, channelType, data, len, static_cast<SessionPktType>(type));
}

int32_t SoftBusClientStub::OnChannelQosEvent(int32_t channelId, int32_t channelType, int32_t eventId,
    int32_t tvCount, const QosTv *tvList)
{
    return TransOnChannelQosEvent(channelId, channelType, eventId, tvCount, tvList);
}

int32_t SoftBusClientStub::OnChannelOpenedInner(MessageParcel &data, MessageParcel &reply)
{
    const char *sessionName = data.ReadCString();
    if (sessionName == nullptr) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "OnChannelOpenedInner read sessionName failed!");
        return SOFTBUS_ERR;
    }

    ChannelInfo channel = {0};
    if (!data.ReadInt32(channel.channelId)) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "OnChannelOpenedInner read retCode failed!");
        return SOFTBUS_ERR;
    }
    if (!data.ReadInt32(channel.channelType)) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "OnChannelOpenedInner read retCode failed!");
        return SOFTBUS_ERR;
    }
    if (channel.channelType == CHANNEL_TYPE_TCP_DIRECT) {
        channel.fd = data.ReadFileDescriptor();
    }
    if (!data.ReadBool(channel.isServer)) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "OnChannelOpenedInner read retCode failed!");
        return SOFTBUS_ERR;
    }
    if (!data.ReadBool(channel.isEnabled)) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "OnChannelOpenedInner read retCode failed!");
        return SOFTBUS_ERR;
    }
    if (!data.ReadInt32(channel.peerUid)) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "OnChannelOpenedInner read retCode failed!");
        return SOFTBUS_ERR;
    }
    if (!data.ReadInt32(channel.peerPid)) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "OnChannelOpenedInner read retCode failed!");
        return SOFTBUS_ERR;
    }
    channel.groupId = (char *)data.ReadCString();
    if (channel.groupId == nullptr) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "OnChannelOpenedInner read addr failed!");
        return SOFTBUS_ERR;
    }
    if (!data.ReadUint32(channel.keyLen)) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "OnChannelOpenedInner len failed!");
        return SOFTBUS_ERR;
    }
    channel.sessionKey = (char *)data.ReadRawData(channel.keyLen);
    if (channel.sessionKey == nullptr) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "OnChannelOpenedInner read addr failed!");
        return SOFTBUS_ERR;
    }
    channel.peerSessionName = (char *)data.ReadCString();
    if (channel.peerSessionName == nullptr) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "OnChannelOpenedInner read addr failed!");
        return SOFTBUS_ERR;
    }
    channel.peerDeviceId = (char *)data.ReadCString();
    if (channel.peerDeviceId == nullptr) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "OnChannelOpenedInner read addr failed!");
        return SOFTBUS_ERR;
    }
    data.ReadInt32(channel.businessType);
    if (channel.channelType == CHANNEL_TYPE_UDP) {
        channel.myIp = (char *)data.ReadCString();
        data.ReadInt32(channel.streamType);
        data.ReadBool(channel.isUdpFile);
        if (!channel.isServer) {
            data.ReadInt32(channel.peerPort);
            channel.peerIp = (char *)data.ReadCString();
        }
    }
    data.ReadInt32(channel.routeType);
    data.ReadInt32(channel.encrypt);
    data.ReadInt32(channel.algorithm);
    data.ReadInt32(channel.crc);

    int ret = OnChannelOpened(sessionName, &channel);
    bool res = reply.WriteInt32(ret);
    if (!res) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "OnChannelOpenedInner write reply failed!");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int32_t SoftBusClientStub::OnChannelOpenFailedInner(MessageParcel &data, MessageParcel &reply)
{
    int32_t channelId;
    if (!data.ReadInt32(channelId)) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "OnChannelOpenFailedInner read channel id failed!");
        return SOFTBUS_ERR;
    }

    int32_t channelType;
    if (!data.ReadInt32(channelType)) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "OnChannelOpenFailedInner read channel type failed!");
        return SOFTBUS_ERR;
    }

    int32_t errCode;
    if (!data.ReadInt32(errCode)) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "OnChannelOpenFailedInner read channel type failed!");
        return SOFTBUS_ERR;
    }
    
    int32_t ret = OnChannelOpenFailed(channelId, channelType, errCode);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "OnChannelOpenFailed failed! ret=%d.", ret);
    }
    return ret;
}

int32_t SoftBusClientStub::OnChannelLinkDownInner(MessageParcel &data, MessageParcel &reply)
{
    const char *networkId = data.ReadCString();
    if (networkId == nullptr) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "OnChannelLinkDownInner read networkId failed!");
        return SOFTBUS_ERR;
    }
    int32_t routeType;
    if (!data.ReadInt32(routeType)) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "OnChannelLinkDownInner read routeType failed!");
        return SOFTBUS_ERR;
    }
    int32_t retReply = OnChannelLinkDown(networkId, routeType);
    if (!reply.WriteInt32(retReply)) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "OnChannelLinkDownInner write reply failed!");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int32_t SoftBusClientStub::OnChannelClosedInner(MessageParcel &data, MessageParcel &reply)
{
    int32_t channelId;
    if (!data.ReadInt32(channelId)) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "OnChannelClosedInner read channel id failed!");
        return SOFTBUS_ERR;
    }

    int32_t channelType;
    if (!data.ReadInt32(channelType)) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "OnChannelOpenFailedInner read channel type failed!");
        return SOFTBUS_ERR;
    }

    int ret = OnChannelClosed(channelId, channelType);
    bool res = reply.WriteInt32(ret);
    if (!res) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "OnChannelClosedInner write reply failed!");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int32_t SoftBusClientStub::OnChannelMsgReceivedInner(MessageParcel &data, MessageParcel &reply)
{
    int32_t channelId;
    if (!data.ReadInt32(channelId)) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "OnChannelMsgReceivedInner read channel id failed!");
        return SOFTBUS_ERR;
    }
    int32_t channelType;
    if (!data.ReadInt32(channelType)) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "OnChannelMsgReceivedInner read channel type failed!");
        return SOFTBUS_ERR;
    }
    uint32_t len;
    if (!data.ReadUint32(len)) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "OnChannelMsgReceivedInner read data len failed!");
        return SOFTBUS_ERR;
    }
    char *dataInfo = (char *)data.ReadRawData(len);
    if (dataInfo == nullptr) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "OnChannelOpenedInner read dataInfo failed!");
        return SOFTBUS_ERR;
    }
    int32_t type;
    if (!data.ReadInt32(type)) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "OnChannelMsgReceivedInner read type failed!");
        return SOFTBUS_ERR;
    }
    int ret = OnChannelMsgReceived(channelId, channelType, dataInfo, len, type);
    bool res = reply.WriteInt32(ret);
    if (!res) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "OnChannelMsgReceivedInner write reply failed!");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int32_t SoftBusClientStub::OnChannelQosEventInner(MessageParcel &data, MessageParcel &reply)
{
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "OnChannelQosEventInner");
    int32_t channelId;
    if (!data.ReadInt32(channelId)) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "OnChannelQosEventInner read channel id failed!");
        return SOFTBUS_ERR;
    }
    int32_t channelType;
    if (!data.ReadInt32(channelType)) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "OnChannelQosEventInner read channel type failed!");
        return SOFTBUS_ERR;
    }
    int32_t eventId;
    if (!data.ReadInt32(eventId)) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "OnChannelQosEventInner read eventId failed!");
        return SOFTBUS_ERR;
    }
    int32_t tvCount;
    if (!data.ReadInt32(tvCount)) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "OnChannelQosEventInner read tv count failed!");
        return SOFTBUS_ERR;
    }
    QosTv *tvList = (QosTv *)data.ReadRawData(sizeof(QosTv) * tvCount);
    if (tvList == nullptr) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "OnChannelQosEventInner read tv list failed!");
        return SOFTBUS_ERR;
    }
    int ret = OnChannelQosEvent(channelId, channelType, eventId, tvCount, tvList);
    bool res = reply.WriteInt32(ret);
    if (!res) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "OnChannelQosEventInner write reply failed!");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int32_t SoftBusClientStub::OnJoinLNNResultInner(MessageParcel &data, MessageParcel &reply)
{
    uint32_t addrTypeLen;
    if (!data.ReadUint32(addrTypeLen) || addrTypeLen != sizeof(ConnectionAddr)) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR,
            "OnJoinLNNResultInner read addr type length:%d failed!", addrTypeLen);
        return SOFTBUS_ERR;
    }
    void *addr = (void *)data.ReadRawData(addrTypeLen);
    if (addr == nullptr) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "OnJoinLNNResultInner read addr failed!");
        return SOFTBUS_ERR;
    }
    int32_t retCode;
    if (!data.ReadInt32(retCode)) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "OnJoinLNNResultInner read retCode failed!");
        return SOFTBUS_ERR;
    }
    const char *networkId = nullptr;
    if (retCode == 0) {
        networkId = data.ReadCString();
        if (networkId == nullptr) {
            SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "OnJoinLNNResultInner read networkId failed!");
            return SOFTBUS_ERR;
        }
    }
    int32_t retReply = OnJoinLNNResult(addr, addrTypeLen, networkId, retCode);
    if (retReply != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "OnJoinLNNResultInner notify join result failed!");
    }
    return SOFTBUS_OK;
}

int32_t SoftBusClientStub::OnJoinMetaNodeResultInner(MessageParcel &data, MessageParcel &reply)
{
    uint32_t addrTypeLen;
    if (!data.ReadUint32(addrTypeLen) || addrTypeLen != sizeof(ConnectionAddr)) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR,
            "OnJoinMetaNodeResultInner read addrTypeLen:%d failed!", addrTypeLen);
        return SOFTBUS_ERR;
    }
    void *addr = (void *)data.ReadRawData(addrTypeLen);
    if (addr == nullptr) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "OnJoinMetaNodeResultInner read addr failed!");
        return SOFTBUS_ERR;
    }
    int32_t retCode;
    if (!data.ReadInt32(retCode)) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "OnJoinMetaNodeResultInner read retCode failed!");
        return SOFTBUS_ERR;
    }
    const char *networkId = nullptr;
    if (retCode == 0) {
        networkId = data.ReadCString();
        if (networkId == nullptr) {
            SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "OnJoinMetaNodeResultInner read networkId failed!");
            return SOFTBUS_ERR;
        }
    }
    int32_t retReply = OnJoinMetaNodeResult(addr, addrTypeLen, networkId, retCode);
    if (retReply != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "OnJoinMetaNodeResultInner notify join result failed!");
    }
    return SOFTBUS_OK;
}

int32_t SoftBusClientStub::OnLeaveLNNResultInner(MessageParcel &data, MessageParcel &reply)
{
    const char *networkId = data.ReadCString();
    if (networkId == nullptr) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "OnLeaveLNNResultInner read networkId failed!");
        return SOFTBUS_ERR;
    }
    int32_t retCode;
    if (!data.ReadInt32(retCode)) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "OnLeaveLNNResultInner read retCode failed!");
        return SOFTBUS_ERR;
    }
    int32_t retReply = OnLeaveLNNResult(networkId, retCode);
    if (retReply != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "OnLeaveLNNResultInner notify leave result failed!");
    }
    return SOFTBUS_OK;
}

int32_t SoftBusClientStub::OnLeaveMetaNodeResultInner(MessageParcel &data, MessageParcel &reply)
{
    const char *networkId = data.ReadCString();
    if (networkId == nullptr) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "OnLeaveMetaNodeResultInner read networkId failed!");
        return SOFTBUS_ERR;
    }
    int32_t retCode;
    if (!data.ReadInt32(retCode)) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "OnLeaveMetaNodeResultInner read retCode failed!");
        return SOFTBUS_ERR;
    }
    int32_t retReply = OnLeaveMetaNodeResult(networkId, retCode);
    if (retReply != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "OnLeaveMetaNodeResultInner notify leave result failed!");
    }
    return SOFTBUS_OK;
}

int32_t SoftBusClientStub::OnNodeOnlineStateChangedInner(MessageParcel &data, MessageParcel &reply)
{
    bool isOnline = false;
    if (!data.ReadBool(isOnline)) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "OnNodeOnlineStateChangedInner read online state failed!");
        return SOFTBUS_ERR;
    }
    uint32_t infoTypeLen;
    if (!data.ReadUint32(infoTypeLen) || infoTypeLen != sizeof(NodeBasicInfo)) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR,
            "OnNodeOnlineStateChangedInner read info type length:%d failed!", infoTypeLen);
        return SOFTBUS_ERR;
    }
    void *info = (void *)data.ReadRawData(infoTypeLen);
    if (info == nullptr) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "OnNodeOnlineStateChangedInner read basic info failed!");
        return SOFTBUS_ERR;
    }
    int32_t retReply = OnNodeOnlineStateChanged(isOnline, info, infoTypeLen);
    if (!reply.WriteInt32(retReply)) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "OnNodeOnlineStateChangedInner write reply failed!");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int32_t SoftBusClientStub::OnNodeBasicInfoChangedInner(MessageParcel &data, MessageParcel &reply)
{
    int32_t type;
    if (!data.ReadInt32(type)) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "OnNodeBasicInfoChangedInner read type failed!");
        return SOFTBUS_ERR;
    }
    SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_INFO, "OnNodeBasicInfoChangedInner type %d", type);
    uint32_t infoTypeLen;
    if (!data.ReadUint32(infoTypeLen) || infoTypeLen != sizeof(NodeBasicInfo)) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR,
            "OnNodeBasicInfoChangedInner read info type length:%d failed!", infoTypeLen);
        return SOFTBUS_ERR;
    }
    void *info = (void *)data.ReadRawData(infoTypeLen);
    if (info == nullptr) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "OnNodeBasicInfoChangedInner read basic info failed!");
        return SOFTBUS_ERR;
    }
    int32_t retReply = OnNodeBasicInfoChanged(info, infoTypeLen, type);
    if (!reply.WriteInt32(retReply)) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "OnNodeBasicInfoChangedInner write reply failed!");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int32_t SoftBusClientStub::OnTimeSyncResultInner(MessageParcel &data, MessageParcel &reply)
{
    uint32_t infoTypeLen;
    if (!data.ReadUint32(infoTypeLen) || infoTypeLen != sizeof(TimeSyncResultInfo)) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR,
            "OnTimeSyncResultInner read info length:%d failed!", infoTypeLen);
        return SOFTBUS_ERR;
    }
    void *info = (void *)data.ReadRawData(infoTypeLen);
    if (info == nullptr) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "OnTimeSyncResultInner read info failed!");
        return SOFTBUS_ERR;
    }
    int32_t retCode;
    if (!data.ReadInt32(retCode)) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "OnTimeSyncResultInner read retCode failed!");
        return SOFTBUS_ERR;
    }

    int32_t retReply = OnTimeSyncResult(info, infoTypeLen, retCode);
    if (!reply.WriteInt32(retReply)) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "OnTimeSyncResultInner write reply failed!");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int32_t SoftBusClientStub::OnPublishLNNResultInner(MessageParcel &data, MessageParcel &reply)
{
    int32_t publishId;
    if (!data.ReadInt32(publishId)) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "OnPublishLNNResultInner read publishId failed!");
        return SOFTBUS_ERR;
    }
    int32_t reason;
    if (!data.ReadInt32(reason)) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "OnPublishLNNResultInner read reason failed!");
        return SOFTBUS_ERR;
    }

    OnPublishLNNResult(publishId, reason);
    return SOFTBUS_OK;
}

int32_t SoftBusClientStub::OnRefreshLNNResultInner(MessageParcel &data, MessageParcel &reply)
{
    int32_t refreshId;
    if (!data.ReadInt32(refreshId)) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "OnRefreshLNNResultInner read publishId failed!");
        return SOFTBUS_ERR;
    }
    int32_t reason;
    if (!data.ReadInt32(reason)) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "OnRefreshLNNResultInner read reason failed!");
        return SOFTBUS_ERR;
    }

    OnRefreshLNNResult(refreshId, reason);
    return SOFTBUS_OK;
}

int32_t SoftBusClientStub::OnRefreshDeviceFoundInner(MessageParcel &data, MessageParcel &reply)
{
    uint32_t deviceLen;
    if (!data.ReadUint32(deviceLen) || deviceLen != sizeof(DeviceInfo)) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR,
            "OnRefreshDeviceFoundInner read info length:%d failed!", deviceLen);
        return SOFTBUS_ERR;
    }
    void *device = (void *)data.ReadRawData(deviceLen);
    if (device == nullptr) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "OnRefreshDeviceFoundInner read info failed!");
        return SOFTBUS_ERR;
    }
    OnRefreshDeviceFound(device, deviceLen);
    return SOFTBUS_OK;
}

int32_t SoftBusClientStub::OnJoinLNNResult(void *addr, uint32_t addrTypeLen, const char *networkId, int retCode)
{
    (void)addrTypeLen;
    return LnnOnJoinResult(addr, networkId, retCode);
}

int32_t SoftBusClientStub::OnJoinMetaNodeResult(void *addr, uint32_t addrTypeLen, const char *networkId, int retCode)
{
    (void)addrTypeLen;
    return MetaNodeOnJoinResult(addr, networkId, retCode);
}

int32_t SoftBusClientStub::OnLeaveLNNResult(const char *networkId, int retCode)
{
    return LnnOnLeaveResult(networkId, retCode);
}

int32_t SoftBusClientStub::OnLeaveMetaNodeResult(const char *networkId, int retCode)
{
    return MetaNodeOnLeaveResult(networkId, retCode);
}

int32_t SoftBusClientStub::OnNodeOnlineStateChanged(bool isOnline, void *info, uint32_t infoTypeLen)
{
    (void)infoTypeLen;
    return LnnOnNodeOnlineStateChanged(isOnline, info);
}

int32_t SoftBusClientStub::OnNodeBasicInfoChanged(void *info, uint32_t infoTypeLen, int32_t type)
{
    (void)infoTypeLen;
    return LnnOnNodeBasicInfoChanged(info, type);
}

int32_t SoftBusClientStub::OnTimeSyncResult(const void *info, uint32_t infoTypeLen, int32_t retCode)
{
    (void)infoTypeLen;
    return LnnOnTimeSyncResult(info, retCode);
}

void SoftBusClientStub::OnPublishLNNResult(int32_t publishId, int32_t reason)
{
    LnnOnPublishLNNResult(publishId, reason);
}

void SoftBusClientStub::OnRefreshLNNResult(int32_t refreshId, int32_t reason)
{
    LnnOnRefreshLNNResult(refreshId, reason);
}

void SoftBusClientStub::OnRefreshDeviceFound(const void *device, uint32_t deviceLen)
{
    (void)deviceLen;
    LnnOnRefreshDeviceFound(device);
}
} // namespace OHOS