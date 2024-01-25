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

#include <string>
#include "softbus_adapter_mem.h"

#include "softbus_client_stub.h"
#include "client_trans_session_manager.h"
#include "client_bus_center_manager.h"
#include "client_disc_manager.h"
#include "client_trans_channel_callback.h"
#include "comm_log.h"
#include "ipc_skeleton.h"
#include "ipc_types.h"
#include "message_parcel.h"
#include "securec.h"
#include "softbus_def.h"
#include "softbus_errcode.h"
#include "softbus_server_ipc_interface_code.h"

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
    memberFuncMap_[CLIENT_ON_LEAVE_RESULT] =
        &SoftBusClientStub::OnLeaveLNNResultInner;
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
    COMM_LOGD(COMM_SDK, "SoftBusClientStub::OnReceived, code=%{public}u", code);
    if (data.ReadInterfaceToken() != GetDescriptor()) {
        COMM_LOGE(COMM_SDK, "SoftBusClientStub: ReadInterfaceToken faild!");
        return SOFTBUS_ERR;
    }
    auto itFunc = memberFuncMap_.find(code);
    if (itFunc != memberFuncMap_.end()) {
        auto memberFunc = itFunc->second;
        if (memberFunc != nullptr) {
            return (this->*memberFunc)(data, reply);
        }
    }
    COMM_LOGI(COMM_SDK, "SoftBusClientStub: default case, need check.");
    return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
}

int32_t SoftBusClientStub::OnClientPermissonChangeInner(MessageParcel &data, MessageParcel &reply)
{
    int32_t state;
    if (!data.ReadInt32(state)) {
        COMM_LOGE(COMM_SDK, "OnClientPermissonChangeInner read state failed!");
        return SOFTBUS_ERR;
    }
    const char *pkgName = data.ReadCString();
    if (pkgName == nullptr) {
        COMM_LOGE(COMM_SDK, "OnClientPermissonChangeInner read pkgName failed!");
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
    return TransOnChannelClosed(channelId, channelType, SHUTDOWN_REASON_PEER);
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
        COMM_LOGE(COMM_SDK, "OnChannelOpenedInner read sessionName failed!");
        return SOFTBUS_ERR;
    }

    ChannelInfo channel = {0};
    if (!data.ReadInt32(channel.channelId)) {
        COMM_LOGE(COMM_SDK, "OnChannelOpenedInner read retCode failed!");
        return SOFTBUS_ERR;
    }
    if (!data.ReadInt32(channel.channelType)) {
        COMM_LOGE(COMM_SDK, "OnChannelOpenedInner read retCode failed!");
        return SOFTBUS_ERR;
    }
    if (channel.channelType == CHANNEL_TYPE_TCP_DIRECT) {
        channel.fd = data.ReadFileDescriptor();
    }
    if (!data.ReadBool(channel.isServer)) {
        COMM_LOGE(COMM_SDK, "OnChannelOpenedInner read retCode failed!");
        return SOFTBUS_ERR;
    }
    if (!data.ReadBool(channel.isEnabled)) {
        COMM_LOGE(COMM_SDK, "OnChannelOpenedInner read retCode failed!");
        return SOFTBUS_ERR;
    }
    if (!data.ReadBool(channel.isEncrypt)) {
        COMM_LOGE(COMM_SDK, "OnChannelOpenedInner read isEncrypt failed!");
        return SOFTBUS_ERR;
    }
    if (!data.ReadInt32(channel.peerUid)) {
        COMM_LOGE(COMM_SDK, "OnChannelOpenedInner read retCode failed!");
        return SOFTBUS_ERR;
    }
    if (!data.ReadInt32(channel.peerPid)) {
        COMM_LOGE(COMM_SDK, "OnChannelOpenedInner read retCode failed!");
        return SOFTBUS_ERR;
    }
    channel.groupId = (char *)data.ReadCString();
    if (channel.groupId == nullptr) {
        COMM_LOGE(COMM_SDK, "OnChannelOpenedInner read addr failed!");
        return SOFTBUS_ERR;
    }
    if (!data.ReadUint32(channel.keyLen)) {
        COMM_LOGE(COMM_SDK, "OnChannelOpenedInner len failed!");
        return SOFTBUS_ERR;
    }
    channel.sessionKey = (char *)data.ReadRawData(channel.keyLen);
    if (channel.sessionKey == nullptr) {
        COMM_LOGE(COMM_SDK, "OnChannelOpenedInner read addr failed!");
        return SOFTBUS_ERR;
    }
    channel.peerSessionName = (char *)data.ReadCString();
    if (channel.peerSessionName == nullptr) {
        COMM_LOGE(COMM_SDK, "OnChannelOpenedInner read addr failed!");
        return SOFTBUS_ERR;
    }
    channel.peerDeviceId = (char *)data.ReadCString();
    if (channel.peerDeviceId == nullptr) {
        COMM_LOGE(COMM_SDK, "OnChannelOpenedInner read addr failed!");
        return SOFTBUS_ERR;
    }
    data.ReadInt32(channel.businessType);
    if (channel.channelType == CHANNEL_TYPE_UDP) {
        channel.myIp = (char *)data.ReadCString();
        if (channel.myIp == nullptr) {
            COMM_LOGE(COMM_SDK, "channel.myIp read addr failed!");
            return SOFTBUS_ERR;
        }
        data.ReadInt32(channel.streamType);
        data.ReadBool(channel.isUdpFile);
        if (!channel.isServer) {
            data.ReadInt32(channel.peerPort);
            channel.peerIp = (char *)data.ReadCString();
            if (channel.peerIp == nullptr) {
                COMM_LOGE(COMM_SDK, "channel.peerIp read addr failed!");
                return SOFTBUS_ERR;
            }
        }
    }
    data.ReadInt32(channel.routeType);
    data.ReadInt32(channel.encrypt);
    data.ReadInt32(channel.algorithm);
    data.ReadInt32(channel.crc);
    if (!data.ReadUint32(channel.dataConfig)) {
        COMM_LOGE(COMM_SDK, "OnChannelOpenedInner data config failed!");
        return SOFTBUS_ERR;
    }

    int ret = OnChannelOpened(sessionName, &channel);
    bool res = reply.WriteInt32(ret);
    if (!res) {
        COMM_LOGE(COMM_SDK, "OnChannelOpenedInner write reply failed!");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int32_t SoftBusClientStub::OnChannelOpenFailedInner(MessageParcel &data, MessageParcel &reply)
{
    int32_t channelId;
    if (!data.ReadInt32(channelId)) {
        COMM_LOGE(COMM_SDK, "OnChannelOpenFailedInner read channel id failed!");
        return SOFTBUS_ERR;
    }

    int32_t channelType;
    if (!data.ReadInt32(channelType)) {
        COMM_LOGE(COMM_SDK, "OnChannelOpenFailedInner read channel type failed!");
        return SOFTBUS_ERR;
    }

    int32_t errCode;
    if (!data.ReadInt32(errCode)) {
        COMM_LOGE(COMM_SDK, "OnChannelOpenFailedInner read channel type failed!");
        return SOFTBUS_ERR;
    }
    
    int32_t ret = OnChannelOpenFailed(channelId, channelType, errCode);
    if (ret != SOFTBUS_OK) {
        COMM_LOGE(COMM_SDK, "OnChannelOpenFailed failed! ret=%{public}d.", ret);
    }
    return ret;
}

int32_t SoftBusClientStub::OnChannelLinkDownInner(MessageParcel &data, MessageParcel &reply)
{
    const char *networkId = data.ReadCString();
    if (networkId == nullptr) {
        COMM_LOGE(COMM_SDK, "OnChannelLinkDownInner read networkId failed!");
        return SOFTBUS_ERR;
    }
    COMM_LOGD(COMM_SDK, "SDK OnChannelMsgReceived");
    int32_t routeType;
    if (!data.ReadInt32(routeType)) {
        COMM_LOGE(COMM_SDK, "OnChannelLinkDownInner read routeType failed!");
        return SOFTBUS_ERR;
    }
    int32_t retReply = OnChannelLinkDown(networkId, routeType);
    if (retReply != SOFTBUS_OK) {
        COMM_LOGE(COMM_SDK, "OnChannelLinkDown proc error!");
    }
    return SOFTBUS_OK;
}

int32_t SoftBusClientStub::OnChannelClosedInner(MessageParcel &data, MessageParcel &reply)
{
    int32_t channelId;
    if (!data.ReadInt32(channelId)) {
        COMM_LOGE(COMM_SDK, "OnChannelClosedInner read channel id failed!");
        return SOFTBUS_ERR;
    }

    int32_t channelType;
    if (!data.ReadInt32(channelType)) {
        COMM_LOGE(COMM_SDK, "OnChannelOpenFailedInner read channel type failed!");
        return SOFTBUS_ERR;
    }

    int ret = OnChannelClosed(channelId, channelType);
    bool res = reply.WriteInt32(ret);
    if (!res) {
        COMM_LOGE(COMM_SDK, "OnChannelClosedInner write reply failed!");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int32_t SoftBusClientStub::OnChannelMsgReceivedInner(MessageParcel &data, MessageParcel &reply)
{
    int32_t channelId;
    if (!data.ReadInt32(channelId)) {
        COMM_LOGE(COMM_SDK, "OnChannelMsgReceivedInner read channel id failed!");
        return SOFTBUS_ERR;
    }
    int32_t channelType;
    if (!data.ReadInt32(channelType)) {
        COMM_LOGE(COMM_SDK, "OnChannelMsgReceivedInner read channel type failed!");
        return SOFTBUS_ERR;
    }
    uint32_t len;
    if (!data.ReadUint32(len)) {
        COMM_LOGE(COMM_SDK, "OnChannelMsgReceivedInner read data len failed!");
        return SOFTBUS_ERR;
    }
    char *dataInfo = (char *)data.ReadRawData(len);
    if (dataInfo == nullptr) {
        COMM_LOGE(COMM_SDK, "OnChannelOpenedInner read dataInfo failed!");
        return SOFTBUS_ERR;
    }
    int32_t type;
    if (!data.ReadInt32(type)) {
        COMM_LOGE(COMM_SDK, "OnChannelMsgReceivedInner read type failed!");
        return SOFTBUS_ERR;
    }
    char *infoData = (char *)SoftBusMalloc(len);
    if (infoData == NULL) {
        COMM_LOGE(COMM_SDK, "malloc infoData failed!");
        return SOFTBUS_ERR;
    }
    memcpy_s(infoData, len, dataInfo, len);
    int ret = OnChannelMsgReceived(channelId, channelType, infoData, len, type);
    SoftBusFree(infoData);
    bool res = reply.WriteInt32(ret);
    if (!res) {
        COMM_LOGE(COMM_SDK, "OnChannelMsgReceivedInner write reply failed!");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int32_t SoftBusClientStub::OnChannelQosEventInner(MessageParcel &data, MessageParcel &reply)
{
    COMM_LOGI(COMM_EVENT, "OnChannelQosEventInner");
    int32_t channelId;
    if (!data.ReadInt32(channelId)) {
        COMM_LOGE(COMM_SDK, "OnChannelQosEventInner read channel id failed!");
        return SOFTBUS_ERR;
    }
    int32_t channelType;
    if (!data.ReadInt32(channelType)) {
        COMM_LOGE(COMM_SDK, "OnChannelQosEventInner read channel type failed!");
        return SOFTBUS_ERR;
    }
    int32_t eventId;
    if (!data.ReadInt32(eventId)) {
        COMM_LOGE(COMM_SDK, "OnChannelQosEventInner read eventId failed!");
        return SOFTBUS_ERR;
    }
    int32_t tvCount;
    if (!data.ReadInt32(tvCount) || tvCount <= 0) {
        COMM_LOGE(COMM_SDK, "OnChannelQosEventInner read tv failed! count=%{public}d", tvCount);
        return SOFTBUS_ERR;
    }
    QosTv *tvList = (QosTv *)data.ReadRawData(sizeof(QosTv) * tvCount);
    if (tvList == nullptr) {
        COMM_LOGE(COMM_SDK, "OnChannelQosEventInner read tv list failed!");
        return SOFTBUS_ERR;
    }
    int ret = OnChannelQosEvent(channelId, channelType, eventId, tvCount, tvList);
    bool res = reply.WriteInt32(ret);
    if (!res) {
        COMM_LOGE(COMM_SDK, "OnChannelQosEventInner write reply failed!");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int32_t SoftBusClientStub::OnJoinLNNResultInner(MessageParcel &data, MessageParcel &reply)
{
    uint32_t addrTypeLen;
    if (!data.ReadUint32(addrTypeLen) || addrTypeLen != sizeof(ConnectionAddr)) {
        COMM_LOGE(COMM_SDK, "OnJoinLNNResultInner read addr type failed! length=%{public}d", addrTypeLen);
        return SOFTBUS_ERR;
    }
    void *addr = (void *)data.ReadRawData(addrTypeLen);
    if (addr == nullptr) {
        COMM_LOGE(COMM_SDK, "OnJoinLNNResultInner read addr failed!");
        return SOFTBUS_ERR;
    }
    int32_t retCode;
    if (!data.ReadInt32(retCode)) {
        COMM_LOGE(COMM_SDK, "OnJoinLNNResultInner read retCode failed!");
        return SOFTBUS_ERR;
    }
    const char *networkId = nullptr;
    if (retCode == 0) {
        networkId = data.ReadCString();
        if (networkId == nullptr) {
            COMM_LOGE(COMM_SDK, "OnJoinLNNResultInner read networkId failed!");
            return SOFTBUS_ERR;
        }
    }
    int32_t retReply = OnJoinLNNResult(addr, addrTypeLen, networkId, retCode);
    if (retReply != SOFTBUS_OK) {
        COMM_LOGE(COMM_SDK, "OnJoinLNNResultInner notify join result failed!");
    }
    return SOFTBUS_OK;
}

int32_t SoftBusClientStub::OnLeaveLNNResultInner(MessageParcel &data, MessageParcel &reply)
{
    const char *networkId = data.ReadCString();
    if (networkId == nullptr) {
        COMM_LOGE(COMM_SDK, "OnLeaveLNNResultInner read networkId failed!");
        return SOFTBUS_ERR;
    }
    int32_t retCode;
    if (!data.ReadInt32(retCode)) {
        COMM_LOGE(COMM_SDK, "OnLeaveLNNResultInner read retCode failed!");
        return SOFTBUS_ERR;
    }
    int32_t retReply = OnLeaveLNNResult(networkId, retCode);
    if (retReply != SOFTBUS_OK) {
        COMM_LOGE(COMM_SDK, "OnLeaveLNNResultInner notify leave result failed!");
    }
    return SOFTBUS_OK;
}

int32_t SoftBusClientStub::OnNodeOnlineStateChangedInner(MessageParcel &data, MessageParcel &reply)
{
    const char *pkgName = data.ReadCString();
    if (strlen(pkgName) == 0) {
        COMM_LOGE(COMM_SDK, "Invalid package name, length is zero");
        return SOFTBUS_ERR;
    }
    bool isOnline = false;
    if (!data.ReadBool(isOnline)) {
        COMM_LOGE(COMM_SDK, "OnNodeOnlineStateChangedInner read online state failed!");
        return SOFTBUS_ERR;
    }
    uint32_t infoTypeLen;
    if (!data.ReadUint32(infoTypeLen) || infoTypeLen != sizeof(NodeBasicInfo)) {
        COMM_LOGE(COMM_SDK, "OnNodeOnlineStateChangedInner read info type failed! length=%{public}d", infoTypeLen);
        return SOFTBUS_ERR;
    }
    void *info = (void *)data.ReadRawData(infoTypeLen);
    if (info == nullptr) {
        COMM_LOGE(COMM_SDK, "OnNodeOnlineStateChangedInner read basic info failed!");
        return SOFTBUS_ERR;
    }
    int32_t retReply = OnNodeOnlineStateChanged(pkgName, isOnline, info, infoTypeLen);
    if (!reply.WriteInt32(retReply)) {
        COMM_LOGE(COMM_SDK, "OnNodeOnlineStateChangedInner write reply failed!");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int32_t SoftBusClientStub::OnNodeBasicInfoChangedInner(MessageParcel &data, MessageParcel &reply)
{
    const char *pkgName = data.ReadCString();
    if (strlen(pkgName) == 0) {
        COMM_LOGE(COMM_SDK, "Invalid package name, length is zero");
        return SOFTBUS_ERR;
    }
    int32_t type;
    if (!data.ReadInt32(type)) {
        COMM_LOGE(COMM_SDK, "OnNodeBasicInfoChangedInner read type failed!");
        return SOFTBUS_ERR;
    }
    COMM_LOGI(COMM_SDK, "OnNodeBasicInfoChangedInner type. type=%{public}d", type);
    uint32_t infoTypeLen;
    if (!data.ReadUint32(infoTypeLen) || infoTypeLen != sizeof(NodeBasicInfo)) {
        COMM_LOGE(COMM_SDK, "OnNodeBasicInfoChangedInner read failed! infoTypeLen=%{public}d", infoTypeLen);
        return SOFTBUS_ERR;
    }
    void *info = (void *)data.ReadRawData(infoTypeLen);
    if (info == nullptr) {
        COMM_LOGE(COMM_SDK, "OnNodeBasicInfoChangedInner read basic info failed!");
        return SOFTBUS_ERR;
    }
    int32_t retReply = OnNodeBasicInfoChanged(pkgName, info, infoTypeLen, type);
    if (!reply.WriteInt32(retReply)) {
        COMM_LOGE(COMM_SDK, "OnNodeBasicInfoChangedInner write reply failed!");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int32_t SoftBusClientStub::OnTimeSyncResultInner(MessageParcel &data, MessageParcel &reply)
{
    uint32_t infoTypeLen;
    if (!data.ReadUint32(infoTypeLen) || infoTypeLen != sizeof(TimeSyncResultInfo)) {
        COMM_LOGE(COMM_SDK, "OnTimeSyncResultInner read info failed! length=%{public}d", infoTypeLen);
        return SOFTBUS_ERR;
    }
    void *info = (void *)data.ReadRawData(infoTypeLen);
    if (info == nullptr) {
        COMM_LOGE(COMM_SDK, "OnTimeSyncResultInner read info failed!");
        return SOFTBUS_ERR;
    }
    int32_t retCode;
    if (!data.ReadInt32(retCode)) {
        COMM_LOGE(COMM_SDK, "OnTimeSyncResultInner read retCode failed!");
        return SOFTBUS_ERR;
    }

    int32_t retReply = OnTimeSyncResult(info, infoTypeLen, retCode);
    if (!reply.WriteInt32(retReply)) {
        COMM_LOGE(COMM_SDK, "OnTimeSyncResultInner write reply failed!");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int32_t SoftBusClientStub::OnPublishLNNResultInner(MessageParcel &data, MessageParcel &reply)
{
    int32_t publishId;
    if (!data.ReadInt32(publishId)) {
        COMM_LOGE(COMM_SDK, "OnPublishLNNResultInner read publishId failed!");
        return SOFTBUS_ERR;
    }
    int32_t reason;
    if (!data.ReadInt32(reason)) {
        COMM_LOGE(COMM_SDK, "OnPublishLNNResultInner read reason failed!");
        return SOFTBUS_ERR;
    }

    OnPublishLNNResult(publishId, reason);
    return SOFTBUS_OK;
}

int32_t SoftBusClientStub::OnRefreshLNNResultInner(MessageParcel &data, MessageParcel &reply)
{
    int32_t refreshId;
    if (!data.ReadInt32(refreshId)) {
        COMM_LOGE(COMM_SDK, "OnRefreshLNNResultInner read publishId failed!");
        return SOFTBUS_ERR;
    }
    int32_t reason;
    if (!data.ReadInt32(reason)) {
        COMM_LOGE(COMM_SDK, "OnRefreshLNNResultInner read reason failed!");
        return SOFTBUS_ERR;
    }

    OnRefreshLNNResult(refreshId, reason);
    return SOFTBUS_OK;
}

int32_t SoftBusClientStub::OnRefreshDeviceFoundInner(MessageParcel &data, MessageParcel &reply)
{
    uint32_t deviceLen;
    if (!data.ReadUint32(deviceLen) || deviceLen != sizeof(DeviceInfo)) {
        COMM_LOGE(COMM_SDK, "OnRefreshDeviceFoundInner read info failed! length=%{public}d", deviceLen);
        return SOFTBUS_ERR;
    }
    void *device = (void *)data.ReadRawData(deviceLen);
    if (device == nullptr) {
        COMM_LOGE(COMM_SDK, "OnRefreshDeviceFoundInner read info failed!");
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

int32_t SoftBusClientStub::OnLeaveLNNResult(const char *networkId, int retCode)
{
    return LnnOnLeaveResult(networkId, retCode);
}

int32_t SoftBusClientStub::OnNodeOnlineStateChanged(const char *pkgName, bool isOnline,
    void *info, uint32_t infoTypeLen)
{
    (void)infoTypeLen;
    return LnnOnNodeOnlineStateChanged(pkgName, isOnline, info);
}

int32_t SoftBusClientStub::OnNodeBasicInfoChanged(const char *pkgName, void *info, uint32_t infoTypeLen, int32_t type)
{
    (void)infoTypeLen;
    return LnnOnNodeBasicInfoChanged(pkgName, info, type);
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