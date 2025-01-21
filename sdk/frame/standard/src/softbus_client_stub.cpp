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

#include "softbus_client_stub.h"

#include <string>

#include "client_bus_center_manager.h"
#include "client_trans_channel_callback.h"
#include "client_trans_session_manager.h"
#include "client_trans_socket_manager.h"
#include "comm_log.h"
#include "ipc_skeleton.h"
#include "ipc_types.h"
#include "message_parcel.h"
#include "securec.h"
#include "session_set_timer.h"
#include "softbus_adapter_mem.h"
#include "softbus_def.h"
#include "softbus_error_code.h"
#include "softbus_server_ipc_interface_code.h"
#include "client_trans_udp_manager.h"

namespace OHOS {
static constexpr uint32_t DFX_TIMERS_S = 15;

SoftBusClientStub::SoftBusClientStub()
{
    memberFuncMap_[CLIENT_ON_CHANNEL_OPENED] = &SoftBusClientStub::OnChannelOpenedInner;
    memberFuncMap_[CLIENT_ON_CHANNEL_OPENFAILED] = &SoftBusClientStub::OnChannelOpenFailedInner;
    memberFuncMap_[CLIENT_ON_CHANNEL_LINKDOWN] = &SoftBusClientStub::OnChannelLinkDownInner;
    memberFuncMap_[CLIENT_ON_CHANNEL_CLOSED] = &SoftBusClientStub::OnChannelClosedInner;
    memberFuncMap_[CLIENT_ON_CHANNEL_MSGRECEIVED] = &SoftBusClientStub::OnChannelMsgReceivedInner;
    memberFuncMap_[CLIENT_ON_CHANNEL_QOSEVENT] = &SoftBusClientStub::OnChannelQosEventInner;
    memberFuncMap_[CLIENT_ON_JOIN_RESULT] = &SoftBusClientStub::OnJoinLNNResultInner;
    memberFuncMap_[CLIENT_ON_LEAVE_RESULT] = &SoftBusClientStub::OnLeaveLNNResultInner;
    memberFuncMap_[CLIENT_ON_NODE_ONLINE_STATE_CHANGED] = &SoftBusClientStub::OnNodeOnlineStateChangedInner;
    memberFuncMap_[CLIENT_ON_NODE_BASIC_INFO_CHANGED] = &SoftBusClientStub::OnNodeBasicInfoChangedInner;
    memberFuncMap_[CLIENT_ON_NODE_STATUS_CHANGED] = &SoftBusClientStub::OnNodeStatusChangedInner;
    memberFuncMap_[CLIENT_ON_LOCAL_NETWORK_ID_CHANGED] = &SoftBusClientStub::OnLocalNetworkIdChangedInner;
    memberFuncMap_[CLIENT_ON_NODE_DEVICE_TRUST_CHANGED] = &SoftBusClientStub::OnNodeDeviceTrustedChangeInner;
    memberFuncMap_[CLIENT_ON_HICHAIN_PROOF_EXCEPTION] = &SoftBusClientStub::OnHichainProofExceptionInner;
    memberFuncMap_[CLIENT_ON_TIME_SYNC_RESULT] = &SoftBusClientStub::OnTimeSyncResultInner;
    memberFuncMap_[CLIENT_ON_PUBLISH_LNN_RESULT] = &SoftBusClientStub::OnPublishLNNResultInner;
    memberFuncMap_[CLIENT_ON_REFRESH_LNN_RESULT] = &SoftBusClientStub::OnRefreshLNNResultInner;
    memberFuncMap_[CLIENT_ON_REFRESH_DEVICE_FOUND] = &SoftBusClientStub::OnRefreshDeviceFoundInner;
    memberFuncMap_[CLIENT_ON_PERMISSION_CHANGE] = &SoftBusClientStub::OnClientPermissonChangeInner;
    memberFuncMap_[CLIENT_SET_CHANNEL_INFO] = &SoftBusClientStub::SetChannelInfoInner;
    memberFuncMap_[CLIENT_ON_DATA_LEVEL_CHANGED] = &SoftBusClientStub::OnDataLevelChangedInner;
    memberFuncMap_[CLIENT_ON_TRANS_LIMIT_CHANGE] = &SoftBusClientStub::OnClientTransLimitChangeInner;
    memberFuncMap_[CLIENT_ON_CHANNEL_BIND] = &SoftBusClientStub::OnChannelBindInner;
    memberFuncMap_[CLIENT_CHANNEL_ON_QOS] = &SoftBusClientStub::OnChannelOnQosInner;
    memberFuncMap_[CLIENT_CHECK_COLLAB_RELATION] = &SoftBusClientStub::OnCheckCollabRelationInner;
}

int32_t SoftBusClientStub::OnRemoteRequest(uint32_t code,
    MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    COMM_LOGD(COMM_SDK, "SoftBusClientStub::OnReceived, code=%{public}u", code);
    if (data.ReadInterfaceToken() != GetDescriptor()) {
        COMM_LOGE(COMM_SDK, "SoftBusClientStub: ReadInterfaceToken faild!");
        return SOFTBUS_TRANS_PROXY_READTOKEN_FAILED;
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
    COMM_CHECK_AND_RETURN_RET_LOGE(
        data.ReadInt32(state), SOFTBUS_TRANS_PROXY_READINT_FAILED, COMM_SDK, "read state failed");

    const char *pkgName = data.ReadCString();
    COMM_CHECK_AND_RETURN_RET_LOGE(
        pkgName != nullptr, SOFTBUS_TRANS_PROXY_READCSTRING_FAILED, COMM_SDK, "read pkgName failed");

    PermissionStateChange(pkgName, state);
    return SOFTBUS_OK;
}

int32_t SoftBusClientStub::OnClientTransLimitChangeInner(MessageParcel &data, MessageParcel &reply)
{
    int32_t channelId;
    COMM_CHECK_AND_RETURN_RET_LOGE(
        data.ReadInt32(channelId), SOFTBUS_TRANS_PROXY_READRAWDATA_FAILED, COMM_SDK, "read channelId failed");

    uint8_t tos;
    COMM_CHECK_AND_RETURN_RET_LOGE(
        data.ReadUint8(tos), SOFTBUS_TRANS_PROXY_READRAWDATA_FAILED, COMM_SDK, "read tos failed");

    int32_t ret = OnClientTransLimitChange(channelId, tos);
    COMM_CHECK_AND_RETURN_RET_LOGE(
        reply.WriteInt32(ret), SOFTBUS_TRANS_PROXY_WRITERAWDATA_FAILED, COMM_SDK, "write reply failed");

    return SOFTBUS_OK;
}

int32_t SoftBusClientStub::OnClientTransLimitChange(int32_t channelId, uint8_t tos)
{
    return TransLimitChange(channelId, tos);
}

int32_t SoftBusClientStub::OnChannelOpened(const char *sessionName, const ChannelInfo *info)
{
    int32_t id = SetTimer("OnChannelOpened", DFX_TIMERS_S);
    int32_t ret = TransOnChannelOpened(sessionName, info);
    CancelTimer(id);
    return ret;
}

int32_t SoftBusClientStub::OnChannelOpenFailed(int32_t channelId, int32_t channelType, int32_t errCode)
{
    return TransOnChannelOpenFailed(channelId, channelType, errCode);
}

int32_t SoftBusClientStub::OnChannelLinkDown(const char *networkId, int32_t routeType)
{
    return TransOnChannelLinkDown(networkId, routeType);
}

int32_t SoftBusClientStub::OnChannelClosed(int32_t channelId, int32_t channelType, int32_t messageType)
{
    return TransOnChannelClosed(channelId, channelType, messageType, SHUTDOWN_REASON_PEER);
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

int32_t SoftBusClientStub::SetChannelInfo(
    const char *sessionName, int32_t sessionId, int32_t channelId, int32_t channelType)
{
    return TransSetChannelInfo(sessionName, sessionId, channelId, channelType);
}

static int32_t MessageTcpParcelRead(MessageParcel &data, ChannelInfo *channel)
{
    if (channel->channelType == CHANNEL_TYPE_TCP_DIRECT) {
        channel->fd = data.ReadFileDescriptor();
        channel->myIp = (char *)data.ReadCString();
        COMM_CHECK_AND_RETURN_RET_LOGE(channel->myIp != nullptr, SOFTBUS_IPC_ERR, COMM_SDK, "read myIp failed");
    }
    return SOFTBUS_OK;
}

static int32_t MessageParcelRead(MessageParcel &data, ChannelInfo *channel)
{
    READ_PARCEL_WITH_RET(data, Int32, channel->channelId, SOFTBUS_IPC_ERR);
    READ_PARCEL_WITH_RET(data, Int32, channel->channelType, SOFTBUS_IPC_ERR);
    READ_PARCEL_WITH_RET(data, Uint64, channel->laneId, SOFTBUS_IPC_ERR);
    READ_PARCEL_WITH_RET(data, Int32, channel->connectType, SOFTBUS_IPC_ERR);
    int32_t ret = MessageTcpParcelRead(data, channel);
    COMM_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, SOFTBUS_IPC_ERR, COMM_SDK, "read tcp ip or fd failed");
    READ_PARCEL_WITH_RET(data, Bool, channel->isServer, SOFTBUS_IPC_ERR);
    READ_PARCEL_WITH_RET(data, Bool, channel->isEnabled, SOFTBUS_IPC_ERR);
    READ_PARCEL_WITH_RET(data, Bool, channel->isEncrypt, SOFTBUS_IPC_ERR);
    READ_PARCEL_WITH_RET(data, Int32, channel->peerUid, SOFTBUS_IPC_ERR);
    READ_PARCEL_WITH_RET(data, Int32, channel->peerPid, SOFTBUS_IPC_ERR);
    channel->groupId = (char *)data.ReadCString();
    COMM_CHECK_AND_RETURN_RET_LOGE(channel->groupId != nullptr, SOFTBUS_IPC_ERR, COMM_SDK, "read groupId failed");
    COMM_CHECK_AND_RETURN_RET_LOGE(channel->keyLen <= SESSION_KEY_LENGTH, SOFTBUS_IPC_ERR, COMM_SDK,
        "channel->keyLen invalid");
    READ_PARCEL_WITH_RET(data, Uint32, channel->keyLen, SOFTBUS_IPC_ERR);
    channel->sessionKey = (char *)data.ReadRawData(channel->keyLen);
    COMM_CHECK_AND_RETURN_RET_LOGE(channel->sessionKey != nullptr, SOFTBUS_IPC_ERR, COMM_SDK, "read rawData failed");
    channel->peerSessionName = (char *)data.ReadCString();
    COMM_CHECK_AND_RETURN_RET_LOGE(
        channel->peerSessionName != nullptr, SOFTBUS_IPC_ERR, COMM_SDK, "read peerSessionName failed");
    channel->peerDeviceId = (char *)data.ReadCString();
    COMM_CHECK_AND_RETURN_RET_LOGE(
        channel->peerDeviceId != nullptr, SOFTBUS_IPC_ERR, COMM_SDK, "read peerDeviceId failed");
    READ_PARCEL_WITH_RET(data, Int32, channel->businessType, SOFTBUS_IPC_ERR);
    if (channel->channelType == CHANNEL_TYPE_UDP) {
        channel->myIp = (char *)data.ReadCString();
        COMM_CHECK_AND_RETURN_RET_LOGE(channel->myIp != nullptr, SOFTBUS_IPC_ERR, COMM_SDK, "read myIp failed");
        READ_PARCEL_WITH_RET(data, Int32, channel->streamType, SOFTBUS_IPC_ERR);
        READ_PARCEL_WITH_RET(data, Bool, channel->isUdpFile, SOFTBUS_IPC_ERR);
        if (!channel->isServer) {
            READ_PARCEL_WITH_RET(data, Int32, channel->peerPort, SOFTBUS_IPC_ERR);
            channel->peerIp = (char *)data.ReadCString();
            COMM_CHECK_AND_RETURN_RET_LOGE(
                channel->peerIp != nullptr, SOFTBUS_IPC_ERR, COMM_SDK, "read channel.peerIp failed");
        }
    }
    READ_PARCEL_WITH_RET(data, Int32, channel->routeType, SOFTBUS_IPC_ERR);
    READ_PARCEL_WITH_RET(data, Int32, channel->encrypt, SOFTBUS_IPC_ERR);
    READ_PARCEL_WITH_RET(data, Int32, channel->algorithm, SOFTBUS_IPC_ERR);
    READ_PARCEL_WITH_RET(data, Int32, channel->crc, SOFTBUS_IPC_ERR);
    READ_PARCEL_WITH_RET(data, Uint32, channel->dataConfig, SOFTBUS_IPC_ERR);
    READ_PARCEL_WITH_RET(data, Int32, channel->linkType, SOFTBUS_IPC_ERR);
    READ_PARCEL_WITH_RET(data, Int32, channel->osType, SOFTBUS_IPC_ERR);
    READ_PARCEL_WITH_RET(data, Bool, channel->isSupportTlv, SOFTBUS_IPC_ERR);
    return SOFTBUS_OK;
}

int32_t SoftBusClientStub::OnChannelOpenedInner(MessageParcel &data, MessageParcel &reply)
{
    const char *sessionName = data.ReadCString();
    COMM_CHECK_AND_RETURN_RET_LOGE(sessionName != nullptr, SOFTBUS_IPC_ERR, COMM_SDK, "read sessionName failed");

    ChannelInfo channel = { 0 };
    int32_t ret = MessageParcelRead(data, &channel);
    if (ret != SOFTBUS_OK) {
        (void)memset_s(&channel, sizeof(ChannelInfo), 0, sizeof(ChannelInfo));
        COMM_LOGE(COMM_SDK, "read channel info failed");
        return ret;
    }

    ret = OnChannelOpened(sessionName, &channel);
    COMM_CHECK_AND_RETURN_RET_LOGE(reply.WriteInt32(ret), SOFTBUS_IPC_ERR, COMM_SDK, "write reply failed");
    return SOFTBUS_OK;
}

int32_t SoftBusClientStub::OnChannelOpenFailedInner(MessageParcel &data, MessageParcel &reply)
{
    int32_t channelId;
    COMM_CHECK_AND_RETURN_RET_LOGE(
        data.ReadInt32(channelId), SOFTBUS_TRANS_PROXY_READINT_FAILED, COMM_SDK, "read channelId failed");

    int32_t channelType;
    COMM_CHECK_AND_RETURN_RET_LOGE(
        data.ReadInt32(channelType), SOFTBUS_TRANS_PROXY_READINT_FAILED, COMM_SDK, "read channelType failed");

    int32_t errCode;
    COMM_CHECK_AND_RETURN_RET_LOGE(
        data.ReadInt32(errCode), SOFTBUS_TRANS_PROXY_READINT_FAILED, COMM_SDK, "read errCode failed");
    
    int32_t ret = OnChannelOpenFailed(channelId, channelType, errCode);
    COMM_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, COMM_SDK, "OnChannelOpenFailed fail! ret=%{public}d", ret);

    return SOFTBUS_OK;
}

int32_t SoftBusClientStub::OnChannelLinkDownInner(MessageParcel &data, MessageParcel &reply)
{
    const char *networkId = data.ReadCString();
    COMM_CHECK_AND_RETURN_RET_LOGE(
        networkId != nullptr, SOFTBUS_TRANS_PROXY_READCSTRING_FAILED, COMM_SDK, "read networkId failed!");

    COMM_LOGD(COMM_SDK, "SDK OnChannelMsgReceived");
    int32_t routeType;
    COMM_CHECK_AND_RETURN_RET_LOGE(
        data.ReadInt32(routeType), SOFTBUS_TRANS_PROXY_READINT_FAILED, COMM_SDK, "read routeType failed");

    int32_t retReply = OnChannelLinkDown(networkId, routeType);
    if (retReply != SOFTBUS_OK) {
        COMM_LOGE(COMM_SDK, "OnChannelLinkDown proc error!");
    }
    return SOFTBUS_OK;
}

int32_t SoftBusClientStub::OnChannelClosedInner(MessageParcel &data, MessageParcel &reply)
{
    int32_t channelId;
    COMM_CHECK_AND_RETURN_RET_LOGE(data.ReadInt32(channelId), SOFTBUS_IPC_ERR, COMM_SDK, "read channelId failed");

    int32_t channelType;
    COMM_CHECK_AND_RETURN_RET_LOGE(data.ReadInt32(channelType), SOFTBUS_IPC_ERR, COMM_SDK, "read channelType failed");

    int32_t messageType;
    COMM_CHECK_AND_RETURN_RET_LOGE(data.ReadInt32(messageType), SOFTBUS_IPC_ERR, COMM_SDK, "read messageType failed");

    int32_t ret = OnChannelClosed(channelId, channelType, messageType);
    COMM_CHECK_AND_RETURN_RET_LOGE(reply.WriteInt32(ret), SOFTBUS_IPC_ERR, COMM_SDK, "write reply failed");

    return SOFTBUS_OK;
}

int32_t SoftBusClientStub::OnChannelMsgReceivedInner(MessageParcel &data, MessageParcel &reply)
{
    int32_t channelId;
    COMM_CHECK_AND_RETURN_RET_LOGE(
        data.ReadInt32(channelId), SOFTBUS_TRANS_PROXY_READINT_FAILED, COMM_SDK, "read channelId failed");

    int32_t channelType;
    COMM_CHECK_AND_RETURN_RET_LOGE(
        data.ReadInt32(channelType), SOFTBUS_TRANS_PROXY_READINT_FAILED, COMM_SDK, "read channelType failed");

    uint32_t len;
    COMM_CHECK_AND_RETURN_RET_LOGE(
        data.ReadUint32(len), SOFTBUS_TRANS_PROXY_READUINT_FAILED, COMM_SDK, "read data len failed");

    char *dataInfo = (char *)data.ReadRawData(len);
    COMM_CHECK_AND_RETURN_RET_LOGE(
        dataInfo != nullptr, SOFTBUS_TRANS_PROXY_READRAWDATA_FAILED, COMM_SDK, "read dataInfo failed!");

    int32_t type;
    COMM_CHECK_AND_RETURN_RET_LOGE(
        data.ReadInt32(type), SOFTBUS_TRANS_PROXY_READINT_FAILED, COMM_SDK, "read type failed");

    int ret = OnChannelMsgReceived(channelId, channelType, dataInfo, len, type);
    COMM_CHECK_AND_RETURN_RET_LOGE(
        reply.WriteInt32(ret), SOFTBUS_TRANS_PROXY_WRITEINT_FAILED, COMM_SDK, "write reply failed");

    return SOFTBUS_OK;
}

int32_t SoftBusClientStub::OnChannelQosEventInner(MessageParcel &data, MessageParcel &reply)
{
    COMM_LOGI(COMM_EVENT, "OnChannelQosEventInner");
    int32_t channelId;
    COMM_CHECK_AND_RETURN_RET_LOGE(
        data.ReadInt32(channelId), SOFTBUS_TRANS_PROXY_READINT_FAILED, COMM_SDK, "read channelId failed");

    int32_t channelType;
    COMM_CHECK_AND_RETURN_RET_LOGE(
        data.ReadInt32(channelType), SOFTBUS_TRANS_PROXY_READINT_FAILED, COMM_SDK, "read channelType failed");

    int32_t eventId;
    COMM_CHECK_AND_RETURN_RET_LOGE(
        data.ReadInt32(eventId), SOFTBUS_TRANS_PROXY_READINT_FAILED, COMM_SDK, "read eventId failed");

    int32_t tvCount;
    COMM_CHECK_AND_RETURN_RET_LOGE(data.ReadInt32(tvCount) && tvCount > 0 && tvCount <= STREAM_TRAFFIC_STASTICS,
        SOFTBUS_TRANS_PROXY_READINT_FAILED, COMM_SDK, "read tv failed! count=%{public}d", tvCount);

    QosTv *tvList = (QosTv *)data.ReadRawData(sizeof(QosTv) * tvCount);
    COMM_CHECK_AND_RETURN_RET_LOGE(
        tvList != nullptr, SOFTBUS_TRANS_PROXY_READRAWDATA_FAILED, COMM_SDK, "read tv list failed!");

    int ret = OnChannelQosEvent(channelId, channelType, eventId, tvCount, tvList);
    COMM_CHECK_AND_RETURN_RET_LOGE(
        reply.WriteInt32(ret), SOFTBUS_TRANS_PROXY_WRITEINT_FAILED, COMM_SDK, "write reply failed");

    return SOFTBUS_OK;
}

int32_t SoftBusClientStub::OnChannelOnQosInner(MessageParcel &data, MessageParcel &reply)
{
    COMM_LOGI(COMM_EVENT, "OnChannelOnQosInner");
    int32_t channelId;
    COMM_CHECK_AND_RETURN_RET_LOGE(
        data.ReadInt32(channelId), SOFTBUS_TRANS_PROXY_READINT_FAILED, COMM_SDK, "read channelId failed");

    int32_t channelType;
    COMM_CHECK_AND_RETURN_RET_LOGE(
        data.ReadInt32(channelType), SOFTBUS_TRANS_PROXY_READINT_FAILED, COMM_SDK, "read channelType failed");

    int32_t event;
    COMM_CHECK_AND_RETURN_RET_LOGE(
        data.ReadInt32(event), SOFTBUS_TRANS_PROXY_READINT_FAILED, COMM_SDK, "read event failed");

    uint32_t count;
    COMM_CHECK_AND_RETURN_RET_LOGE(
        data.ReadUint32(count), SOFTBUS_TRANS_PROXY_READINT_FAILED, COMM_SDK, "read count failed");
    COMM_CHECK_AND_RETURN_RET_LOGE(count < QOS_TYPE_BUTT, SOFTBUS_INVALID_PARAM, COMM_SDK, "invalid count");

    QosTV *qos = (QosTV *)data.ReadBuffer(sizeof(QosTV) * count);
    COMM_CHECK_AND_RETURN_RET_LOGE(
        qos != nullptr, SOFTBUS_TRANS_PROXY_READRAWDATA_FAILED, COMM_SDK, "read qos failed!");

    int32_t ret = OnClientChannelOnQos(channelId, channelType, (QoSEvent)event, qos, count);
    if (ret != SOFTBUS_OK) {
        COMM_LOGE(COMM_SDK, "OnClientChannelOnQos failed, ret=%{public}d", ret);
    }
    return SOFTBUS_OK;
}

int32_t SoftBusClientStub::SetChannelInfoInner(MessageParcel &data, MessageParcel &reply)
{
    const char *sessionName = data.ReadCString();
    COMM_CHECK_AND_RETURN_RET_LOGE(sessionName != nullptr, SOFTBUS_IPC_ERR, COMM_SDK, "read sessionName failed");

    int32_t sessionId;
    COMM_CHECK_AND_RETURN_RET_LOGE(data.ReadInt32(sessionId), SOFTBUS_IPC_ERR, COMM_SDK, "read sessionId failed");

    int32_t channelId;
    COMM_CHECK_AND_RETURN_RET_LOGE(data.ReadInt32(channelId), SOFTBUS_IPC_ERR, COMM_SDK, "read channelId failed");

    int32_t channelType;
    COMM_CHECK_AND_RETURN_RET_LOGE(data.ReadInt32(channelType), SOFTBUS_IPC_ERR, COMM_SDK, "read channelType failed");

    int ret = SetChannelInfo(sessionName, sessionId, channelId, channelType);
    COMM_CHECK_AND_RETURN_RET_LOGE(
        reply.WriteInt32(ret), SOFTBUS_TRANS_PROXY_WRITEINT_FAILED, COMM_SDK, "write reply failed");

    return SOFTBUS_OK;
}

int32_t SoftBusClientStub::OnJoinLNNResultInner(MessageParcel &data, MessageParcel &reply)
{
    uint32_t addrTypeLen;
    if (!data.ReadUint32(addrTypeLen) || addrTypeLen != sizeof(ConnectionAddr)) {
        COMM_LOGE(COMM_SDK, "OnJoinLNNResultInner read addr type failed! length=%{public}d", addrTypeLen);
        return SOFTBUS_TRANS_PROXY_READUINT_FAILED;
    }
    void *addr = (void *)data.ReadRawData(addrTypeLen);
    if (addr == nullptr) {
        COMM_LOGE(COMM_SDK, "OnJoinLNNResultInner read addr failed!");
        return SOFTBUS_TRANS_PROXY_READRAWDATA_FAILED;
    }
    int32_t retCode;
    if (!data.ReadInt32(retCode)) {
        COMM_LOGE(COMM_SDK, "OnJoinLNNResultInner read retCode failed!");
        return SOFTBUS_TRANS_PROXY_READINT_FAILED;
    }
    const char *networkId = nullptr;
    if (retCode == 0) {
        networkId = data.ReadCString();
        if (networkId == nullptr) {
            COMM_LOGE(COMM_SDK, "OnJoinLNNResultInner read networkId failed!");
            return SOFTBUS_TRANS_PROXY_READCSTRING_FAILED;
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
        return SOFTBUS_TRANS_PROXY_READCSTRING_FAILED;
    }
    int32_t retCode;
    if (!data.ReadInt32(retCode)) {
        COMM_LOGE(COMM_SDK, "OnLeaveLNNResultInner read retCode failed!");
        return SOFTBUS_TRANS_PROXY_READINT_FAILED;
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
    if (pkgName == nullptr || strlen(pkgName) == 0) {
        COMM_LOGE(COMM_SDK, "Invalid package name, or length is zero");
        return SOFTBUS_TRANS_PROXY_READCSTRING_FAILED;
    }
    bool isOnline = false;
    if (!data.ReadBool(isOnline)) {
        COMM_LOGE(COMM_SDK, "OnNodeOnlineStateChangedInner read online state failed!");
        return SOFTBUS_TRANS_PROXY_READBOOL_FAILED;
    }
    uint32_t infoTypeLen;
    if (!data.ReadUint32(infoTypeLen) || infoTypeLen != sizeof(NodeBasicInfo)) {
        COMM_LOGE(COMM_SDK, "OnNodeOnlineStateChangedInner read info type failed! length=%{public}d", infoTypeLen);
        return SOFTBUS_TRANS_PROXY_READUINT_FAILED;
    }
    void *info = (void *)data.ReadRawData(infoTypeLen);
    if (info == nullptr) {
        COMM_LOGE(COMM_SDK, "OnNodeOnlineStateChangedInner read basic info failed!");
        return SOFTBUS_TRANS_PROXY_READRAWDATA_FAILED;
    }
    int32_t retReply = OnNodeOnlineStateChanged(pkgName, isOnline, info, infoTypeLen);
    COMM_LOGI(COMM_SDK, "notify complete, pkgName=%{public}s, isOnline=%{public}d", pkgName, isOnline);
    if (!reply.WriteInt32(retReply)) {
        COMM_LOGE(COMM_SDK, "OnNodeOnlineStateChangedInner write reply failed!");
        return SOFTBUS_TRANS_PROXY_WRITEINT_FAILED;
    }
    return SOFTBUS_OK;
}

int32_t SoftBusClientStub::OnNodeBasicInfoChangedInner(MessageParcel &data, MessageParcel &reply)
{
    const char *pkgName = data.ReadCString();
    if (pkgName == nullptr || strlen(pkgName) == 0) {
        COMM_LOGE(COMM_SDK, "Invalid package name, or length is zero");
        return SOFTBUS_TRANS_PROXY_READCSTRING_FAILED;
    }
    int32_t type;
    if (!data.ReadInt32(type)) {
        COMM_LOGE(COMM_SDK, "OnNodeBasicInfoChangedInner read type failed!");
        return SOFTBUS_TRANS_PROXY_READINT_FAILED;
    }
    COMM_LOGD(COMM_SDK, "OnNodeBasicInfoChangedInner type. type=%{public}d", type);
    uint32_t infoTypeLen;
    if (!data.ReadUint32(infoTypeLen) || infoTypeLen != sizeof(NodeBasicInfo)) {
        COMM_LOGE(COMM_SDK, "OnNodeBasicInfoChangedInner read failed! infoTypeLen=%{public}d", infoTypeLen);
        return SOFTBUS_TRANS_PROXY_READUINT_FAILED;
    }
    void *info = (void *)data.ReadRawData(infoTypeLen);
    if (info == nullptr) {
        COMM_LOGE(COMM_SDK, "OnNodeBasicInfoChangedInner read basic info failed!");
        return SOFTBUS_TRANS_PROXY_READRAWDATA_FAILED;
    }
    int32_t retReply = OnNodeBasicInfoChanged(pkgName, info, infoTypeLen, type);
    if (!reply.WriteInt32(retReply)) {
        COMM_LOGE(COMM_SDK, "OnNodeBasicInfoChangedInner write reply failed!");
        return SOFTBUS_TRANS_PROXY_WRITEINT_FAILED;
    }
    return SOFTBUS_OK;
}

int32_t SoftBusClientStub::OnNodeStatusChangedInner(MessageParcel &data, MessageParcel &reply)
{
    const char *pkgName = data.ReadCString();
    if (pkgName == nullptr || strlen(pkgName) == 0) {
        COMM_LOGE(COMM_SDK, "Invalid package name, or length is zero");
        return SOFTBUS_INVALID_PARAM;
    }
    int32_t type;
    if (!data.ReadInt32(type)) {
        COMM_LOGE(COMM_SDK, "OnNodeStatusChangedInner read type failed!");
        return SOFTBUS_NETWORK_READINT32_FAILED;
    }
    COMM_LOGD(COMM_SDK, "OnNodeStatusChangedInner type=%{public}d", type);
    uint32_t infoTypeLen;
    if (!data.ReadUint32(infoTypeLen) || infoTypeLen != sizeof(NodeStatus)) {
        COMM_LOGE(COMM_SDK, "OnNodeStatusChangedInner read failed! infoTypeLen=%{public}d", infoTypeLen);
        return SOFTBUS_NETWORK_READINT32_FAILED;
    }
    void *info = (void *)data.ReadRawData(infoTypeLen);
    if (info == nullptr) {
        COMM_LOGE(COMM_SDK, "OnNodeStatusChangedInner read node status failed!");
        return SOFTBUS_NETWORK_READRAWDATA_FAILED;
    }
    int32_t retReply = OnNodeStatusChanged(pkgName, info, infoTypeLen, type);
    if (!reply.WriteInt32(retReply)) {
        COMM_LOGE(COMM_SDK, "OnNodeStatusChangedInner write reply failed!");
        return SOFTBUS_NETWORK_WRITEINT32_FAILED;
    }
    return SOFTBUS_OK;
}

int32_t SoftBusClientStub::OnLocalNetworkIdChangedInner(MessageParcel &data, MessageParcel &reply)
{
    const char *pkgName = data.ReadCString();
    if (pkgName == nullptr || strlen(pkgName) == 0) {
        COMM_LOGE(COMM_SDK, "Invalid package name, or length is zero");
        return SOFTBUS_INVALID_PARAM;
    }
    int32_t retReply = OnLocalNetworkIdChanged(pkgName);
    if (!reply.WriteInt32(retReply)) {
        COMM_LOGE(COMM_SDK, "OnLocalNetworkIdChangedInner write reply failed!");
        return SOFTBUS_IPC_ERR;
    }
    return SOFTBUS_OK;
}

int32_t SoftBusClientStub::OnNodeDeviceTrustedChangeInner(MessageParcel &data, MessageParcel &reply)
{
    const char *pkgName = data.ReadCString();
    if (pkgName == nullptr || strlen(pkgName) == 0) {
        COMM_LOGE(COMM_SDK, "Invalid package name, or length is zero");
        return SOFTBUS_INVALID_PARAM;
    }
    int32_t type = 0;
    if (!data.ReadInt32(type)) {
        COMM_LOGE(COMM_SDK, "read type failed!");
        return SOFTBUS_TRANS_PROXY_READINT_FAILED;
    }
    const char *msg = data.ReadCString();
    if (msg == nullptr) {
        COMM_LOGE(COMM_SDK, "read msg failed!");
        return SOFTBUS_TRANS_PROXY_READCSTRING_FAILED;
    }
    uint32_t msgLen = 0;
    if (!data.ReadUint32(msgLen)) {
        COMM_LOGE(COMM_SDK, "read failed! msgLen=%{public}u", msgLen);
        return SOFTBUS_TRANS_PROXY_READINT_FAILED;
    }
    int32_t retReply = OnNodeDeviceTrustedChange(pkgName, type, msg, msgLen);
    if (!reply.WriteInt32(retReply)) {
        COMM_LOGE(COMM_SDK, "write reply failed!");
        return SOFTBUS_TRANS_PROXY_WRITEINT_FAILED;
    }
    return SOFTBUS_OK;
}

int32_t SoftBusClientStub::OnHichainProofExceptionInner(MessageParcel &data, MessageParcel &reply)
{
    const char *pkgName = data.ReadCString();
    if (pkgName == nullptr || strlen(pkgName) == 0) {
        COMM_LOGE(COMM_SDK, "Invalid package name, or length is zero");
        return SOFTBUS_INVALID_PARAM;
    }
    uint32_t proofLen = 0;
    if (!data.ReadUint32(proofLen)) {
        COMM_LOGE(COMM_SDK, "read failed! proofLen=%{public}u", proofLen);
        return SOFTBUS_NETWORK_PROXY_READINT_FAILED;
    }
    char *proofInfo = nullptr;
    if (proofLen != 0) {
        proofInfo = (char *)data.ReadRawData(proofLen);
        if (proofInfo == nullptr) {
            COMM_LOGE(COMM_SDK, "read proofInfo failed!");
            return SOFTBUS_NETWORK_READRAWDATA_FAILED;
        }
    }
    uint16_t deviceTypeId = 0;
    if (!data.ReadUint16(deviceTypeId)) {
        COMM_LOGE(COMM_SDK, "read failed! deviceTypeId=%{public}hu", deviceTypeId);
        return SOFTBUS_NETWORK_PROXY_READINT_FAILED;
    }
    int32_t errCode = 0;
    if (!data.ReadInt32(errCode)) {
        COMM_LOGE(COMM_SDK, "read failed! errCode=%{public}d", errCode);
        return SOFTBUS_NETWORK_PROXY_READINT_FAILED;
    }
    int32_t retReply = OnHichainProofException(pkgName, proofInfo, proofLen, deviceTypeId, errCode);
    if (!reply.WriteInt32(retReply)) {
        COMM_LOGE(COMM_SDK, "OnHichainProofException write reply failed!");
        return SOFTBUS_NETWORK_WRITEINT32_FAILED;
    }
    return SOFTBUS_OK;
}

int32_t SoftBusClientStub::OnTimeSyncResultInner(MessageParcel &data, MessageParcel &reply)
{
    uint32_t infoTypeLen;
    if (!data.ReadUint32(infoTypeLen) || infoTypeLen != sizeof(TimeSyncResultInfo)) {
        COMM_LOGE(COMM_SDK, "OnTimeSyncResultInner read info failed! length=%{public}d", infoTypeLen);
        return SOFTBUS_TRANS_PROXY_READUINT_FAILED;
    }
    void *info = (void *)data.ReadRawData(infoTypeLen);
    if (info == nullptr) {
        COMM_LOGE(COMM_SDK, "OnTimeSyncResultInner read info failed!");
        return SOFTBUS_TRANS_PROXY_READRAWDATA_FAILED;
    }
    int32_t retCode;
    if (!data.ReadInt32(retCode)) {
        COMM_LOGE(COMM_SDK, "OnTimeSyncResultInner read retCode failed!");
        return SOFTBUS_TRANS_PROXY_READINT_FAILED;
    }

    int32_t retReply = OnTimeSyncResult(info, infoTypeLen, retCode);
    if (!reply.WriteInt32(retReply)) {
        COMM_LOGE(COMM_SDK, "OnTimeSyncResultInner write reply failed!");
        return SOFTBUS_TRANS_PROXY_WRITEINT_FAILED;
    }
    return SOFTBUS_OK;
}

int32_t SoftBusClientStub::OnPublishLNNResultInner(MessageParcel &data, MessageParcel &reply)
{
    int32_t publishId;
    if (!data.ReadInt32(publishId)) {
        COMM_LOGE(COMM_SDK, "OnPublishLNNResultInner read publishId failed!");
        return SOFTBUS_TRANS_PROXY_READINT_FAILED;
    }
    int32_t reason;
    if (!data.ReadInt32(reason)) {
        COMM_LOGE(COMM_SDK, "OnPublishLNNResultInner read reason failed!");
        return SOFTBUS_TRANS_PROXY_READINT_FAILED;
    }

    OnPublishLNNResult(publishId, reason);
    return SOFTBUS_OK;
}

int32_t SoftBusClientStub::OnRefreshLNNResultInner(MessageParcel &data, MessageParcel &reply)
{
    int32_t refreshId;
    if (!data.ReadInt32(refreshId)) {
        COMM_LOGE(COMM_SDK, "OnRefreshLNNResultInner read publishId failed!");
        return SOFTBUS_TRANS_PROXY_READINT_FAILED;
    }
    int32_t reason;
    if (!data.ReadInt32(reason)) {
        COMM_LOGE(COMM_SDK, "OnRefreshLNNResultInner read reason failed!");
        return SOFTBUS_TRANS_PROXY_READINT_FAILED;
    }

    OnRefreshLNNResult(refreshId, reason);
    return SOFTBUS_OK;
}

int32_t SoftBusClientStub::OnRefreshDeviceFoundInner(MessageParcel &data, MessageParcel &reply)
{
    uint32_t deviceLen;
    if (!data.ReadUint32(deviceLen) || deviceLen != sizeof(DeviceInfo)) {
        COMM_LOGE(COMM_SDK, "OnRefreshDeviceFoundInner read info failed! length=%{public}d", deviceLen);
        return SOFTBUS_TRANS_PROXY_READUINT_FAILED;
    }
    void *device = (void *)data.ReadRawData(deviceLen);
    if (device == nullptr) {
        COMM_LOGE(COMM_SDK, "OnRefreshDeviceFoundInner read info failed!");
        return SOFTBUS_TRANS_PROXY_READRAWDATA_FAILED;
    }
    OnRefreshDeviceFound(device, deviceLen);
    return SOFTBUS_OK;
}

int32_t SoftBusClientStub::OnDataLevelChangedInner(MessageParcel &data, MessageParcel &reply)
{
    const char *networkId = data.ReadCString();
    if (networkId == nullptr || strlen(networkId) == 0) {
        COMM_LOGE(COMM_SDK, "Invalid network, or length is zero");
        return SOFTBUS_TRANS_PROXY_READCSTRING_FAILED;
    }

    DataLevelInfo *info = (DataLevelInfo *)data.ReadRawData(sizeof(DataLevelInfo));
    if (info == nullptr) {
        COMM_LOGE(COMM_SDK, "OnDataLevelChangedInner read data level chagne info failed");
        return SOFTBUS_TRANS_PROXY_READRAWDATA_FAILED;
    }
    OnDataLevelChanged(networkId, info);
    return SOFTBUS_OK;
}

int32_t SoftBusClientStub::OnChannelBind(int32_t channelId, int32_t channelType)
{
    return TransOnChannelBind(channelId, channelType);
}

int32_t SoftBusClientStub::OnChannelBindInner(MessageParcel &data, MessageParcel &reply)
{
    int32_t channelId;
    COMM_CHECK_AND_RETURN_RET_LOGE(data.ReadInt32(channelId), SOFTBUS_IPC_ERR, COMM_SDK, "read channelId failed");

    int32_t channelType;
    COMM_CHECK_AND_RETURN_RET_LOGE(data.ReadInt32(channelType), SOFTBUS_IPC_ERR, COMM_SDK, "read channelType failed");

    int32_t ret = OnChannelBind(channelId, channelType);
    COMM_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, COMM_SDK,
        "OnChannelBind failed! ret=%{public}d, channelId=%{public}d, channelType=%{public}d",
        ret, channelId, channelType);

    return SOFTBUS_OK;
}

static int32_t MessageParcelReadCollabInfo(MessageParcel &data, CollabInfo &info)
{
    READ_PARCEL_WITH_RET(data, Int64, info.accountId, SOFTBUS_IPC_ERR);
    READ_PARCEL_WITH_RET(data, Uint64, info.tokenId, SOFTBUS_IPC_ERR);
    READ_PARCEL_WITH_RET(data, Int32, info.userId, SOFTBUS_IPC_ERR);
    READ_PARCEL_WITH_RET(data, Int32, info.pid, SOFTBUS_IPC_ERR);
    char *deviceId = (char *)data.ReadCString();
    COMM_CHECK_AND_RETURN_RET_LOGE(deviceId != nullptr, SOFTBUS_IPC_ERR, COMM_SDK, "read deviceId failed");
    if (strcpy_s(info.deviceId, sizeof(info.deviceId), deviceId) != EOK) {
        COMM_LOGE(COMM_SDK, "strcpy_s failed to copy deviceId");
    }
    return SOFTBUS_OK;
}

int32_t SoftBusClientStub::OnCheckCollabRelation(
    const CollabInfo *sourceInfo, const CollabInfo *sinkInfo, int32_t channelId, int32_t channelType)
{
    if (sourceInfo == nullptr || sinkInfo == nullptr) {
        COMM_LOGE(COMM_SDK, "invalid param.");
        return SOFTBUS_INVALID_PARAM;
    }
    return TransOnCheckCollabRelation(sourceInfo, sinkInfo, channelId, channelType);
}

int32_t SoftBusClientStub::OnCheckCollabRelationInner(MessageParcel &data, MessageParcel &reply)
{
    CollabInfo sourceInfo;
    CollabInfo sinkInfo;
    int32_t ret = MessageParcelReadCollabInfo(data, sourceInfo);
    COMM_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, COMM_SDK, "read source info failed");
    ret = MessageParcelReadCollabInfo(data, sinkInfo);
    COMM_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, COMM_SDK, "read sink info failed");
    int32_t channelId;
    COMM_CHECK_AND_RETURN_RET_LOGE(data.ReadInt32(channelId), SOFTBUS_IPC_ERR, COMM_SDK, "read channelId failed");
    int32_t channelType;
    COMM_CHECK_AND_RETURN_RET_LOGE(data.ReadInt32(channelType), SOFTBUS_IPC_ERR, COMM_SDK, "read channelType failed");
    ret = OnCheckCollabRelation(&sourceInfo, &sinkInfo, channelId, channelType);
    COMM_CHECK_AND_RETURN_RET_LOGE(
        ret == SOFTBUS_OK, ret, COMM_SDK, "CheckCollabRelation failed! ret=%{public}d.", ret);
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

int32_t SoftBusClientStub::OnNodeStatusChanged(const char *pkgName, void *info, uint32_t infoTypeLen, int32_t type)
{
    (void)infoTypeLen;
    return LnnOnNodeStatusChanged(pkgName, info, type);
}

int32_t SoftBusClientStub::OnLocalNetworkIdChanged(const char *pkgName)
{
    return LnnOnLocalNetworkIdChanged(pkgName);
}

int32_t SoftBusClientStub::OnNodeDeviceTrustedChange(const char *pkgName, int32_t type, const char *msg,
    uint32_t msgLen)
{
    return LnnOnNodeDeviceTrustedChange(pkgName, type, msg, msgLen);
}

int32_t SoftBusClientStub::OnHichainProofException(
    const char *pkgName, const char *proofInfo, uint32_t proofLen, uint16_t deviceTypeId, int32_t errCode)
{
    return LnnOnHichainProofException(pkgName, proofInfo, proofLen, deviceTypeId, errCode);
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

void SoftBusClientStub::OnDataLevelChanged(const char *networkId, const DataLevelInfo *dataLevelInfo)
{
    LnnOnDataLevelChanged(networkId, dataLevelInfo);
}

int32_t SoftBusClientStub::OnClientChannelOnQos(
    int32_t channelId, int32_t channelType, QoSEvent event, const QosTV *qos, uint32_t count)
{
    if (event < QOS_SATISFIED || event > QOS_NOT_SATISFIED) {
        COMM_LOGE(COMM_SDK, "OnChannelOnQos invalid event=%{public}d", event);
        return SOFTBUS_INVALID_PARAM;
    }
    if (qos == nullptr || count == 0) {
        COMM_LOGE(COMM_SDK, "OnChannelOnQos invalid qos or count");
        return SOFTBUS_INVALID_PARAM;
    }
    return TransOnChannelOnQos(channelId, channelType, event, qos, count);
}
} // namespace OHOS
