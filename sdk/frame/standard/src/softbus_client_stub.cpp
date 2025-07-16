/*
 * Copyright (c) 2021-2025 Huawei Device Co., Ltd.
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

#include "anonymizer.h"
#include "br_proxy.h"
#include "client_bus_center_manager.h"
#include "general_client_connection.h"
#include "client_trans_channel_callback.h"
#include "client_trans_socket_manager.h"
#include "client_trans_udp_manager.h"
#include "securec.h"
#include "session_set_timer.h"
#include "softbus_access_token_adapter.h"
#include "softbus_server_ipc_interface_code.h"

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
    memberFuncMap_[CLIENT_ON_RANGE_RESULT] = &SoftBusClientStub::OnMsdpRangeResultInner;
    memberFuncMap_[CLIENT_ON_TRANS_LIMIT_CHANGE] = &SoftBusClientStub::OnClientTransLimitChangeInner;
    memberFuncMap_[CLIENT_ON_CHANNEL_BIND] = &SoftBusClientStub::OnChannelBindInner;
    memberFuncMap_[CLIENT_CHANNEL_ON_QOS] = &SoftBusClientStub::OnChannelOnQosInner;
    memberFuncMap_[CLIENT_CHECK_COLLAB_RELATION] = &SoftBusClientStub::OnCheckCollabRelationInner;
    memberFuncMap_[CLIENT_GENERAL_CONNECTION_STATE_CHANGE] = &SoftBusClientStub::OnConnectionStateChangeInner;
    memberFuncMap_[CLIENT_GENERAL_ACCEPT_CONNECT] = &SoftBusClientStub::OnAcceptConnectInner;
    memberFuncMap_[CLIENT_GENERAL_DATA_RECEIVED] = &SoftBusClientStub::OnDataReceivedInner;
    memberFuncMap_[CLIENT_ON_BR_PROXY_OPENED] = &SoftBusClientStub::OnBrProxyOpenedInner;
    memberFuncMap_[CLIENT_ON_BR_PROXY_DATA_RECV] = &SoftBusClientStub::OnBrProxyDataRecvInner;
    memberFuncMap_[CLIENT_ON_BR_PROXY_STATE_CHANGED] = &SoftBusClientStub::OnBrProxyStateChangedInner;
    memberFuncMap_[CLIENT_ON_BR_PROXY_QUERY_PERMISSION] = &SoftBusClientStub::OnBrProxyQueryPermissionInner;
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
        READ_PARCEL_WITH_RET(data, Uint32, channel->fdProtocol, SOFTBUS_IPC_ERR);
        channel->peerIp = (char *)data.ReadCString();
        COMM_CHECK_AND_RETURN_RET_LOGE(channel->peerIp != nullptr, SOFTBUS_IPC_ERR, COMM_SDK, "read peerIp failed");
        READ_PARCEL_WITH_RET(data, Int32, channel->peerPort, SOFTBUS_IPC_ERR);
        channel->pkgName = (char *)data.ReadCString();
        COMM_CHECK_AND_RETURN_RET_LOGE(channel->pkgName != nullptr, SOFTBUS_IPC_ERR, COMM_SDK, "read pkgName failed");
    }
    return SOFTBUS_OK;
}

static int32_t MessageParcelReadEx(MessageParcel &data, ChannelInfo *channel)
{
    READ_PARCEL_WITH_RET(data, Int32, channel->routeType, SOFTBUS_IPC_ERR);
    READ_PARCEL_WITH_RET(data, Int32, channel->encrypt, SOFTBUS_IPC_ERR);
    READ_PARCEL_WITH_RET(data, Int32, channel->algorithm, SOFTBUS_IPC_ERR);
    READ_PARCEL_WITH_RET(data, Int32, channel->crc, SOFTBUS_IPC_ERR);
    READ_PARCEL_WITH_RET(data, Uint32, channel->dataConfig, SOFTBUS_IPC_ERR);
    READ_PARCEL_WITH_RET(data, Int32, channel->linkType, SOFTBUS_IPC_ERR);
    READ_PARCEL_WITH_RET(data, Int32, channel->osType, SOFTBUS_IPC_ERR);
    READ_PARCEL_WITH_RET(data, Bool, channel->isSupportTlv, SOFTBUS_IPC_ERR);
    channel->peerDeviceId = (char *)data.ReadCString();
    COMM_CHECK_AND_RETURN_RET_LOGE(channel->peerDeviceId != nullptr,
        SOFTBUS_IPC_ERR, COMM_SDK, "read peerDeviceId failed");
    READ_PARCEL_WITH_RET(data, Bool, channel->isD2D, SOFTBUS_IPC_ERR);
    if (channel->isD2D) {
        READ_PARCEL_WITH_RET(data, Uint32, channel->businessFlag, SOFTBUS_IPC_ERR);
        READ_PARCEL_WITH_RET(data, Uint32, channel->deviceTypeId, SOFTBUS_IPC_ERR);
        channel->pagingNonce = (char *)data.ReadRawData(PAGING_NONCE_LEN);
        COMM_CHECK_AND_RETURN_RET_LOGE(channel->pagingNonce != nullptr, SOFTBUS_IPC_ERR,
            COMM_SDK, "read pagingNonce failed");
        channel->pagingSessionkey = (char *)data.ReadRawData(SHORT_SESSION_KEY_LENGTH);
        COMM_CHECK_AND_RETURN_RET_LOGE(channel->pagingSessionkey != nullptr, SOFTBUS_IPC_ERR,
            COMM_SDK, "read pagingSessionkey failed");
        READ_PARCEL_WITH_RET(data, Uint32, channel->dataLen, SOFTBUS_IPC_ERR);
        if (channel->dataLen > 0) {
            channel->extraData = (char *)data.ReadRawData(channel->dataLen);
            COMM_CHECK_AND_RETURN_RET_LOGE(channel->extraData != nullptr, SOFTBUS_IPC_ERR,
                COMM_SDK, "read extraData failed");
        }
        if (channel->isServer) {
            channel->pagingAccountId = (char *)data.ReadCString();
            COMM_CHECK_AND_RETURN_RET_LOGE(channel->pagingAccountId != nullptr,
                SOFTBUS_IPC_ERR, COMM_SDK, "read pagingAccountId failed");
        }
    } else {
        READ_PARCEL_WITH_RET(data, Int32, channel->tokenType, SOFTBUS_IPC_ERR);
        if (channel->tokenType > ACCESS_TOKEN_TYPE_HAP && channel->channelType != CHANNEL_TYPE_AUTH &&
            channel->isServer) {
            READ_PARCEL_WITH_RET(data, Int32, channel->peerUserId, SOFTBUS_IPC_ERR);
            READ_PARCEL_WITH_RET(data, Uint64, channel->peerTokenId, SOFTBUS_IPC_ERR);
            channel->peerExtraAccessInfo = (char *)data.ReadCString();
        }
        channel->sessionKey = (char *)data.ReadRawData(channel->keyLen);
        COMM_CHECK_AND_RETURN_RET_LOGE(channel->sessionKey != nullptr, SOFTBUS_IPC_ERR,
            COMM_SDK, "read rawData failed");
        channel->groupId = (char *)data.ReadCString();
        COMM_CHECK_AND_RETURN_RET_LOGE(channel->groupId != nullptr,
            SOFTBUS_IPC_ERR, COMM_SDK, "read groupId failed");
    }
    return SOFTBUS_OK;
}

static int32_t MessageParcelRead(MessageParcel &data, ChannelInfo *channel)
{
    READ_PARCEL_WITH_RET(data, Int32, channel->sessionId, SOFTBUS_IPC_ERR);
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
    COMM_CHECK_AND_RETURN_RET_LOGE(channel->keyLen <= SESSION_KEY_LENGTH, SOFTBUS_IPC_ERR, COMM_SDK,
        "channel->keyLen invalid");
    READ_PARCEL_WITH_RET(data, Uint32, channel->keyLen, SOFTBUS_IPC_ERR);
    channel->peerSessionName = (char *)data.ReadCString();
    COMM_CHECK_AND_RETURN_RET_LOGE(
        channel->peerSessionName != nullptr, SOFTBUS_IPC_ERR, COMM_SDK, "read peerSessionName failed");
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
    return MessageParcelReadEx(data, channel);
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
        COMM_LOGE(COMM_SDK, "OnDataLevelChangedInner read data level change info failed");
        return SOFTBUS_TRANS_PROXY_READRAWDATA_FAILED;
    }
    OnDataLevelChanged(networkId, info);
    return SOFTBUS_OK;
}

int32_t SoftBusClientStub::OnMsdpRangeResultInner(MessageParcel &data, MessageParcel &reply)
{
    RangeResultInnerInfo *tempInfo = (RangeResultInnerInfo *)data.ReadRawData(sizeof(RangeResultInnerInfo));
    if (tempInfo == nullptr) {
        COMM_LOGE(COMM_SDK, "read ble range info failed");
        return SOFTBUS_TRANS_PROXY_READRAWDATA_FAILED;
    }
    RangeResultInnerInfo info;
    (void)memset_s(&info, sizeof(RangeResultInnerInfo), 0, sizeof(RangeResultInnerInfo));
    if (memcpy_s(&info, sizeof(RangeResultInnerInfo), tempInfo, sizeof(RangeResultInnerInfo)) != EOK) {
        COMM_LOGE(COMM_SDK, "memcpy_s failed");
        return SOFTBUS_MEM_ERR;
    }
    if (tempInfo->length > 0 && tempInfo->length < MAX_ADDITION_DATA_LEN) {
        info.addition = (uint8_t *)data.ReadRawData(tempInfo->length);
        if (info.addition == nullptr) {
            COMM_LOGE(COMM_SDK, "read addition data failed");
            return SOFTBUS_TRANS_PROXY_READRAWDATA_FAILED;
        }
    }
    char *anonyNetworkId = nullptr;
    Anonymize(info.networkId, &anonyNetworkId);
    COMM_LOGI(COMM_SDK, "medium=%{public}d, distance=%{public}f, networkId=%{public}s", info.medium, info.distance,
        AnonymizeWrapper(anonyNetworkId));
    AnonymizeFree(anonyNetworkId);
    OnMsdpRangeResult(&info);
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
    const char *accountId = data.ReadCString();
    if (accountId == nullptr) {
        COMM_LOGE(COMM_SDK, "read accountId failed");
    } else {
        if (strcpy_s(info.accountId, sizeof(info.accountId), accountId) != EOK) {
            COMM_LOGE(COMM_SDK, "strcpy_s failed to copy accountId");
        }
    }
    READ_PARCEL_WITH_RET(data, Uint64, info.tokenId, SOFTBUS_IPC_ERR);
    READ_PARCEL_WITH_RET(data, Int32, info.userId, SOFTBUS_IPC_ERR);
    READ_PARCEL_WITH_RET(data, Int32, info.pid, SOFTBUS_IPC_ERR);
    const char *deviceId = data.ReadCString();
    COMM_CHECK_AND_RETURN_RET_LOGE(deviceId != nullptr, SOFTBUS_IPC_ERR, COMM_SDK, "read deviceId failed");
    if (strcpy_s(info.deviceId, sizeof(info.deviceId), deviceId) != EOK) {
        COMM_LOGE(COMM_SDK, "strcpy_s failed to copy deviceId");
    }
    return SOFTBUS_OK;
}

int32_t SoftBusClientStub::OnCheckCollabRelation(
    const CollabInfo *sourceInfo, bool isSinkSide, const CollabInfo *sinkInfo, int32_t channelId, int32_t channelType)
{
    if (sourceInfo == nullptr || sinkInfo == nullptr) {
        COMM_LOGE(COMM_SDK, "invalid param.");
        return SOFTBUS_INVALID_PARAM;
    }
    return TransOnCheckCollabRelation(sourceInfo, isSinkSide, sinkInfo, channelId, channelType);
}

int32_t SoftBusClientStub::OnCheckCollabRelationInner(MessageParcel &data, MessageParcel &reply)
{
    CollabInfo sourceInfo;
    CollabInfo sinkInfo;
    bool isSinkSide = false;
    int32_t channelId = -1;
    int32_t channelType = -1;
    READ_PARCEL_WITH_RET(data, Bool, isSinkSide, SOFTBUS_IPC_ERR);
    int32_t ret = MessageParcelReadCollabInfo(data, sourceInfo);
    COMM_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, COMM_SDK, "read source info failed");
    ret = MessageParcelReadCollabInfo(data, sinkInfo);
    COMM_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, COMM_SDK, "read sink info failed");
    if (isSinkSide) {
        COMM_CHECK_AND_RETURN_RET_LOGE(data.ReadInt32(channelId), SOFTBUS_IPC_ERR, COMM_SDK, "read channelId failed");
        COMM_CHECK_AND_RETURN_RET_LOGE(
            data.ReadInt32(channelType), SOFTBUS_IPC_ERR, COMM_SDK, "read channelType failed");
    }
    ret = OnCheckCollabRelation(&sourceInfo, isSinkSide, &sinkInfo, channelId, channelType);
    COMM_CHECK_AND_RETURN_RET_LOGE(
        ret == SOFTBUS_OK, ret, COMM_SDK, "CheckCollabRelation failed! ret=%{public}d.", ret);
    return SOFTBUS_OK;
}

int32_t SoftBusClientStub::OnBrProxyOpenedInner(MessageParcel &data, MessageParcel &reply)
{
    int32_t channelId;
    COMM_CHECK_AND_RETURN_RET_LOGE(data.ReadInt32(channelId), SOFTBUS_IPC_ERR, COMM_SDK, "read channelId failed");
    char *brMac = (char *)data.ReadCString();
    COMM_CHECK_AND_RETURN_RET_LOGE(brMac != nullptr, SOFTBUS_IPC_ERR, COMM_SDK, "read brMac failed");
    char *uuid = (char *)data.ReadCString();
    COMM_CHECK_AND_RETURN_RET_LOGE(uuid != nullptr, SOFTBUS_IPC_ERR, COMM_SDK, "read uuid failed");
    int32_t reason;
    COMM_CHECK_AND_RETURN_RET_LOGE(data.ReadInt32(reason), SOFTBUS_IPC_ERR, COMM_SDK, "read reason failed");
 
    return ClientTransOnBrProxyOpened(channelId, brMac, uuid, reason);
}
 
int32_t SoftBusClientStub::OnBrProxyDataRecvInner(MessageParcel &data, MessageParcel &reply)
{
    int32_t channelId;
    COMM_CHECK_AND_RETURN_RET_LOGE(data.ReadInt32(channelId), SOFTBUS_IPC_ERR, COMM_SDK, "read channelId failed");
    uint32_t len;
    COMM_CHECK_AND_RETURN_RET_LOGE(
        data.ReadUint32(len), SOFTBUS_TRANS_PROXY_READUINT_FAILED, COMM_SDK, "read data len failed");
    uint8_t *dataInfo = (uint8_t *)data.ReadRawData(len);
    COMM_CHECK_AND_RETURN_RET_LOGE(
        dataInfo != nullptr, SOFTBUS_TRANS_PROXY_READRAWDATA_FAILED, COMM_SDK, "read dataInfo failed!");
 
    return ClientTransBrProxyDataReceived(channelId, dataInfo, len);
}
 
int32_t SoftBusClientStub::OnBrProxyStateChangedInner(MessageParcel &data, MessageParcel &reply)
{
    int32_t channelId;
    COMM_CHECK_AND_RETURN_RET_LOGE(data.ReadInt32(channelId), SOFTBUS_IPC_ERR, COMM_SDK, "read channelId failed");
    int32_t errCode;
    COMM_CHECK_AND_RETURN_RET_LOGE(data.ReadInt32(errCode), SOFTBUS_IPC_ERR, COMM_SDK, "read errCode failed");
 
    return ClientTransBrProxyChannelChange(channelId, errCode);
}

int32_t SoftBusClientStub::OnBrProxyQueryPermissionInner(MessageParcel &data, MessageParcel &reply)
{
    char *bundleName = (char *)data.ReadCString();
    bool isEmpowered = false;

    int32_t ret = ClientTransBrProxyQueryPermission(bundleName, &isEmpowered);
    COMM_LOGI(COMM_SDK, "[br_proxy] ret:%{public}d", ret);
 
    if (!reply.WriteBool(isEmpowered)) {
        COMM_LOGE(COMM_SDK, "OnTimeSyncResultInner write reply failed!");
        return SOFTBUS_TRANS_PROXY_WRITEINT_FAILED;
    }

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

void SoftBusClientStub::OnMsdpRangeResult(const RangeResultInnerInfo *rangeInfo)
{
    LnnOnRangeResult(rangeInfo);
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

int32_t SoftBusClientStub::OnConnectionStateChangeInner(MessageParcel &data, MessageParcel &reply)
{
    uint32_t handle;
    if (!data.ReadUint32(handle)) {
        COMM_LOGE(COMM_SDK, "OnConnectionStateChangeInner read handle failed!");
        return SOFTBUS_IPC_ERR;
    }
    int32_t state;
    if (!data.ReadInt32(state)) {
        COMM_LOGE(COMM_SDK, "OnConnectionStateChangeInner read state failed!");
        return SOFTBUS_IPC_ERR;
    }
    int32_t reason;
    if (!data.ReadInt32(reason)) {
        COMM_LOGE(COMM_SDK, "OnConnectionStateChangeInner read reason failed!");
        return SOFTBUS_IPC_ERR;
    }
    int32_t ret = OnConnectionStateChange(handle, state, reason);
    if (ret != SOFTBUS_OK) {
        COMM_LOGE(COMM_SDK, "OnConnectionStateChangeInner failed! ret=%{public}d", ret);
    }
    return SOFTBUS_OK;
}

int32_t SoftBusClientStub::OnAcceptConnectInner(MessageParcel &data, MessageParcel &reply)
{
    char *name = (char *)data.ReadCString();
    if (name == nullptr) {
        COMM_LOGE(COMM_SDK, "OnAcceptConnectInner read name failed!");
        return SOFTBUS_IPC_ERR;
    }
    uint32_t handle;
    if (!data.ReadUint32(handle)) {
        COMM_LOGE(COMM_SDK, "OnAcceptConnectInner read handle failed!");
        return SOFTBUS_IPC_ERR;
    }
    int32_t ret = OnAcceptConnect(name, handle);
    if (ret != SOFTBUS_OK) {
        COMM_LOGE(COMM_SDK, "OnAcceptConnectInner failed! ret=%{public}d", ret);
    }
    return SOFTBUS_OK;
}

int32_t SoftBusClientStub::OnDataReceivedInner(MessageParcel &data, MessageParcel &reply)
{
    uint32_t handle;
    if (!data.ReadUint32(handle)) {
        COMM_LOGE(COMM_SDK, "OnDataReceivedInner read handle failed!");
        return SOFTBUS_IPC_ERR;
    }
    uint32_t len;
    if (!data.ReadUint32(len)) {
        COMM_LOGE(COMM_SDK, "OnDataReceivedInner read len failed!");
        return SOFTBUS_IPC_ERR;
    }
    const uint8_t *dataPtr = (const uint8_t *)data.ReadBuffer(len);
    if (dataPtr == nullptr) {
        COMM_LOGE(COMM_SDK, "OnDataReceivedInner read data failed!");
        return SOFTBUS_IPC_ERR;
    }
    int32_t ret = OnDataReceived(handle, dataPtr, len);
    if (ret != SOFTBUS_OK) {
        COMM_LOGE(COMM_SDK, "OnDataReceivedInner failed! ret=%{public}d", ret);
    }
    return SOFTBUS_OK;
}

int32_t SoftBusClientStub::OnConnectionStateChange(uint32_t handle, int32_t state, int32_t reason)
{
    COMM_LOGI(COMM_SDK, "OnConnectionStateChange handle=%{public}d, state=%{public}d, reason=%{public}d", handle, state,
        reason);
    return ConnectionStateChange(handle, state, reason);
}

int32_t SoftBusClientStub::OnAcceptConnect(const char *name, uint32_t handle)
{
    COMM_LOGI(COMM_SDK, "OnAcceptConnect name=%{public}s, handle=%{public}d", name, handle);
    return AcceptConnect(name, handle);
}

int32_t SoftBusClientStub::OnDataReceived(uint32_t handle, const uint8_t *data, uint32_t len)
{
    COMM_LOGI(COMM_SDK, "OnDataReceived handle=%{public}d, len=%{public}u", handle, len);
    DataReceived(handle, data, len);
    return SOFTBUS_OK;
}
} // namespace OHOS
