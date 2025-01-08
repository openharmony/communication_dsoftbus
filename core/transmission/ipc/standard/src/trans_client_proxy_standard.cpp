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

#include "trans_client_proxy_standard.h"

#include "message_parcel.h"
#include "softbus_def.h"
#include "softbus_error_code.h"
#include "softbus_server_ipc_interface_code.h"
#include "trans_channel_manager.h"
#include "trans_log.h"

#define WRITE_PARCEL_WITH_RET(parcel, type, data, retval)                              \
    do {                                                                               \
        if (!(parcel).Write##type(data)) {                                             \
            TRANS_LOGE(TRANS_SVC, "write data failed.");                               \
            return (retval);                                                           \
        }                                                                              \
    } while (false)

namespace OHOS {
int32_t TransClientProxy::OnClientPermissonChange(const char *pkgName, int32_t state)
{
    if (pkgName == NULL) {
        TRANS_LOGE(TRANS_SDK, "invalid param.");
        return SOFTBUS_INVALID_PARAM;
    }
    sptr<IRemoteObject> remote = Remote();
    TRANS_CHECK_AND_RETURN_RET_LOGE(remote != nullptr,
        SOFTBUS_TRANS_PROXY_REMOTE_NULL, TRANS_CTRL, "remote is nullptr");
    MessageParcel data;
    TRANS_CHECK_AND_RETURN_RET_LOGE(data.WriteInterfaceToken(GetDescriptor()),
        SOFTBUS_TRANS_PROXY_WRITETOKEN_FAILED, TRANS_CTRL, "write InterfaceToken failed!");
    TRANS_CHECK_AND_RETURN_RET_LOGE(data.WriteInt32(state),
        SOFTBUS_TRANS_PROXY_WRITEINT_FAILED, TRANS_CTRL, "write permStateChangeType failed");
    TRANS_CHECK_AND_RETURN_RET_LOGE(data.WriteCString(pkgName),
        SOFTBUS_TRANS_PROXY_WRITECSTRING_FAILED, TRANS_CTRL, "write pkgName failed");
    MessageParcel reply;
    MessageOption option = { MessageOption::TF_ASYNC };
    int32_t ret = remote->SendRequest(CLIENT_ON_PERMISSION_CHANGE, data, reply, option);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL,
            "DataSyncPermissionChange send request failed, ret=%{public}d", ret);
        return SOFTBUS_TRANS_PROXY_SEND_REQUEST_FAILED;
    }
    return SOFTBUS_OK;
}

int32_t TransClientProxy::MessageParcelWrite(MessageParcel &data, const char *sessionName, const ChannelInfo *channel)
{
    if (sessionName == NULL || channel == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        TRANS_LOGE(TRANS_CTRL, "write InterfaceToken failed.");
        return SOFTBUS_TRANS_PROXY_WRITETOKEN_FAILED;
    }
    WRITE_PARCEL_WITH_RET(data, CString, sessionName, SOFTBUS_IPC_ERR);
    WRITE_PARCEL_WITH_RET(data, Int32, channel->channelId, SOFTBUS_IPC_ERR);
    WRITE_PARCEL_WITH_RET(data, Int32, channel->channelType, SOFTBUS_IPC_ERR);
    WRITE_PARCEL_WITH_RET(data, Uint64, channel->laneId, SOFTBUS_IPC_ERR);
    WRITE_PARCEL_WITH_RET(data, Int32, channel->connectType, SOFTBUS_IPC_ERR);
    
    if (channel->channelType == CHANNEL_TYPE_TCP_DIRECT) {
        WRITE_PARCEL_WITH_RET(data, FileDescriptor, channel->fd, SOFTBUS_IPC_ERR);
        WRITE_PARCEL_WITH_RET(data, CString, channel->myIp, SOFTBUS_IPC_ERR);
    }
    WRITE_PARCEL_WITH_RET(data, Bool, channel->isServer, SOFTBUS_IPC_ERR);
    WRITE_PARCEL_WITH_RET(data, Bool, channel->isEnabled, SOFTBUS_IPC_ERR);
    WRITE_PARCEL_WITH_RET(data, Bool, channel->isEncrypt, SOFTBUS_IPC_ERR);
    WRITE_PARCEL_WITH_RET(data, Int32, channel->peerUid, SOFTBUS_IPC_ERR);
    WRITE_PARCEL_WITH_RET(data, Int32, channel->peerPid, SOFTBUS_IPC_ERR);
    WRITE_PARCEL_WITH_RET(data, CString, channel->groupId, SOFTBUS_IPC_ERR);
    WRITE_PARCEL_WITH_RET(data, Uint32, channel->keyLen, SOFTBUS_IPC_ERR);
    if (!data.WriteRawData(channel->sessionKey, channel->keyLen)) {
        TRANS_LOGE(TRANS_CTRL, "write sessionKey and keyLen failed.");
        return SOFTBUS_TRANS_PROXY_WRITERAWDATA_FAILED;
    }
    WRITE_PARCEL_WITH_RET(data, CString, channel->peerSessionName, SOFTBUS_IPC_ERR);
    WRITE_PARCEL_WITH_RET(data, CString, channel->peerDeviceId, SOFTBUS_IPC_ERR);
    WRITE_PARCEL_WITH_RET(data, Int32, channel->businessType, SOFTBUS_IPC_ERR);
    if (channel->channelType == CHANNEL_TYPE_UDP) {
        WRITE_PARCEL_WITH_RET(data, CString, channel->myIp, SOFTBUS_IPC_ERR);
        WRITE_PARCEL_WITH_RET(data, Int32, channel->streamType, SOFTBUS_IPC_ERR);
        WRITE_PARCEL_WITH_RET(data, Bool, channel->isUdpFile, SOFTBUS_IPC_ERR);
        
        if (!channel->isServer) {
            WRITE_PARCEL_WITH_RET(data, Int32, channel->peerPort, SOFTBUS_IPC_ERR);
            WRITE_PARCEL_WITH_RET(data, CString, channel->peerIp, SOFTBUS_IPC_ERR);
        }
    }
    WRITE_PARCEL_WITH_RET(data, Int32, channel->routeType, SOFTBUS_IPC_ERR);
    WRITE_PARCEL_WITH_RET(data, Int32, channel->encrypt, SOFTBUS_IPC_ERR);
    WRITE_PARCEL_WITH_RET(data, Int32, channel->algorithm, SOFTBUS_IPC_ERR);
    WRITE_PARCEL_WITH_RET(data, Int32, channel->crc, SOFTBUS_IPC_ERR);
    WRITE_PARCEL_WITH_RET(data, Uint32, channel->dataConfig, SOFTBUS_IPC_ERR);
    WRITE_PARCEL_WITH_RET(data, Int32, channel->linkType, SOFTBUS_IPC_ERR);
    WRITE_PARCEL_WITH_RET(data, Int32, channel->osType, SOFTBUS_IPC_ERR);
    WRITE_PARCEL_WITH_RET(data, Bool, channel->isSupportTlv, SOFTBUS_IPC_ERR);
    return SOFTBUS_OK;
}

int32_t TransClientProxy::OnClientTransLimitChange(int32_t channelId, uint8_t tos)
{
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        TRANS_LOGE(TRANS_CTRL, "remote is nullptr");
        return SOFTBUS_TRANS_PROXY_REMOTE_NULL;
    }
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        TRANS_LOGE(TRANS_CTRL, "write InterfaceToken failed!");
        return SOFTBUS_TRANS_PROXY_WRITETOKEN_FAILED;
    }
    if (!data.WriteInt32(channelId)) {
        TRANS_LOGE(TRANS_CTRL, "write channel id failed");
        return SOFTBUS_TRANS_PROXY_WRITERAWDATA_FAILED;
    }
    if (!data.WriteUint8(tos)) {
        TRANS_LOGE(TRANS_CTRL, "write tos failed");
        return SOFTBUS_TRANS_PROXY_WRITERAWDATA_FAILED;
    }

    MessageParcel reply;
    MessageOption option = { MessageOption::TF_ASYNC };
    int32_t ret = remote->SendRequest(CLIENT_ON_TRANS_LIMIT_CHANGE, data, reply, option);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "OnClientTransLimitChange send request failed, ret=%{public}d", ret);
        return ret;
    }
    return SOFTBUS_OK;
}

int32_t TransClientProxy::OnChannelOpened(const char *sessionName, const ChannelInfo *channel)
{
    sptr<IRemoteObject> remote = Remote();
    TRANS_CHECK_AND_RETURN_RET_LOGE(remote != nullptr,
        SOFTBUS_TRANS_PROXY_REMOTE_NULL, TRANS_CTRL, "remote is nullptr");
    MessageParcel data;
    int32_t ret = MessageParcelWrite(data, sessionName, channel);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "message parcel write failed.");
        return ret;
    }

    MessageParcel reply;
    MessageOption option = { MessageOption::TF_ASYNC };
    ret = remote->SendRequest(CLIENT_ON_CHANNEL_OPENED, data, reply, option);
    int32_t channelId = channel->channelId;
    int32_t channelType = channel->channelType;
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "OnChannelOpened send request failed, ret=%{public}d", ret);
        return ret;
    }
    if (channel->isServer) {
        TransCheckChannelOpenToLooperDelay(channelId, channelType, FAST_INTERVAL_MILLISECOND);
    }
    return SOFTBUS_OK;
}

int32_t TransClientProxy::OnChannelBind(int32_t channelId, int32_t channelType)
{
    sptr<IRemoteObject> remote = Remote();
    TRANS_CHECK_AND_RETURN_RET_LOGE(remote != nullptr,
        SOFTBUS_TRANS_PROXY_REMOTE_NULL, TRANS_CTRL, "remote is nullptr");

    MessageParcel data;
    TRANS_CHECK_AND_RETURN_RET_LOGE(data.WriteInterfaceToken(GetDescriptor()),
        SOFTBUS_TRANS_PROXY_WRITETOKEN_FAILED, TRANS_CTRL, "write InterfaceToken failed!");
    TRANS_CHECK_AND_RETURN_RET_LOGE(data.WriteInt32(channelId),
        SOFTBUS_TRANS_PROXY_WRITEINT_FAILED, TRANS_CTRL, "write channel id failed");
    TRANS_CHECK_AND_RETURN_RET_LOGE(data.WriteInt32(channelType),
        SOFTBUS_TRANS_PROXY_WRITEINT_FAILED, TRANS_CTRL, "write channel type failed");

    MessageParcel reply;
    MessageOption option = { MessageOption::TF_ASYNC };
    int32_t ret = remote->SendRequest(CLIENT_ON_CHANNEL_BIND, data, reply, option);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(
            TRANS_CTRL, "OnChannelBind send request failed, ret=%{public}d, channelId=%{public}d", ret, channelId);
        return SOFTBUS_TRANS_PROXY_SEND_REQUEST_FAILED;
    }

    return SOFTBUS_OK;
}

int32_t TransClientProxy::OnChannelOpenFailed(int32_t channelId, int32_t channelType, int32_t errCode)
{
    sptr<IRemoteObject> remote = Remote();
    TRANS_CHECK_AND_RETURN_RET_LOGE(remote != nullptr,
        SOFTBUS_TRANS_PROXY_REMOTE_NULL, TRANS_CTRL, "remote is nullptr");

    MessageParcel data;
    TRANS_CHECK_AND_RETURN_RET_LOGE(data.WriteInterfaceToken(GetDescriptor()),
        SOFTBUS_TRANS_PROXY_WRITETOKEN_FAILED, TRANS_CTRL, "write InterfaceToken failed!");
    TRANS_CHECK_AND_RETURN_RET_LOGE(data.WriteInt32(channelId),
        SOFTBUS_TRANS_PROXY_WRITEINT_FAILED, TRANS_CTRL, "write channel id failed");
    TRANS_CHECK_AND_RETURN_RET_LOGE(data.WriteInt32(channelType),
        SOFTBUS_TRANS_PROXY_WRITEINT_FAILED, TRANS_CTRL, "write channel type failed");
    TRANS_CHECK_AND_RETURN_RET_LOGE(data.WriteInt32(errCode),
        SOFTBUS_TRANS_PROXY_WRITEINT_FAILED, TRANS_CTRL, "write error code failed");

    MessageParcel reply;
    MessageOption option = { MessageOption::TF_ASYNC };
    int32_t ret = remote->SendRequest(CLIENT_ON_CHANNEL_OPENFAILED, data, reply, option);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "OnChannelOpenFailed send request failed, ret=%{public}d", ret);
        return SOFTBUS_TRANS_PROXY_SEND_REQUEST_FAILED;
    }

    return SOFTBUS_OK;
}

int32_t TransClientProxy::OnChannelLinkDown(const char *networkId, int32_t routeType)
{
    sptr<IRemoteObject> remote = Remote();
    TRANS_CHECK_AND_RETURN_RET_LOGE(remote != nullptr,
        SOFTBUS_TRANS_PROXY_REMOTE_NULL, TRANS_CTRL, "remote is nullptr");
    TRANS_CHECK_AND_RETURN_RET_LOGE(networkId != nullptr,
        SOFTBUS_INVALID_PARAM, TRANS_CTRL, "invalid parameters");

    MessageParcel data;
    TRANS_CHECK_AND_RETURN_RET_LOGE(data.WriteInterfaceToken(GetDescriptor()),
        SOFTBUS_TRANS_PROXY_WRITETOKEN_FAILED, TRANS_CTRL, "write InterfaceToken failed!");
    TRANS_CHECK_AND_RETURN_RET_LOGE(data.WriteCString(networkId),
        SOFTBUS_TRANS_PROXY_WRITECSTRING_FAILED, TRANS_CTRL, "write networkId failed");
    TRANS_CHECK_AND_RETURN_RET_LOGE(data.WriteInt32(routeType),
        SOFTBUS_TRANS_PROXY_WRITEINT_FAILED, TRANS_CTRL, "write routeType failed");

    MessageParcel reply;
    MessageOption option(MessageOption::TF_ASYNC);
    int32_t ret = remote->SendRequest(CLIENT_ON_CHANNEL_LINKDOWN, data, reply, option);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "OnChannelLinkDwon send request failed, ret=%{public}d", ret);
        return SOFTBUS_TRANS_PROXY_SEND_REQUEST_FAILED;
    }
    return SOFTBUS_OK;
}

int32_t TransClientProxy::OnChannelClosed(int32_t channelId, int32_t channelType, int32_t messageType)
{
    sptr<IRemoteObject> remote = Remote();
    TRANS_CHECK_AND_RETURN_RET_LOGE(remote != nullptr,
        SOFTBUS_TRANS_PROXY_REMOTE_NULL, TRANS_CTRL, "remote is nullptr");

    MessageParcel data;
    TRANS_CHECK_AND_RETURN_RET_LOGE(data.WriteInterfaceToken(GetDescriptor()),
        SOFTBUS_TRANS_PROXY_WRITETOKEN_FAILED, TRANS_CTRL, "write InterfaceToken failed!");
    TRANS_CHECK_AND_RETURN_RET_LOGE(data.WriteInt32(channelId),
        SOFTBUS_TRANS_PROXY_WRITEINT_FAILED, TRANS_CTRL, "write channel id failed");
    TRANS_CHECK_AND_RETURN_RET_LOGE(data.WriteInt32(channelType),
        SOFTBUS_TRANS_PROXY_WRITEINT_FAILED, TRANS_CTRL, "write channel type failed");
    TRANS_CHECK_AND_RETURN_RET_LOGE(data.WriteInt32(messageType),
        SOFTBUS_TRANS_PROXY_WRITEINT_FAILED, TRANS_CTRL, "write message type failed");

    MessageParcel reply;
    MessageOption option(MessageOption::TF_ASYNC);
    int32_t ret = remote->SendRequest(CLIENT_ON_CHANNEL_CLOSED, data, reply, option);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "OnChannelClosed send request failed, ret=%{public}d", ret);
        return SOFTBUS_TRANS_PROXY_SEND_REQUEST_FAILED;
    }
    return SOFTBUS_OK;
}

int32_t TransClientProxy::OnChannelMsgReceived(int32_t channelId, int32_t channelType, const void *dataInfo,
    uint32_t len, int32_t type)
{
    sptr<IRemoteObject> remote = Remote();
    TRANS_CHECK_AND_RETURN_RET_LOGE(remote != nullptr,
        SOFTBUS_TRANS_PROXY_REMOTE_NULL, TRANS_CTRL, "remote is nullptr");

    MessageParcel data;
    TRANS_CHECK_AND_RETURN_RET_LOGE(data.WriteInterfaceToken(GetDescriptor()),
        SOFTBUS_TRANS_PROXY_WRITETOKEN_FAILED, TRANS_CTRL, "write InterfaceToken failed!");
    TRANS_CHECK_AND_RETURN_RET_LOGE(data.WriteInt32(channelId),
        SOFTBUS_TRANS_PROXY_WRITEINT_FAILED, TRANS_CTRL, "write channel id failed");
    TRANS_CHECK_AND_RETURN_RET_LOGE(data.WriteInt32(channelType),
        SOFTBUS_TRANS_PROXY_WRITEINT_FAILED, TRANS_CTRL, "write channel type failed");
    TRANS_CHECK_AND_RETURN_RET_LOGE(data.WriteUint32(len),
        SOFTBUS_TRANS_PROXY_WRITEINT_FAILED, TRANS_CTRL, "write data len failed");
    TRANS_CHECK_AND_RETURN_RET_LOGE(data.WriteRawData(dataInfo, len),
        SOFTBUS_TRANS_PROXY_READRAWDATA_FAILED, TRANS_CTRL, "write (dataInfo, len) failed");
    TRANS_CHECK_AND_RETURN_RET_LOGE(data.WriteInt32(type),
        SOFTBUS_TRANS_PROXY_WRITEINT_FAILED, TRANS_CTRL, "write type failed");

    MessageParcel reply;
    MessageOption option(MessageOption::TF_ASYNC);
    TRANS_LOGD(TRANS_CTRL, "SendRequest start");
    int32_t ret = remote->SendRequest(CLIENT_ON_CHANNEL_MSGRECEIVED, data, reply, option);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "OnChannelMsgReceived send request failed, ret=%{public}d",
            ret);
        return SOFTBUS_TRANS_PROXY_SEND_REQUEST_FAILED;
    }
    return SOFTBUS_OK;
}

int32_t TransClientProxy::OnChannelQosEvent(int32_t channelId, int32_t channelType, int32_t eventId, int32_t tvCount,
    const QosTv *tvList)
{
    sptr<IRemoteObject> remote = Remote();
    TRANS_CHECK_AND_RETURN_RET_LOGE(remote != nullptr,
        SOFTBUS_TRANS_PROXY_REMOTE_NULL, TRANS_CTRL, "remote is nullptr");

    MessageParcel data;
    TRANS_CHECK_AND_RETURN_RET_LOGE(data.WriteInterfaceToken(GetDescriptor()),
        SOFTBUS_TRANS_PROXY_WRITETOKEN_FAILED, TRANS_CTRL, "write InterfaceToken failed!");
    TRANS_CHECK_AND_RETURN_RET_LOGE(data.WriteInt32(channelId),
        SOFTBUS_TRANS_PROXY_WRITEINT_FAILED, TRANS_CTRL, "write channel id failed");
    TRANS_CHECK_AND_RETURN_RET_LOGE(data.WriteInt32(channelType),
        SOFTBUS_TRANS_PROXY_WRITEINT_FAILED, TRANS_CTRL, "write channel type failed");
    TRANS_CHECK_AND_RETURN_RET_LOGE(data.WriteInt32(eventId),
        SOFTBUS_TRANS_PROXY_WRITEINT_FAILED, TRANS_CTRL, "write eventId failed");
    TRANS_CHECK_AND_RETURN_RET_LOGE(data.WriteInt32(tvCount),
        SOFTBUS_TRANS_PROXY_WRITEINT_FAILED, TRANS_CTRL, "write tv count failed");
    TRANS_CHECK_AND_RETURN_RET_LOGE(data.WriteRawData(tvList, sizeof(QosTv) * tvCount),
        SOFTBUS_TRANS_PROXY_WRITERAWDATA_FAILED, TRANS_CTRL, "write tv list failed");
    MessageParcel reply;
    MessageOption option;
    int32_t ret = remote->SendRequest(CLIENT_ON_CHANNEL_QOSEVENT, data, reply, option);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "OnChannelQosEvent send request failed, ret=%{public}d", ret);
        return ret;
    }
    int32_t serverRet;
    if (!reply.ReadInt32(serverRet)) {
        TRANS_LOGE(TRANS_CTRL, "OnChannelQosEvent read serverRet failed");
        return SOFTBUS_TRANS_PROXY_READINT_FAILED;
    }
    return SOFTBUS_OK;
}

int32_t TransClientProxy::SetChannelInfo(
    const char *sessionName, int32_t sessionId, int32_t channelId, int32_t channelType)
{
    if (sessionName == nullptr) {
        TRANS_LOGE(TRANS_CTRL, "Invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        TRANS_LOGE(TRANS_CTRL, "Remote is nullptr");
        return SOFTBUS_TRANS_PROXY_REMOTE_NULL;
    }

    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        TRANS_LOGE(TRANS_CTRL, "Write InterfaceToken failed!");
        return SOFTBUS_TRANS_PROXY_WRITETOKEN_FAILED;
    }
    WRITE_PARCEL_WITH_RET(data, CString, sessionName, SOFTBUS_TRANS_PROXY_WRITECSTRING_FAILED);
    WRITE_PARCEL_WITH_RET(data, Int32, sessionId, SOFTBUS_TRANS_PROXY_WRITERAWDATA_FAILED);
    WRITE_PARCEL_WITH_RET(data, Int32, channelId, SOFTBUS_TRANS_PROXY_WRITERAWDATA_FAILED);
    WRITE_PARCEL_WITH_RET(data, Int32, channelType, SOFTBUS_TRANS_PROXY_WRITERAWDATA_FAILED);
    MessageParcel reply;
    MessageOption option;
    int32_t ret = remote->SendRequest(CLIENT_SET_CHANNEL_INFO, data, reply, option);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "Send request failed, ret=%{public}d", ret);
        return SOFTBUS_TRANS_PROXY_SEND_REQUEST_FAILED;
    }
    int32_t serverRet;
    if (!reply.ReadInt32(serverRet)) {
        TRANS_LOGE(TRANS_CTRL, "read serverRet failed");
        return SOFTBUS_TRANS_PROXY_READRAWDATA_FAILED;
    }
    return serverRet;
}

int32_t TransClientProxy::OnClientChannelOnQos(
    int32_t channelId, int32_t channelType, QoSEvent event, const QosTV *qos, uint32_t count)
{
    if (qos == nullptr) {
        TRANS_LOGE(TRANS_CTRL, "qos is nullptr");
        return SOFTBUS_INVALID_PARAM;
    }
    sptr<IRemoteObject> remote = Remote();
    TRANS_CHECK_AND_RETURN_RET_LOGE(
        remote != nullptr, SOFTBUS_TRANS_PROXY_REMOTE_NULL, TRANS_CTRL, "remote is nullptr");

    MessageParcel data;
    TRANS_CHECK_AND_RETURN_RET_LOGE(data.WriteInterfaceToken(GetDescriptor()), SOFTBUS_TRANS_PROXY_WRITETOKEN_FAILED,
        TRANS_CTRL, "write interface token failed!");
    TRANS_CHECK_AND_RETURN_RET_LOGE(
        data.WriteInt32(channelId), SOFTBUS_TRANS_PROXY_WRITEINT_FAILED, TRANS_CTRL, "write channel id failed");
    TRANS_CHECK_AND_RETURN_RET_LOGE(
        data.WriteInt32(channelType), SOFTBUS_TRANS_PROXY_WRITEINT_FAILED, TRANS_CTRL, "write channel type failed");
    TRANS_CHECK_AND_RETURN_RET_LOGE(
        data.WriteInt32(event), SOFTBUS_TRANS_PROXY_WRITEINT_FAILED, TRANS_CTRL, "write qos event failed");
    TRANS_CHECK_AND_RETURN_RET_LOGE(
        data.WriteUint32(count), SOFTBUS_TRANS_PROXY_WRITEINT_FAILED, TRANS_CTRL, "write qos tv count failed");
    TRANS_CHECK_AND_RETURN_RET_LOGE(
        data.WriteBuffer(qos, sizeof(QosTV) * count), SOFTBUS_IPC_ERR, TRANS_CTRL, "write qos failed");
    MessageParcel reply;
    MessageOption option = { MessageOption::TF_ASYNC };
    int32_t ret = remote->SendRequest(CLIENT_CHANNEL_ON_QOS, data, reply, option);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "OnClientChannelOnQos send request failed, ret=%{public}d", ret);
        return SOFTBUS_TRANS_PROXY_SEND_REQUEST_FAILED;
    }
    return SOFTBUS_OK;
}

int32_t TransClientProxy::OnCheckCollabRelation(
    const CollabInfo *sourceInfo, const CollabInfo *sinkInfo, int32_t channelId, int32_t channelType)
{
    if (sourceInfo == nullptr || sinkInfo == nullptr) {
        TRANS_LOGE(TRANS_CTRL, "invalid param.");
        return SOFTBUS_INVALID_PARAM;
    }
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        TRANS_LOGE(TRANS_CTRL, "Remote is nullptr");
        return SOFTBUS_TRANS_PROXY_REMOTE_NULL;
    }

    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        TRANS_LOGE(TRANS_CTRL, "Write InterfaceToken failed!");
        return SOFTBUS_TRANS_PROXY_WRITETOKEN_FAILED;
    }
    WRITE_PARCEL_WITH_RET(data, Int64, sourceInfo->accountId, SOFTBUS_TRANS_PROXY_WRITEINT_FAILED);
    WRITE_PARCEL_WITH_RET(data, Uint64, sourceInfo->tokenId, SOFTBUS_TRANS_PROXY_WRITEINT_FAILED);
    WRITE_PARCEL_WITH_RET(data, Int32, sourceInfo->userId, SOFTBUS_TRANS_PROXY_WRITEINT_FAILED);
    WRITE_PARCEL_WITH_RET(data, Int32, sourceInfo->pid, SOFTBUS_TRANS_PROXY_WRITEINT_FAILED);
    WRITE_PARCEL_WITH_RET(data, CString, sourceInfo->deviceId, SOFTBUS_TRANS_PROXY_WRITECSTRING_FAILED);
    WRITE_PARCEL_WITH_RET(data, Int64, sinkInfo->accountId, SOFTBUS_TRANS_PROXY_WRITEINT_FAILED);
    WRITE_PARCEL_WITH_RET(data, Uint64, sinkInfo->tokenId, SOFTBUS_TRANS_PROXY_WRITEINT_FAILED);
    WRITE_PARCEL_WITH_RET(data, Int32, sinkInfo->userId, SOFTBUS_TRANS_PROXY_WRITEINT_FAILED);
    WRITE_PARCEL_WITH_RET(data, Int32, sinkInfo->pid, SOFTBUS_TRANS_PROXY_WRITEINT_FAILED);
    WRITE_PARCEL_WITH_RET(data, CString, sinkInfo->deviceId, SOFTBUS_TRANS_PROXY_WRITECSTRING_FAILED);
    WRITE_PARCEL_WITH_RET(data, Int32, channelId, SOFTBUS_TRANS_PROXY_WRITEINT_FAILED);
    WRITE_PARCEL_WITH_RET(data, Int32, channelType, SOFTBUS_TRANS_PROXY_WRITEINT_FAILED);
    MessageParcel reply;
    MessageOption option(MessageOption::TF_ASYNC);
    int32_t ret = remote->SendRequest(CLIENT_CHECK_COLLAB_RELATION, data, reply, option);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "Send request failed, ret=%{public}d", ret);
        return SOFTBUS_TRANS_PROXY_SEND_REQUEST_FAILED;
    }
    TransCheckChannelOpenToLooperDelay(channelId, channelType, FAST_INTERVAL_MILLISECOND);
    return ret;
}

int32_t TransClientProxy::OnJoinLNNResult(void *addr, uint32_t addrTypeLen, const char *networkId, int retCode)
{
    (void)addr;
    (void)addrTypeLen;
    (void)networkId;
    (void)retCode;
    return SOFTBUS_OK;
}

int32_t TransClientProxy::OnJoinMetaNodeResult(void *addr, uint32_t addrTypeLen, void *metaInfo,
    uint32_t infoLen, int retCode)
{
    (void)addr;
    (void)addrTypeLen;
    (void)metaInfo;
    (void)infoLen;
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

int32_t TransClientProxy::OnNodeOnlineStateChanged(const char *pkgName, bool isOnline,
    void *info, uint32_t infoTypeLen)
{
    (void)pkgName;
    (void)isOnline;
    (void)info;
    (void)infoTypeLen;
    return SOFTBUS_OK;
}

int32_t TransClientProxy::OnNodeBasicInfoChanged(const char *pkgName, void *info,
    uint32_t infoTypeLen, int32_t type)
{
    (void)pkgName;
    (void)info;
    (void)infoTypeLen;
    (void)type;
    return SOFTBUS_OK;
}

int32_t TransClientProxy::OnNodeStatusChanged(const char *pkgName, void *info,
    uint32_t infoTypeLen, int32_t type)
{
    (void)pkgName;
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

void TransClientProxy::OnDataLevelChanged(const char *networkId, const DataLevelInfo *dataLevelInfo)
{
    (void)networkId;
    (void)dataLevelInfo;
}
} // namespace OHOS