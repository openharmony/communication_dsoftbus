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

#include "trans_client_proxy.h"

#include "ipc_skeleton.h"
#include "serializer.h"
#include "softbus_adapter_mem.h"
#include "softbus_base_listener.h"
#include "softbus_client_info_manager.h"
#include "softbus_def.h"
#include "softbus_error_code.h"
#include "softbus_server_ipc_interface_code.h"
#include "softbus_socket.h"
#include "trans_log.h"

static int32_t GetSvcIdentityByPkgName(const char *pkgName, SvcIdentity *svc)
{
    struct CommonScvId svcId = {0};
    int32_t ret = SERVER_GetIdentityByPkgName(pkgName, &svcId);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "ger identity failed");
        return ret;
    }
    svc->handle = (int32_t)svcId.handle;
    svc->token = (uintptr_t)svcId.token;
    svc->cookie = (uintptr_t)svcId.cookie;

    return SOFTBUS_OK;
}

static int32_t OnUdpChannelOpenedAsServer(const SvcIdentity *svc, IpcIo *io)
{
    IpcIo reply;
    uintptr_t ptr = 0;
    MessageOption option;
    MessageOptionInit(&option);
    int32_t ans = SendRequest(*svc, CLIENT_ON_CHANNEL_OPENED, io, &reply, option, &ptr);
    if (ans != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "OnChannelOpened SendRequest failed");
        FreeBuffer((void *)ptr);
        return ans;
    }
    int32_t udpPort;
    ReadInt32(&reply, &udpPort);
    FreeBuffer((void *)ptr);
    return udpPort;
}

int32_t ClientIpcOnChannelOpened(const char *pkgName, const char *sessionName,
    const ChannelInfo *channel, int32_t pid)
{
    (void)pid;
    IpcIo io;
    uint8_t tmpData[MAX_SOFT_BUS_IPC_LEN_EX];
    IpcIoInit(&io, tmpData, MAX_SOFT_BUS_IPC_LEN_EX, (channel->channelType == CHANNEL_TYPE_TCP_DIRECT) ? 1 : 0);
    WriteString(&io, sessionName);
    WriteInt32(&io, channel->channelId);
    WriteInt32(&io, channel->channelType);
    WriteBool(&io, channel->isServer);
    WriteBool(&io, channel->isEnabled);
    WriteBool(&io, channel->isEncrypt);
    WriteInt32(&io, channel->peerUid);
    WriteInt32(&io, channel->peerPid);
    WriteString(&io, channel->groupId);
    WriteUint32(&io, channel->keyLen);
    WriteBuffer(&io, channel->sessionKey, channel->keyLen);
    WriteString(&io, channel->peerSessionName);
    WriteString(&io, channel->peerDeviceId);
    if ((channel->channelType == CHANNEL_TYPE_TCP_DIRECT) && (!WriteString(&io, channel->myIp) ||
        !WriteFileDescriptor(&io, channel->fd))) {
        return SOFTBUS_TRANS_INVALID_CHANNEL_TYPE;
    }
    SvcIdentity svc = { 0 };
    int32_t ret = GetSvcIdentityByPkgName(pkgName, &svc);
    TRANS_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, TRANS_CTRL, "OnChannelOpened get svc failed.");
    WriteInt32(&io, channel->businessType);
    if (channel->channelType == CHANNEL_TYPE_UDP) {
        WriteString(&io, channel->myIp);
        WriteInt32(&io, channel->streamType);
        WriteBool(&io, channel->isUdpFile);
        if (channel->isServer) {
            return OnUdpChannelOpenedAsServer(&svc, &io);
        }
        WriteInt32(&io, channel->peerPort);
        WriteString(&io, channel->peerIp);
    }
    WriteInt32(&io, channel->routeType);
    MessageOption option;
    MessageOptionInit(&option);
    option.flags = TF_OP_ASYNC;
    int32_t ans = SendRequest(svc, CLIENT_ON_CHANNEL_OPENED, &io, NULL, option, NULL);
    if (ans != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "OnChannelOpened SendRequest failed");
    }
    return ans;
}

int32_t ClientIpcOnChannelBind(ChannelMsg *data)
{
    if (data == NULL) {
        TRANS_LOGE(TRANS_CTRL, "ClientIpcOnChannelBind data is null.");
        return SOFTBUS_INVALID_PARAM;
    }

    IpcIo io;
    uint8_t tmpData[MAX_SOFT_BUS_IPC_LEN];
    IpcIoInit(&io, tmpData, MAX_SOFT_BUS_IPC_LEN, 0);
    WriteInt32(&io, data->msgChannelId);
    WriteInt32(&io, data->msgChannelType);
    SvcIdentity svc = {0};
    int32_t ret = GetSvcIdentityByPkgName(data->msgPkgName, &svc);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "ClientIpcOnChannelBind get svc failed, msgPkgName=%{public}s", data->msgPkgName);
        return ret;
    }
    MessageOption option;
    MessageOptionInit(&option);
    option.flags = TF_OP_ASYNC;
    ret = SendRequest(svc, CLIENT_ON_CHANNEL_BIND, &io, NULL, option, NULL);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "ClientIpcOnChannelBind SendRequest failed, msgPkgName=%{public}s", data->msgPkgName);
    }
    return ret;
}

int32_t ClientIpcOnChannelOpenFailed(ChannelMsg *data, int32_t errCode)
{
    if (data == NULL) {
        TRANS_LOGE(TRANS_CTRL, "ClientIpcOnChannelOpenFailed data is null.");
        return SOFTBUS_INVALID_PARAM;
    }
    TRANS_LOGI(TRANS_CTRL, "on channel open failed ipc server push");
    IpcIo io;
    uint8_t tmpData[MAX_SOFT_BUS_IPC_LEN];
    IpcIoInit(&io, tmpData, MAX_SOFT_BUS_IPC_LEN, 0);
    WriteInt32(&io, data->msgChannelId);
    WriteInt32(&io, data->msgChannelType);
    WriteInt32(&io, errCode);
    SvcIdentity svc = {0};
    int32_t ret = GetSvcIdentityByPkgName(data->msgPkgName, &svc);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "ClientIpcOnChannelOpenFailed get svc failed.");
        return ret;
    }
    MessageOption option;
    MessageOptionInit(&option);
    option.flags = TF_OP_ASYNC;
    int32_t ans = SendRequest(svc, CLIENT_ON_CHANNEL_OPENFAILED, &io, NULL, option, NULL);
    if (ans != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "ClientIpcOnChannelOpenFailed SendRequest failed");
    }
    return ans;
}

int32_t ClientIpcOnChannelLinkDown(ChannelMsg *data, const char *networkId, const char *peerIp, int32_t routeType)
{
    if (data == NULL || networkId == NULL) {
        TRANS_LOGE(TRANS_CTRL, "ClientIpcOnChannelLinkDown data or networkId is null.");
        return SOFTBUS_INVALID_PARAM;
    }
    (void)peerIp;
    TRANS_LOGI(TRANS_CTRL, "pkgName=%{public}s", data->msgPkgName);

    IpcIo io;
    uint8_t tmpData[MAX_SOFT_BUS_IPC_LEN];
    IpcIoInit(&io, tmpData, MAX_SOFT_BUS_IPC_LEN, 0);
    WriteString(&io, networkId);
    WriteInt32(&io, routeType);
    SvcIdentity svc = {0};
    int32_t ret = GetSvcIdentityByPkgName(data->msgPkgName, &svc);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "OnLeaveLNNResult callback get svc failed.");
        return ret;
    }
    MessageOption option;
    MessageOptionInit(&option);
    option.flags = TF_OP_ASYNC;
    int32_t ans = SendRequest(svc, CLIENT_ON_CHANNEL_LINKDOWN, &io, NULL, option, NULL);
    if (ans != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "callback SendRequest failed.");
        return ans;
    }
    return SOFTBUS_OK;
}

int32_t ClientIpcOnChannelClosed(ChannelMsg *data)
{
    if (data == NULL) {
        TRANS_LOGE(TRANS_CTRL, "ClientIpcOnChannelClosed data is null.");
        return SOFTBUS_INVALID_PARAM;
    }
    TRANS_LOGI(TRANS_CTRL, "on channel closed ipc server push");
    IpcIo io;
    uint8_t tmpData[MAX_SOFT_BUS_IPC_LEN];
    IpcIoInit(&io, tmpData, MAX_SOFT_BUS_IPC_LEN, 0);
    WriteInt32(&io, data->msgChannelId);
    WriteInt32(&io, data->msgChannelType);
    WriteInt32(&io, data->msgMessageType);
    SvcIdentity svc = {0};
    int32_t ret = GetSvcIdentityByPkgName(data->msgPkgName, &svc);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "OnChannelOpenClosed get svc failed.");
        return ret;
    }
    MessageOption option;
    MessageOptionInit(&option);
    option.flags = TF_OP_ASYNC;
    int32_t ans = SendRequest(svc, CLIENT_ON_CHANNEL_CLOSED, &io, NULL, option, NULL);
    if (ans != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "OnChannelOpenClosed SendRequest failed");
    }
    return ans;
}

int32_t ClientIpcOnChannelMsgReceived(ChannelMsg *data, TransReceiveData *receiveData)
{
    if (data == NULL || receiveData == NULL) {
        TRANS_LOGE(TRANS_CTRL, "ClientIpcOnChannelClosed data or receiveData is null.");
        return SOFTBUS_INVALID_PARAM;
    }
    TRANS_LOGI(TRANS_CTRL, "on channel msg received ipc server push");
    IpcIo io;
    uint8_t *tmpData = (uint8_t *)SoftBusCalloc(receiveData->dataLen + MAX_SOFT_BUS_IPC_LEN);
    if (tmpData == NULL) {
        TRANS_LOGE(TRANS_CTRL, "tmpData is null");
        return SOFTBUS_MALLOC_ERR;
    }
    IpcIoInit(&io, tmpData, receiveData->dataLen + MAX_SOFT_BUS_IPC_LEN, 0);
    WriteInt32(&io, data->msgChannelId);
    WriteInt32(&io, data->msgChannelType);
    WriteInt32(&io, receiveData->dataType);
    WriteUint32(&io, receiveData->dataLen);
    WriteBuffer(&io, receiveData->data, receiveData->dataLen);
    SvcIdentity svc = {0};
    int32_t ret = GetSvcIdentityByPkgName(data->msgPkgName, &svc);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "OnChannelMsgReceived get svc failed");
        SoftBusFree(tmpData);
        return ret;
    }
    MessageOption option;
    MessageOptionInit(&option);
    option.flags = TF_OP_ASYNC;
    int32_t ans = SendRequest(svc, CLIENT_ON_CHANNEL_MSGRECEIVED, &io, NULL, option, NULL);
    if (ans != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "OnChannelMsgReceived SendRequest failed");
    }
    SoftBusFree(tmpData);
    return ans;
}

int32_t ClientIpcOnChannelQosEvent(const char *pkgName, const QosParam *param)
{
    (void)pkgName;
    (void)param;
    return SOFTBUS_FUNC_NOT_SUPPORT;
}

int32_t ClientIpcSetChannelInfo(
    const char *pkgName, const char *sessionName, int32_t sessionId, const TransInfo *transInfo, int32_t pid)
{
    if (pkgName == NULL || sessionName == NULL || transInfo == NULL) {
        TRANS_LOGE(TRANS_CTRL, "Invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    (void)pid;
    TRANS_LOGI(TRANS_CTRL, "Set channel info ipc server push");
    IpcIo io;
    uint8_t tmpData[MAX_SOFT_BUS_IPC_LEN];
    IpcIoInit(&io, tmpData, MAX_SOFT_BUS_IPC_LEN, 0);
    WriteString(&io, sessionName);
    WriteInt32(&io, sessionId);
    WriteInt32(&io, transInfo->channelId);
    WriteInt32(&io, transInfo->channelType);
    SvcIdentity svc = {0};
    int32_t ret = GetSvcIdentityByPkgName(pkgName, &svc);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "get svc failed, ret=%{public}d", ret);
        return ret;
    }
    MessageOption option;
    MessageOptionInit(&option);
    option.flags = TF_OP_ASYNC;
    ret = SendRequest(svc, CLIENT_SET_CHANNEL_INFO, &io, NULL, option, NULL);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "SendRequest failed, ret=%{public}d", ret);
    }
    return ret;
}

int32_t ClientIpcOnTransLimitChange(const char *pkgName, int32_t pid, int32_t channelId, uint8_t tos)
{
    (void)pkgName;
    (void)pid;
    (void)channelId;
    (void)tos;
    return SOFTBUS_FUNC_NOT_SUPPORT;
}

int32_t CheckServiceIsRegistered(const char *pkgName, int32_t pid)
{
    (void)pkgName;
    (void)pid;
    return SOFTBUS_FUNC_NOT_SUPPORT;
}

int32_t ClientIpcChannelOnQos(ChannelMsg *data, QoSEvent event, const QosTV *qos, uint32_t count)
{
    (void)data;
    (void)event;
    (void)qos;
    (void)count;
    return SOFTBUS_FUNC_NOT_SUPPORT;
}

void RegisterPermissionChangeCallback(void)
{
    return;
}

int32_t ClientIpcCheckCollabRelation(const char *pkgName, int32_t pid,
    const CollabInfo *sourceInfo, const CollabInfo *sinkInfo, const TransInfo *transInfo)
{
    if (pkgName == NULL || sourceInfo == NULL || sinkInfo == NULL || transInfo == NULL) {
        TRANS_LOGE(TRANS_CTRL, "Invalid param.");
        return SOFTBUS_INVALID_PARAM;
    }
    (void)pid;
    TRANS_LOGI(TRANS_CTRL, "check Collab relation ipc server push.");
    IpcIo io;
    uint8_t tmpData[MAX_SOFT_BUS_IPC_LEN];
    IpcIoInit(&io, tmpData, MAX_SOFT_BUS_IPC_LEN, 0);
    WriteInt64(&io, sourceInfo->accountId);
    WriteUint64(&io, sourceInfo->tokenId);
    WriteInt32(&io, sourceInfo->userId);
    WriteInt32(&io, sourceInfo->pid);
    WriteString(&io, sourceInfo->deviceId);
    WriteInt64(&io, sinkInfo->accountId);
    WriteUint64(&io, sinkInfo->tokenId);
    WriteInt32(&io, sinkInfo->userId);
    WriteInt32(&io, sinkInfo->pid);
    WriteString(&io, sinkInfo->deviceId);
    WriteInt32(&io, transInfo->channelId);
    WriteInt32(&io, transInfo->channelType);
    SvcIdentity svc = {0};
    int32_t ret = GetSvcIdentityByPkgName(pkgName, &svc);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "get svc failed, ret=%{public}d", ret);
        return ret;
    }
    MessageOption option;
    MessageOptionInit(&option);
    option.flags = TF_OP_ASYNC;
    ret = SendRequest(svc, CLIENT_CHECK_COLLAB_RELATION, &io, NULL, option, NULL);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "SendRequest failed, ret=%{public}d", ret);
    }
    return ret;
}
