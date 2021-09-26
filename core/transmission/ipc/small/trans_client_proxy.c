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

#include "trans_client_proxy.h"

#include "liteipc_adapter.h"
#include "serializer.h"
#include "softbus_adapter_mem.h"
#include "softbus_base_listener.h"
#include "softbus_client_info_manager.h"
#include "softbus_errcode.h"
#include "softbus_ipc_def.h"
#include "softbus_log.h"
#include "softbus_tcp_socket.h"

static int32_t GetSvcIdentityByPkgName(const char *pkgName, SvcIdentity *svc)
{
    struct CommonScvId svcId = {0};
    if (SERVER_GetIdentityByPkgName(pkgName, &svcId) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "ger identity failed");
        return SOFTBUS_ERR;
    }
    svc->handle = svcId.handle;
    svc->token = svcId.token;
    svc->cookie = svcId.cookie;
#ifdef __LINUX__
    svc->ipcContext = svcId.ipcCtx;
#endif
    return SOFTBUS_OK;
}

static int32_t OnUdpChannelOpenedAsServer(const SvcIdentity *svc, IpcIo *io)
{
    IpcIo reply;
    uintptr_t ptr = NULL;
    int32_t ans = SendRequest(NULL, *svc, CLIENT_ON_CHANNEL_OPENED, io, &reply, LITEIPC_FLAG_DEFAULT, &ptr);
    if (ans != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "OnChannelOpened SendRequest failed");
        FreeBuffer(NULL, (void *)ptr);
        return SOFTBUS_ERR;
    }
    int32_t udpPort = IpcIoPopInt32(&reply);
    FreeBuffer(NULL, (void *)ptr);
    return udpPort;
}

int32_t ClientIpcOnChannelOpened(const char *pkgName, const char *sessionName, const ChannelInfo *channel)
{
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "on channel opened ipc server push");
    IpcIo io;
    uint8_t tmpData[MAX_SOFT_BUS_IPC_LEN_EX];
    if (channel->channelType == CHANNEL_TYPE_TCP_DIRECT) {
        IpcIoInit(&io, tmpData, MAX_SOFT_BUS_IPC_LEN_EX, 1);
    } else {
        IpcIoInit(&io, tmpData, MAX_SOFT_BUS_IPC_LEN_EX, 0);
    }
    IpcIoPushString(&io, sessionName);
    IpcIoPushInt32(&io, channel->channelId);
    IpcIoPushInt32(&io, channel->channelType);
    IpcIoPushBool(&io, channel->isServer);
    IpcIoPushBool(&io, channel->isEnabled);
    IpcIoPushInt32(&io, channel->peerUid);
    IpcIoPushInt32(&io, channel->peerPid);
    IpcIoPushString(&io, channel->groupId);
    IpcIoPushUint32(&io, channel->keyLen);
    IpcIoPushFlatObj(&io, channel->sessionKey, channel->keyLen);
    IpcIoPushString(&io, channel->peerSessionName);
    IpcIoPushString(&io, channel->peerDeviceId);
    if (channel->channelType == CHANNEL_TYPE_TCP_DIRECT) {
        IpcIoPushFd(&io, channel->fd);
    }
    SvcIdentity svc = {0};
    if (GetSvcIdentityByPkgName(pkgName, &svc) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "OnChannelOpened get svc failed.");
        return SOFTBUS_ERR;
    }
    if (channel->channelType == CHANNEL_TYPE_UDP) {
        IpcIoPushInt32(&io, channel->businessType);
        IpcIoPushString(&io, channel->myIp);
        if (channel->isServer) {
            return OnUdpChannelOpenedAsServer(&svc, &io);
        }
        IpcIoPushInt32(&io, channel->peerPort);
        IpcIoPushString(&io, channel->peerIp);
    }
    int32_t ans = SendRequest(NULL, svc, CLIENT_ON_CHANNEL_OPENED, &io, NULL, LITEIPC_FLAG_ONEWAY, NULL);
    if (ans != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "OnChannelOpened SendRequest failed");
    }
    return ans;
}

int32_t ClientIpcOnChannelOpenFailed(const char *pkgName, int32_t channelId, int32_t channelType)
{
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "on channel open failed ipc server push");
    IpcIo io;
    uint8_t tmpData[MAX_SOFT_BUS_IPC_LEN];
    IpcIoInit(&io, tmpData, MAX_SOFT_BUS_IPC_LEN, 0);
    IpcIoPushInt32(&io, channelId);
    IpcIoPushInt32(&io, channelType);
    SvcIdentity svc = {0};
    if (GetSvcIdentityByPkgName(pkgName, &svc) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "OnChannelOpenFailed get svc failed.");
        return SOFTBUS_ERR;
    }
    int32_t ans = SendRequest(NULL, svc, CLIENT_ON_CHANNEL_OPENFAILED, &io, NULL, LITEIPC_FLAG_ONEWAY, NULL);
    if (ans != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "OnChannelOpenFailed SendRequest failed");
    }
    return ans;
}

int32_t ClientIpcOnChannelClosed(const char *pkgName, int32_t channelId, int32_t channelType)
{
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "on channel closed ipc server push");
    IpcIo io;
    uint8_t tmpData[MAX_SOFT_BUS_IPC_LEN];
    IpcIoInit(&io, tmpData, MAX_SOFT_BUS_IPC_LEN, 0);
    IpcIoPushInt32(&io, channelId);
    IpcIoPushInt32(&io, channelType);
    SvcIdentity svc = {0};
    if (GetSvcIdentityByPkgName(pkgName, &svc) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "OnChannelOpenClosed get svc failed.");
        return SOFTBUS_ERR;
    }
    int32_t ans = SendRequest(NULL, svc, CLIENT_ON_CHANNEL_CLOSED, &io, NULL, LITEIPC_FLAG_ONEWAY, NULL);
    if (ans != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "OnChannelOpenClosed SendRequest failed");
    }
    return ans;
}

int32_t ClientIpcOnChannelMsgReceived(const char *pkgName, int32_t channelId, int32_t channelType, 
                                      const void *data, unsigned int len, int32_t type)
{
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "on channel closed ipc server push");
    IpcIo io;
    uint8_t *tmpData = (uint8_t *)SoftBusCalloc(len + MAX_SOFT_BUS_IPC_LEN);
    IpcIoInit(&io, tmpData, len + MAX_SOFT_BUS_IPC_LEN, 0);
    IpcIoPushInt32(&io, channelId);
    IpcIoPushInt32(&io, channelType);
    IpcIoPushInt32(&io, type);
    IpcIoPushFlatObj(&io, data, len);
    SvcIdentity svc = {0};
    if (GetSvcIdentityByPkgName(pkgName, &svc) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "OnChannelOpenClosed get svc failed.");
        SoftBusFree(tmpData);
        return SOFTBUS_ERR;
    }
    int32_t ans = SendRequest(NULL, svc, CLIENT_ON_CHANNEL_MSGRECEIVED, &io, NULL, LITEIPC_FLAG_ONEWAY, NULL);
    if (ans != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "OnChannelOpenClosed SendRequest failed");
    }
    SoftBusFree(tmpData);
    return ans;
}