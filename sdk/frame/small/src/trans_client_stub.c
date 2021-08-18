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

#include "trans_client_stub.h"

#include "client_trans_channel_callback.h"
#include "softbus_ipc_def.h"
#include "softbus_log.h"

void ClientOnChannelOpened(IpcIo *reply, const IpcContext *ctx, void *ipcMsg)
{
    if (reply == NULL) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "invalid param.");
        FreeBuffer(ctx, ipcMsg);
        return;
    }
    int32_t size = 0;
    ChannelInfo channel = {0};
    const char *sessionName = (const char *)IpcIoPopString(reply, &size);
    channel.channelId = IpcIoPopInt32(reply);
    channel.channelType = IpcIoPopInt32(reply);
    channel.isServer = IpcIoPopBool(reply);
    channel.isEnabled = IpcIoPopBool(reply);
    channel.peerUid = IpcIoPopInt32(reply);
    channel.peerPid = IpcIoPopInt32(reply);
    channel.groupId = (char *)IpcIoPopString(reply, &size);
    channel.keyLen = IpcIoPopUint32(reply);
    channel.sessionKey = (char *)IpcIoPopFlatObj(reply, &size);
    channel.peerSessionName = (char *)IpcIoPopString(reply, &size);
    channel.peerDeviceId = (char *)IpcIoPopString(reply, &size);
    if (channel.groupId == NULL || channel.sessionKey == NULL || channel.peerSessionName == NULL ||
        channel.peerDeviceId == NULL) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "pointer null error.");
        return;
    }
    if (channel.channelType == CHANNEL_TYPE_TCP_DIRECT) {
        channel.fd = IpcIoPopFd(reply);
    }
    if (channel.channelType == CHANNEL_TYPE_UDP) {
        channel.businessType = IpcIoPopInt32(reply);
        channel.myIp = IpcIoPopString(reply, &size);
        if (channel.isServer) {
            int32_t udpPort = TransOnChannelOpened(sessionName, &channel);
            IpcIo ret;
            uint8_t tempData[MAX_SOFT_BUS_IPC_LEN] = {0};
            IpcIoInit(&ret, tempData, MAX_SOFT_BUS_IPC_LEN, 0);
            IpcIoPushInt32(&ret, udpPort);
            SendReply(NULL, ipcMsg, &ret);
            return;
        }
        channel.peerPort = IpcIoPopInt32(reply);
        channel.peerIp = IpcIoPopString(reply, &size);
    }
    int ret = TransOnChannelOpened(sessionName, &channel);
    if (ret < 0) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "TransOnChannelOpened fail, error code: %d.", ret);
    }
    
    FreeBuffer(ctx, ipcMsg);
}

void ClientOnChannelOpenfailed(IpcIo *reply, const IpcContext *ctx, void *ipcMsg)
{
    if (reply == NULL) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "invalid param.");
        FreeBuffer(ctx, ipcMsg);
        return;
    }
    int32_t channelId = IpcIoPopInt32(reply);
    int32_t channelType = IpcIoPopInt32(reply);
    (void)TransOnChannelOpenFailed(channelId, channelType);
    FreeBuffer(ctx, ipcMsg);
}

void ClientOnChannelClosed(IpcIo *reply, const IpcContext *ctx, void *ipcMsg)
{
    if (reply == NULL) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "invalid param.");
        FreeBuffer(ctx, ipcMsg);
        return;
    }
    int32_t channelId = IpcIoPopInt32(reply);
    int32_t channelType = IpcIoPopInt32(reply);
    (void)TransOnChannelClosed(channelId, channelType);
    FreeBuffer(ctx, ipcMsg);
}

void ClientOnChannelMsgreceived(IpcIo *reply, const IpcContext *ctx, void *ipcMsg)
{
    if (reply == NULL) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "invalid param.");
        FreeBuffer(ctx, ipcMsg);
        return;
    }
    int32_t channelId = IpcIoPopInt32(reply);
    int32_t channelType = IpcIoPopInt32(reply);
    int32_t type = IpcIoPopInt32(reply);
    uint32_t dataLen = 0;
    void *data = IpcIoPopFlatObj(reply, &dataLen);
    (void)TransOnChannelMsgReceived(channelId, channelType, data, dataLen, type);
    FreeBuffer(ctx, ipcMsg);
}
