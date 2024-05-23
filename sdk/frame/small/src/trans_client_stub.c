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

#include "trans_client_stub.h"

#include "client_trans_channel_callback.h"
#include "ipc_skeleton.h"
#include "softbus_errcode.h"
#include "softbus_server_ipc_interface_code.h"
#include "trans_log.h"

int32_t ClientOnChannelOpened(IpcIo *data, IpcIo *reply)
{
    TRANS_CHECK_AND_RETURN_RET_LOGE(reply != NULL, SOFTBUS_INVALID_PARAM, TRANS_CTRL, "invalid param");
    size_t size = 0;
    ChannelInfo channel = {0};
    const char *sessionName = (const char *)ReadString(data, &size);
    ReadInt32(data, &(channel.channelId));
    ReadInt32(data, &(channel.channelType));
    ReadBool(data, &(channel.isServer));
    ReadBool(data, &(channel.isEnabled));
    ReadBool(data, &(channel.isEncrypt));
    ReadInt32(data, &(channel.peerUid));
    ReadInt32(data, &(channel.peerPid));
    channel.groupId = (char *)ReadString(data, &size);
    ReadUint32(data, &(channel.keyLen));
    channel.sessionKey = (char *)ReadBuffer(data, channel.keyLen);
    channel.peerSessionName = (char *)ReadString(data, &size);
    channel.peerDeviceId = (char *)ReadString(data, &size);
    if (channel.groupId == NULL || channel.sessionKey == NULL || channel.peerSessionName == NULL ||
        channel.peerDeviceId == NULL) {
        TRANS_LOGE(TRANS_CTRL, "pointer null error.");
        return SOFTBUS_ERR;
    }
    if (channel.channelType == CHANNEL_TYPE_TCP_DIRECT) {
        channel.myIp = (char *)ReadString(data, &size);
        TRANS_CHECK_AND_RETURN_RET_LOGE(channel.myIp != NULL, SOFTBUS_IPC_ERR, TRANS_CTRL, "pointer null error.");
        channel.fd = ReadFileDescriptor(data);
    }
    ReadInt32(data, &(channel.businessType));
    if (channel.channelType == CHANNEL_TYPE_UDP) {
        channel.myIp = (char *)ReadString(data, &size);
        ReadInt32(data, &(channel.streamType));
        ReadBool(data, &(channel.isUdpFile));
        if (channel.isServer) {
            int32_t udpPort = TransOnChannelOpened(sessionName, &channel);
            WriteInt32(reply, udpPort);
            return SOFTBUS_ERR;
        }
        ReadInt32(data, &(channel.peerPort));
        channel.peerIp = (char *)ReadString(data, &size);
    }
    int ret = TransOnChannelOpened(sessionName, &channel);
    if (ret < 0) {
        TRANS_LOGE(TRANS_CTRL, "TransOnChannelOpened fail, errcode=%{public}d.", ret);
    }
    return SOFTBUS_OK;
}

int32_t ClientOnChannelOpenfailed(IpcIo *data, IpcIo *reply)
{
    if (data == NULL) {
        TRANS_LOGE(TRANS_CTRL, "invalid param.");
        return SOFTBUS_INVALID_PARAM;
    }
    int32_t channelId = 0;
    int32_t channelType = 0;
    int32_t errCode = SOFTBUS_OK;
    ReadInt32(data, &channelId);
    ReadInt32(data, &channelType);
    ReadInt32(data, &errCode);
    (void)TransOnChannelOpenFailed(channelId, channelType, errCode);
    return SOFTBUS_OK;
}

int32_t ClientOnChannelClosed(IpcIo *data, IpcIo *reply)
{
    if (data == NULL) {
        TRANS_LOGE(TRANS_CTRL, "invalid param.");
        return SOFTBUS_INVALID_PARAM;
    }
    int32_t channelId = 0;
    int32_t channelType = 0;
    int32_t messageType = 0;
    ReadInt32(data, &channelId);
    ReadInt32(data, &channelType);
    ReadInt32(data, &messageType);
    (void)TransOnChannelClosed(channelId, channelType, messageType, SHUTDOWN_REASON_PEER);
    return SOFTBUS_OK;
}

int32_t ClientOnChannelMsgreceived(IpcIo *data, IpcIo *reply)
{
    if (data == NULL) {
        TRANS_LOGE(TRANS_CTRL, "invalid param.");
        return SOFTBUS_INVALID_PARAM;
    }
    int32_t channelId = 0;
    int32_t channelType = 0;
    int32_t type = 0;
    ReadInt32(data, &channelId);
    ReadInt32(data, &channelType);
    ReadInt32(data, &type);
    uint32_t dataLen = 0;
    ReadUint32(data, &dataLen);
    const uint8_t *data2 = ReadBuffer(data, dataLen);
    (void)TransOnChannelMsgReceived(channelId, channelType, data2, dataLen, type);
    return SOFTBUS_OK;
}

int32_t ClientSetChannelInfo(IpcIo *data, IpcIo *reply)
{
    if (data == NULL) {
        TRANS_LOGE(TRANS_CTRL, "invalid param.");
        return SOFTBUS_INVALID_PARAM;
    }
    (void)reply;
    size_t size = 0;
    const char *sessionName = (const char *)ReadString(data, &size);
    int32_t sessionId = 0;
    int32_t channelId = 0;
    int32_t channelType = 0;
    ReadInt32(data, &sessionId);
    ReadInt32(data, &channelId);
    ReadInt32(data, &channelType);
    (void)TransSetChannelInfo(sessionName, sessionId, channelId, channelType);
    return SOFTBUS_OK;
}