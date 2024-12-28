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

#include "client_trans_udp_manager.h"

#include "softbus_error_code.h"

int32_t ClientTransUdpMgrInit(IClientSessionCallBack *callback)
{
    (void)callback;
    return SOFTBUS_OK;
}

void ClientTransUdpMgrDeinit(void)
{
    return;
}

int32_t TransOnUdpChannelOpened(const char *sessionName, const ChannelInfo *channel, int32_t *udpPort)
{
    (void)sessionName;
    (void)channel;
    (void)udpPort;
    return SOFTBUS_FUNC_NOT_SUPPORT;
}

int32_t TransOnUdpChannelOpenFailed(int32_t channelId, int32_t errCode)
{
    (void)channelId;
    (void)errCode;
    return SOFTBUS_FUNC_NOT_SUPPORT;
}
int32_t TransOnUdpChannelClosed(int32_t channelId, ShutdownReason reason)
{
    (void)channelId;
    return SOFTBUS_FUNC_NOT_SUPPORT;
}

int32_t ClientTransCloseUdpChannel(int32_t channelId, ShutdownReason reason)
{
    (void)channelId;
    (void)reason;
    return SOFTBUS_FUNC_NOT_SUPPORT;
}

int32_t TransUdpChannelSendStream(int32_t channelId, const StreamData *data, const StreamData *ext,
    const StreamFrameInfo *param)
{
    (void)channelId;
    (void)data;
    (void)ext;
    (void)param;
    return SOFTBUS_FUNC_NOT_SUPPORT;
}

int32_t TransUdpChannelSendFile(int32_t channelId, const char *sFileList[], const char *dFileList[], uint32_t fileCnt)
{
    (void)channelId;
    (void)sFileList;
    (void)dFileList;
    (void)fileCnt;
    return SOFTBUS_FUNC_NOT_SUPPORT;
}

int32_t TransGetUdpChannelByFileId(int32_t dfileId, UdpChannel *udpChannel)
{
    (void)dfileId;
    (void)udpChannel;
    return SOFTBUS_FUNC_NOT_SUPPORT;
}

void TransUdpDeleteFileListener(const char *sessionName)
{
    (void)sessionName;
}

int32_t TransOnUdpChannelQosEvent(int32_t channelId, int32_t eventId, int32_t tvCount, const QosTv *tvList)
{
    (void)channelId;
    (void)eventId;
    (void)tvCount;
    (void)tvList;
    return SOFTBUS_FUNC_NOT_SUPPORT;
}

int32_t TransGetUdpChannel(int32_t channelId, UdpChannel *udpChannel)
{
    (void)channelId;
    (void)udpChannel;
    return SOFTBUS_FUNC_NOT_SUPPORT;
}

int32_t TransLimitChange(int32_t channelId, uint8_t tos)
{
    (void)channelId;
    (void)tos;
    return SOFTBUS_FUNC_NOT_SUPPORT;
}

int32_t TransSetUdpChanelSessionId(int32_t channelId, int32_t sessionId)
{
    (void)channelId;
    (void)sessionId;
    return SOFTBUS_FUNC_NOT_SUPPORT;
}

int32_t ClientEmitFileEvent(int32_t channelId)
{
    (void)channelId;
    return SOFTBUS_FUNC_NOT_SUPPORT;
}

int32_t TransUdpOnCloseAckReceived(int32_t channelId)
{
    (void)channelId;
    return SOFTBUS_FUNC_NOT_SUPPORT;
}

int32_t TransOnUdpChannelBind(int32_t channelId, int32_t channelType)
{
    (void)channelId;
    (void)channelType;
    return SOFTBUS_FUNC_NOT_SUPPORT;
}

int32_t TransSetUdpChannelRenameHook(int32_t channelId, OnRenameFileCallback onRenameFile)
{
    (void)channelId;
    (void)onRenameFile;
    return SOFTBUS_FUNC_NOT_SUPPORT;
}

int32_t TransUdpChannelSetStreamMultiLayer(int32_t channelId, const void *optValue)
{
    (void)channelId;
    (void)optValue;
    return SOFTBUS_FUNC_NOT_SUPPORT;
}