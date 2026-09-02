/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "client_trans_proxy_file_manager.h"
#include "client_trans_proxy_manager.h"
#include "client_trans_pending.h"

#include "softbus_error_code.h"

int32_t ClientTransProxyInit(const IClientSessionCallBack *cb)
{
    (void)cb;
    return SOFTBUS_OK;
}

void ClientTransProxyDeinit(void)
{
    return;
}

int32_t ClientTransProxyGetInfoByChannelId(int32_t channelId, ProxyChannelInfoDetail *info)
{
    (void)channelId;
    (void)info;
    return SOFTBUS_FUNC_NOT_SUPPORT;
}

int32_t ClientTransProxyGetOsTypeByChannelId(int32_t channelId, int32_t *osType)
{
    (void)channelId;
    if (osType != NULL) {
        *osType = 0;
    }
    return SOFTBUS_FUNC_NOT_SUPPORT;
}

int32_t ClientTransProxyGetLinkTypeByChannelId(int32_t channelId, int32_t *linkType)
{
    (void)channelId;
    if (linkType != NULL) {
        *linkType = 0;
    }
    return SOFTBUS_OK;
}

int32_t ClientTransProxyOnChannelOpened(
    const char *sessionName, const ChannelInfo *channel, SocketAccessInfo *accessInfo)
{
    (void)sessionName;
    (void)channel;
    (void)accessInfo;
    return SOFTBUS_FUNC_NOT_SUPPORT;
}

int32_t ClientTransProxyOnChannelClosed(int32_t channelId, ShutdownReason reason)
{
    (void)channelId;
    (void)reason;
    return SOFTBUS_FUNC_NOT_SUPPORT;
}

int32_t ClientTransProxyOnChannelOpenFailed(int32_t channelId, int32_t errCode)
{
    (void)channelId;
    (void)errCode;
    return SOFTBUS_FUNC_NOT_SUPPORT;
}

int32_t ClientTransProxyOnDataReceived(int32_t channelId, const void *data, uint32_t len, SessionPktType type)
{
    (void)channelId;
    (void)data;
    (void)len;
    (void)type;
    return SOFTBUS_FUNC_NOT_SUPPORT;
}

void ClientTransProxyCloseChannel(int32_t channelId)
{
    (void)channelId;
    return;
}

int32_t TransProxyChannelSendBytes(int32_t channelId, const void *data, uint32_t len, bool neeedAck)
{
    (void)channelId;
    (void)data;
    (void)len;
    (void)neeedAck;
    return SOFTBUS_FUNC_NOT_SUPPORT;
}

int32_t TransProxyChannelAsyncSendBytes(int32_t channelId, const void *data, uint32_t len, uint32_t dataSeq)
{
    (void)channelId;
    (void)data;
    (void)len;
    (void)dataSeq;
    return SOFTBUS_FUNC_NOT_SUPPORT;
}

int32_t TransProxyChannelSendMessage(int32_t channelId, const void *data, uint32_t len)
{
    (void)channelId;
    (void)data;
    (void)len;
    return SOFTBUS_FUNC_NOT_SUPPORT;
}

int32_t TransProxyChannelAsyncSendMessage(int32_t channelId, const void *data, uint32_t len, uint16_t dataSeq)
{
    (void)channelId;
    (void)data;
    (void)len;
    (void)dataSeq;
    return SOFTBUS_FUNC_NOT_SUPPORT;
}

int32_t ClientTransProxyOnChannelBind(int32_t channelId, int32_t channelType)
{
    (void)channelId;
    (void)channelType;
    return SOFTBUS_FUNC_NOT_SUPPORT;
}

int32_t InitPendingPacket(void)
{
    return SOFTBUS_OK;
}

void DestroyPendingPacket(void)
{
    return;
}

int32_t CreatePendingPacket(uint32_t id, uint64_t seq)
{
    (void)id;
    (void)seq;
    return SOFTBUS_FUNC_NOT_SUPPORT;
}

void DeletePendingPacket(uint32_t id, uint64_t seq)
{
    (void)id;
    (void)seq;
    return;
}

int32_t GetPendingPacketData(uint32_t id, uint64_t seq, uint32_t waitMillis, bool isDelete, TransPendData *data)
{
    (void)id;
    (void)seq;
    (void)waitMillis;
    (void)isDelete;
    (void)data;
    return SOFTBUS_FUNC_NOT_SUPPORT;
}

int32_t SetPendingPacketData(uint32_t id, uint64_t seq, const TransPendData *data)
{
    (void)id;
    (void)seq;
    (void)data;
    return SOFTBUS_FUNC_NOT_SUPPORT;
}

int32_t ClientTransProxyAddChannelInfo(ClientProxyChannelInfo *info)
{
    (void)info;
    return SOFTBUS_FUNC_NOT_SUPPORT;
}

int32_t ClientTransProxyDelChannelInfo(int32_t channelId)
{
    (void)channelId;
    return SOFTBUS_FUNC_NOT_SUPPORT;
}

int32_t ClientTransProxyPackAndSendData(int32_t channelId, const void *data, uint32_t len,
    ProxyChannelInfoDetail *info, SessionPktType pktType)
{
    (void)channelId;
    (void)data;
    (void)len;
    (void)info;
    (void)pktType;
    return SOFTBUS_FUNC_NOT_SUPPORT;
}

int32_t TransProxyAsyncPackAndSendData(int32_t channelId, const void *data, uint32_t len, uint32_t dataSeq,
    SessionPktType pktType)
{
    (void)channelId;
    (void)data;
    (void)len;
    (void)dataSeq;
    (void)pktType;
    return SOFTBUS_FUNC_NOT_SUPPORT;
}

int32_t TransProxyChannelSendFile(int32_t channelId, const char *sFileList[], const char *dFileList[],
    uint32_t fileCnt)
{
    (void)channelId;
    (void)sFileList;
    (void)dFileList;
    (void)fileCnt;
    return SOFTBUS_FUNC_NOT_SUPPORT;
}

int32_t ProcessFileFrameData(int32_t sessionId, int32_t channelId, const char *data, uint32_t len, int32_t type)
{
    (void)sessionId;
    (void)channelId;
    (void)data;
    (void)len;
    (void)type;
    return SOFTBUS_FUNC_NOT_SUPPORT;
}

int32_t TransProxyAsyncPackAndSendMessage(
    int32_t channelId, const void *data, uint32_t len, uint16_t dataSeq, SessionPktType pktType)
{
    (void)channelId;
    (void)data;
    (void)len;
    (void)dataSeq;
    (void)pktType;
    return SOFTBUS_FUNC_NOT_SUPPORT;
}

void ClientDeleteRecvFileList(int32_t sessionId)
{
    (void)sessionId;
    return;
}