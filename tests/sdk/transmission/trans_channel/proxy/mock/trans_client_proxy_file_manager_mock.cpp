/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "trans_client_proxy_file_manager_mock.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
void *g_transClientProxyFileManagerInterface;
TransClientProxyFileManagerInterfaceMock::TransClientProxyFileManagerInterfaceMock()
{
    g_transClientProxyFileManagerInterface = reinterpret_cast<void *>(this);
}

TransClientProxyFileManagerInterfaceMock::~TransClientProxyFileManagerInterfaceMock()
{
    g_transClientProxyFileManagerInterface = nullptr;
}

static TransClientProxyFileManagerInterface *GetTransClientProxyFileManagerInterface()
{
    return reinterpret_cast<TransClientProxyFileManagerInterface *>(g_transClientProxyFileManagerInterface);
}

extern "C" {
SoftBusList *CreateSoftBusList(void)
{
    return GetTransClientProxyFileManagerInterface()->CreateSoftBusList();
}

int32_t RegisterTimeoutCallback(int32_t timerFunId, TimerFunCallback callback)
{
    return GetTransClientProxyFileManagerInterface()->RegisterTimeoutCallback(timerFunId, callback);
}

int32_t UnRegisterTimeoutCallback(int32_t timerFunId)
{
    return GetTransClientProxyFileManagerInterface()->UnRegisterTimeoutCallback(timerFunId);
}

int32_t InitPendingPacket(void)
{
    return GetTransClientProxyFileManagerInterface()->InitPendingPacket();
}

int32_t PendingInit(int32_t type)
{
    return GetTransClientProxyFileManagerInterface()->PendingInit(type);
}

int32_t TransProxyDecryptPacketData(int32_t seq, ProxyDataInfo *dataInfo, const char *sessionKey)
{
    return GetTransClientProxyFileManagerInterface()->TransProxyDecryptPacketData(seq, dataInfo, sessionKey);
}

int32_t GetSupportTlvAndNeedAckById(int32_t channelId, int32_t channelType, bool *supportTlv, bool *needAck)
{
    return GetTransClientProxyFileManagerInterface()->GetSupportTlvAndNeedAckById(
        channelId, channelType, supportTlv, needAck);
}

int32_t TransProxyPackTlvBytes(
    ProxyDataInfo *dataInfo, const char *sessionKey, SessionPktType flag, int32_t seq, DataHeadTlvPacketHead *info)
{
    return GetTransClientProxyFileManagerInterface()->TransProxyPackTlvBytes(
        dataInfo, sessionKey, flag, seq, info);
}

int32_t TransProxyPackBytes(
    int32_t channelId, ProxyDataInfo *dataInfo, const char *sessionKey, SessionPktType flag, int32_t seq)
{
    return GetTransClientProxyFileManagerInterface()->TransProxyPackBytes(channelId, dataInfo, sessionKey, flag, seq);
}

int32_t FileUnLock(int32_t fd)
{
    return GetTransClientProxyFileManagerInterface()->FileUnLock(fd);
}

int32_t SendFileTransResult(int32_t channelId, uint32_t seq, int32_t result, uint32_t side)
{
    return GetTransClientProxyFileManagerInterface()->SendFileTransResult(channelId, seq, result, side);
}

int32_t ServerIpcSendMessage(int32_t channelId, int32_t channelType, const void *data, uint32_t len, int32_t msgType)
{
    return GetTransClientProxyFileManagerInterface()->ServerIpcSendMessage(channelId, channelType, data, len, msgType);
}

int32_t CreatePendingPacket(uint32_t id, uint64_t seq)
{
    return GetTransClientProxyFileManagerInterface()->CreatePendingPacket(id, seq);
}

int32_t ProxyChannelSendFileStream(int32_t channelId, const char *data, uint32_t len, int32_t type)
{
    return GetTransClientProxyFileManagerInterface()->ProxyChannelSendFileStream(channelId, data, len, type);
}

int32_t GetPendingPacketData(uint32_t id, uint64_t seq, uint32_t waitMillis, bool isDelete, TransPendData *data)
{
    return GetTransClientProxyFileManagerInterface()->GetPendingPacketData(id, seq, waitMillis, isDelete, data);
}

int64_t SoftBusPwriteFile(int32_t fd, const void *buf, uint64_t writeBytes, uint64_t offset)
{
    return GetTransClientProxyFileManagerInterface()->SoftBusPwriteFile(fd, buf, writeBytes, offset);
}

int32_t SendFileAckReqAndResData(int32_t channelId, uint32_t startSeq, uint32_t value, int32_t type)
{
    return GetTransClientProxyFileManagerInterface()->SendFileAckReqAndResData(
        channelId, startSeq, value, type);
}

void DeletePendingPacket(uint32_t id, uint64_t seq)
{
    return GetTransClientProxyFileManagerInterface()->DeletePendingPacket(id, seq);
}

int32_t AckResponseDataHandle(const SendListenerInfo *info, const char *data, uint32_t len)
{
    return GetTransClientProxyFileManagerInterface()->AckResponseDataHandle(info, data, len);
}

int32_t ClientGetChannelBusinessTypeByChannelId(int32_t channelId, int32_t *businessType)
{
    return GetTransClientProxyFileManagerInterface()->ClientGetChannelBusinessTypeByChannelId(channelId, businessType);
}
}
}
