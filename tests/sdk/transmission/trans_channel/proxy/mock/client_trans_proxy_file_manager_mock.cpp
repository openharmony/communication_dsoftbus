/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "client_trans_proxy_file_manager_mock.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
void *g_clientTransProxyFileManagerInterface;
ClientTransProxyFileManagerInterfaceMock::ClientTransProxyFileManagerInterfaceMock()
{
    g_clientTransProxyFileManagerInterface = reinterpret_cast<void *>(this);
}

ClientTransProxyFileManagerInterfaceMock::~ClientTransProxyFileManagerInterfaceMock()
{
    g_clientTransProxyFileManagerInterface = nullptr;
}

static ClientTransProxyFileManagerInterface *GetClientTransProxyFileManagerInterface()
{
    return reinterpret_cast<ClientTransProxyFileManagerInterface *>(g_clientTransProxyFileManagerInterface);
}

extern "C" {
uint32_t SoftBusLtoHl(uint32_t value)
{
    return GetClientTransProxyFileManagerInterface()->SoftBusLtoHl(value);
}

uint32_t SoftBusHtoLl(uint64_t value)
{
    return GetClientTransProxyFileManagerInterface()->SoftBusHtoLl(value);
}

uint64_t SoftBusLtoHll(uint64_t value)
{
    return GetClientTransProxyFileManagerInterface()->SoftBusLtoHll(value);
}

uint64_t SoftBusHtoLll(uint64_t value)
{
    return GetClientTransProxyFileManagerInterface()->SoftBusHtoLll(value);
}

int32_t SoftBusGetFileSize(const char *fileName, uint64_t *fileSize)
{
    return GetClientTransProxyFileManagerInterface()->SoftBusGetFileSize(fileName, fileSize);
}

int32_t GetPendingPacketData(uint32_t id, uint64_t seq, uint32_t waitMillis, bool isDelete, TransPendData *data)
{
    return GetClientTransProxyFileManagerInterface()->GetPendingPacketData(id, seq, waitMillis, isDelete, data);
}

int32_t CreatePendingPacket(uint32_t id, uint64_t seq)
{
    return GetClientTransProxyFileManagerInterface()->CreatePendingPacket(id, seq);
}

int32_t FrameIndexToType(uint64_t index, uint64_t frameNumber)
{
    return GetClientTransProxyFileManagerInterface()->FrameIndexToType(index, frameNumber);
}

int64_t SoftBusPreadFile(int32_t fd, void *buf, uint64_t readBytes, uint64_t offset)
{
    return GetClientTransProxyFileManagerInterface()->SoftBusPreadFile(fd, buf, readBytes, offset);
}

bool CheckDestFilePathValid(const char *destFile)
{
    return GetClientTransProxyFileManagerInterface()->CheckDestFilePathValid(destFile);
}

int32_t GetAndCheckRealPath(const char *filePath, char *absPath)
{
    return GetClientTransProxyFileManagerInterface()->GetAndCheckRealPath(filePath, absPath);
}

int32_t SoftBusOpenFile(const char *fileName, int32_t flags)
{
    return GetClientTransProxyFileManagerInterface()->SoftBusOpenFile(fileName, flags);
}

int32_t TryFileLock(int32_t fd, int32_t type, int32_t retryTimes)
{
    return GetClientTransProxyFileManagerInterface()->TryFileLock(fd, type, retryTimes);
}

int32_t ClientGetSessionIdByChannelId(int32_t channelId, int32_t channelType, int32_t *sessionId, bool isClosing)
{
    return GetClientTransProxyFileManagerInterface()->ClientGetSessionIdByChannelId(
        channelId, channelType, sessionId, isClosing);
}

int32_t ClientGetSessionDataById(int32_t sessionId, char *data, uint16_t len, SessionKey key)
{
    return GetClientTransProxyFileManagerInterface()->ClientGetSessionDataById(sessionId, data, len, key);
}

int32_t ClientGetFileConfigInfoById(int32_t sessionId, int32_t *fileEncrypt, int32_t *algorithm, int32_t *crc)
{
    return GetClientTransProxyFileManagerInterface()->ClientGetFileConfigInfoById(
        sessionId, fileEncrypt, algorithm, crc);
}

int32_t TransGetFileListener(const char *sessionName, FileListener *fileListener)
{
    return GetClientTransProxyFileManagerInterface()->TransGetFileListener(sessionName, fileListener);
}

int32_t InitPendingPacket(void)
{
    return GetClientTransProxyFileManagerInterface()->InitPendingPacket();
}

int32_t FileUnLock(int32_t fd)
{
    return GetClientTransProxyFileManagerInterface()->FileUnLock(fd);
}

int32_t SendFileTransResult(int32_t channelId, uint32_t seq, int32_t result, uint32_t side)
{
    return GetClientTransProxyFileManagerInterface()->SendFileTransResult(channelId, seq, result, side);
}

int32_t SendFileAckReqAndResData(int32_t channelId, uint32_t startSeq, uint32_t value, int32_t type)
{
    return GetClientTransProxyFileManagerInterface()->SendFileAckReqAndResData(
        channelId, startSeq, value, type);
}

void DeletePendingPacket(uint32_t id, uint64_t seq)
{
    return GetClientTransProxyFileManagerInterface()->DeletePendingPacket(id, seq);
}

int32_t AckResponseDataHandle(const SendListenerInfo *info, const char *data, uint32_t len)
{
    return GetClientTransProxyFileManagerInterface()->AckResponseDataHandle(info, data, len);
}

int32_t ProxyChannelSendFileStream(int32_t channelId, const char *data, uint32_t len, int32_t type)
{
    return GetClientTransProxyFileManagerInterface()->ProxyChannelSendFileStream(channelId, data, len, type);
}

int64_t PackReadFileData(FileFrame *fileFrame, uint64_t readLength, uint64_t fileOffset, SendListenerInfo *info)
{
    return GetClientTransProxyFileManagerInterface()->PackReadFileData(fileFrame, readLength, fileOffset, info);
}

int32_t FileListToBuffer(const char **destFile, uint32_t fileCnt, FileListBuffer *outbufferInfo)
{
    return GetClientTransProxyFileManagerInterface()->FileListToBuffer(destFile, fileCnt, outbufferInfo);
}

uint32_t SoftBusNtoHl(uint32_t netlong)
{
    return GetClientTransProxyFileManagerInterface()->SoftBusNtoHl(netlong);
}

int32_t SetPendingPacket(int32_t channelId, int32_t seqNum, int32_t type)
{
    return GetClientTransProxyFileManagerInterface()->SetPendingPacket(channelId, seqNum, type);
}
}
}
