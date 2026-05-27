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

#include "softbus_proxychannel_control_paging_test_mock.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
void *g_softbusProxychannelControlPagingInterface;
SoftbusProxychannelControlPagingInterfaceMock::SoftbusProxychannelControlPagingInterfaceMock()
{
    g_softbusProxychannelControlPagingInterface = reinterpret_cast<void *>(this);
}

SoftbusProxychannelControlPagingInterfaceMock::~SoftbusProxychannelControlPagingInterfaceMock()
{
    g_softbusProxychannelControlPagingInterface = nullptr;
}

static SoftbusProxychannelControlPagingInterface *GetSoftbusProxychannelControlPagingInterface()
{
    return reinterpret_cast<SoftbusProxychannelControlPagingInterface *>(g_softbusProxychannelControlPagingInterface);
}

extern "C" {
int32_t TransProxyGetSendMsgChanInfo(int32_t channelId, ProxyChannelInfo *chanInfo)
{
    return GetSoftbusProxychannelControlPagingInterface()->TransProxyGetSendMsgChanInfo(channelId, chanInfo);
}

char *TransPagingPackHandShakeMsg(ProxyChannelInfo *info)
{
    return GetSoftbusProxychannelControlPagingInterface()->TransPagingPackHandShakeMsg(info);
}

int32_t TransPagingPackMessage(PagingProxyMessage *msg, ProxyDataInfo *dataInfo, ProxyChannelInfo *chan, bool needHash)
{
    return GetSoftbusProxychannelControlPagingInterface()->TransPagingPackMessage(msg, dataInfo, chan, needHash);
}

int32_t TransProxyTransSendMsg(uint32_t connectionId, uint8_t *buf, uint32_t len, int32_t priority, int32_t pid)
{
    return GetSoftbusProxychannelControlPagingInterface()->TransProxyTransSendMsg(
        connectionId, buf, len, priority, pid);
}

int32_t ConvertBytesToHexString(
    char *outBuf, uint32_t outBufLen, const unsigned char *inBuf, uint32_t inLen)
{
    return GetSoftbusProxychannelControlPagingInterface()->ConvertBytesToHexString(outBuf, outBufLen, inBuf, inLen);
}

int32_t AuthFindApplyKey(
    const RequestBusinessInfo *info, uint8_t *applyKey, char *accountHash, uint32_t accountHashLen)
{
    return GetSoftbusProxychannelControlPagingInterface()->AuthFindApplyKey(
        info, applyKey, accountHash, accountHashLen);
}

char *TransPagingPackHandshakeAckMsg(ProxyChannelInfo *chan)
{
    return GetSoftbusProxychannelControlPagingInterface()->TransPagingPackHandshakeAckMsg(chan);
}

int32_t TransProxyPackMessage(ProxyMessageHead *msg, AuthHandle authHandle, ProxyDataInfo *dataInfo)
{
    return GetSoftbusProxychannelControlPagingInterface()->TransProxyPackMessage(msg, authHandle, dataInfo);
}

char *TransProxyPackHandshakeMsg(ProxyChannelInfo *info)
{
    return GetSoftbusProxychannelControlPagingInterface()->TransProxyPackHandshakeMsg(info);
}

char *TransProxyPackHandshakeErrMsg(int32_t errCode)
{
    return GetSoftbusProxychannelControlPagingInterface()->TransProxyPackHandshakeErrMsg(errCode);
}

char *TransProxyPackHandshakeAckMsg(ProxyChannelInfo *chan)
{
    return GetSoftbusProxychannelControlPagingInterface()->TransProxyPackHandshakeAckMsg(chan);
}

char *TransProxyPackIdentity(const char *identity)
{
    return GetSoftbusProxychannelControlPagingInterface()->TransProxyPackIdentity(identity);
}

char *TransProxyPagingPackChannelId(int16_t channelId)
{
    return GetSoftbusProxychannelControlPagingInterface()->TransProxyPagingPackChannelId(channelId);
}

char *TransPagingPackHandshakeErrMsg(int32_t errCode, int32_t channelId)
{
    return GetSoftbusProxychannelControlPagingInterface()->TransPagingPackHandshakeErrMsg(errCode, channelId);
}

void AuthGetLatestIdByUuid(const char *uuid, AuthLinkType type, bool isMeta, AuthHandle *authHandle)
{
    GetSoftbusProxychannelControlPagingInterface()->AuthGetLatestIdByUuid(uuid, type, isMeta, authHandle);
}

int32_t TransProxySetAuthHandleByChanId(int32_t channelId, AuthHandle authHandle)
{
    return GetSoftbusProxychannelControlPagingInterface()->TransProxySetAuthHandleByChanId(channelId, authHandle);
}

int32_t AuthGetConnInfo(AuthHandle authHandle, AuthConnInfo *connInfo)
{
    return GetSoftbusProxychannelControlPagingInterface()->AuthGetConnInfo(authHandle, connInfo);
}

int32_t AuthGetServerSide(int64_t authId, bool *isServer)
{
    return GetSoftbusProxychannelControlPagingInterface()->AuthGetServerSide(authId, isServer);
}

int32_t SoftBusEncryptData(AesGcmCipherKey *cipherKey, const unsigned char *input, uint32_t inLen,
    unsigned char *encryptData, uint32_t *encryptLen)
{
    return GetSoftbusProxychannelControlPagingInterface()->SoftBusEncryptData(
        cipherKey, input, inLen, encryptData, encryptLen);
}

int32_t ConnGetConnectionInfo(uint32_t connectionId, ConnectionInfo *info)
{
    return GetSoftbusProxychannelControlPagingInterface()->ConnGetConnectionInfo(connectionId, info);
}

int32_t ConnDisconnectDeviceAllConn(const ConnectOption *option)
{
    return GetSoftbusProxychannelControlPagingInterface()->ConnDisconnectDeviceAllConn(option);
}
}
}