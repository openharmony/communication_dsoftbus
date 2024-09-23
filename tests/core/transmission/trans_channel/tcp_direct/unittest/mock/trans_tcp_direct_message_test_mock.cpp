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

#include "trans_tcp_direct_message_test_mock.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
void *g_transTcpDirectMessageInterface;
TransTcpDirectMessageInterfaceMock::TransTcpDirectMessageInterfaceMock()
{
    g_transTcpDirectMessageInterface = reinterpret_cast<void *>(this);
}

TransTcpDirectMessageInterfaceMock::~TransTcpDirectMessageInterfaceMock()
{
    g_transTcpDirectMessageInterface = nullptr;
}

static TransTcpDirectMessageInterface *GetTransTcpDirectMessageInterface()
{
    return reinterpret_cast<TransTcpDirectMessageInterface *>(g_transTcpDirectMessageInterface);
}

extern "C" {
SoftBusList *CreateSoftBusList()
{
    return GetTransTcpDirectMessageInterface()->CreateSoftBusList();
}

int64_t GetAuthIdByChanId(int32_t channelId)
{
    return GetTransTcpDirectMessageInterface()->GetAuthIdByChanId(channelId);
}

int32_t GetAuthHandleByChanId(int32_t channelId, AuthHandle *authHandle)
{
    return GetTransTcpDirectMessageInterface()->GetAuthHandleByChanId(channelId, authHandle);
}

int32_t AuthEncrypt(AuthHandle *authHandle, const uint8_t *inData, uint32_t inLen, uint8_t *outData,
    uint32_t *outLen)
{
    return GetTransTcpDirectMessageInterface()->AuthEncrypt(authHandle, inData, inLen, outData, outLen);
}

ssize_t ConnSendSocketData(int32_t fd, const char *buf, size_t len, int32_t timeout)
{
    return GetTransTcpDirectMessageInterface()->ConnSendSocketData(fd, buf, len, timeout);
}

ssize_t ConnRecvSocketData(int32_t fd, char *buf, size_t len, int32_t timeout)
{
    return GetTransTcpDirectMessageInterface()->ConnRecvSocketData(fd, buf, len, timeout);
}

int32_t TransTdcOnChannelOpenFailed(const char *pkgName, int32_t pid, int32_t channelId, int32_t errCode)
{
    return GetTransTcpDirectMessageInterface()->TransTdcOnChannelOpenFailed(pkgName, pid, channelId, errCode);
}

int32_t TransTdcGetPkgName(const char *sessionName, char *pkgName, uint16_t len)
{
    return GetTransTcpDirectMessageInterface()->TransTdcGetPkgName(sessionName, pkgName, len);
}

int32_t LnnGetLocalStrInfo(InfoKey key, char *info, uint32_t len)
{
    return GetTransTcpDirectMessageInterface()->LnnGetLocalStrInfo(key, info, len);
}

int32_t GetLocalIpByRemoteIp(const char *remoteIp, char *localIp, int32_t localIpSize)
{
    return GetTransTcpDirectMessageInterface()->GetLocalIpByRemoteIp(remoteIp, localIp, localIpSize);
}

int32_t UnpackReplyErrCode(const cJSON *msg, int32_t *errCode)
{
    return GetTransTcpDirectMessageInterface()->UnpackReplyErrCode(msg, errCode);
}

int32_t UnpackReply(const cJSON *msg, AppInfo *appInfo, uint16_t *fastDataSize)
{
    return GetTransTcpDirectMessageInterface()->UnpackReply(msg, appInfo, fastDataSize);
}

int32_t SoftbusGetConfig(ConfigType type, unsigned char *val, uint32_t len)
{
    return GetTransTcpDirectMessageInterface()->SoftbusGetConfig(type, val, len);
}

int32_t SetAppInfoById(int32_t channelId, const AppInfo *appInfo)
{
    return GetTransTcpDirectMessageInterface()->SetAppInfoById(channelId, appInfo);
}

int32_t AuthGetDeviceUuid(int64_t authId, char *uuid, uint16_t size)
{
    return GetTransTcpDirectMessageInterface()->AuthGetDeviceUuid(authId, uuid, size);
}

int32_t UnpackRequest(const cJSON *msg, AppInfo *appInfo)
{
    return GetTransTcpDirectMessageInterface()->UnpackRequest(msg, appInfo);
}

int32_t GetAppInfoById(int32_t channelId, AppInfo *appInfo)
{
    return GetTransTcpDirectMessageInterface()->GetAppInfoById(channelId, appInfo);
}

int32_t GetRemoteUuidByIp(const char *remoteIp, char *localIp, int32_t localIpSize)
{
    return GetTransTcpDirectMessageInterface()->GetRemoteUuidByIp(remoteIp, localIp, localIpSize);
}

int32_t SetAuthHandleByChanId(int32_t channelId, AuthHandle *authHandle)
{
    return GetTransTcpDirectMessageInterface()->SetAuthHandleByChanId(channelId, authHandle);
}

int32_t AuthDecrypt(AuthHandle *authHandle, const uint8_t *inData, uint32_t inLen, uint8_t *outData, uint32_t *outLen)
{
    return GetTransTcpDirectMessageInterface()->AuthDecrypt(authHandle, inData, inLen, outData, outLen);
}

int32_t SoftBusGenerateSessionKey(char *key, uint32_t len)
{
    return GetTransTcpDirectMessageInterface()->SoftBusGenerateSessionKey(key, len);
}

int32_t AuthGetServerSide(int64_t authId, bool *isServer)
{
    return GetTransTcpDirectMessageInterface()->AuthGetServerSide(authId, isServer);
}

int32_t AuthGetConnInfo(AuthHandle authHandle, AuthConnInfo *connInfo)
{
    return GetTransTcpDirectMessageInterface()->AuthGetConnInfo(authHandle, connInfo);
}

char *PackRequest(const AppInfo *appInfo)
{
    return GetTransTcpDirectMessageInterface()->PackRequest(appInfo);
}

int32_t LnnSetLocalStrInfo(InfoKey key, const char *info)
{
    return GetTransTcpDirectMessageInterface()->LnnSetLocalStrInfo(key, info);
}

int32_t LnnSetDLP2pIp(const char *id, IdCategory type, const char *p2pIp)
{
    return GetTransTcpDirectMessageInterface()->LnnSetDLP2pIp(id, type, p2pIp);
}

int32_t LnnGetNetworkIdByUuid(const char *uuid, char *buf, uint32_t len)
{
    return GetTransTcpDirectMessageInterface()->LnnGetNetworkIdByUuid(uuid, buf, len);
}

int32_t TransTdcGetUidAndPid(const char *sessionName, int32_t *uid, int32_t *pid)
{
    return GetTransTcpDirectMessageInterface()->TransTdcGetUidAndPid(sessionName, uid, pid);
}

int32_t TransGetLaneIdByChannelId(int32_t channelId, uint64_t *laneId)
{
    return GetTransTcpDirectMessageInterface()->TransGetLaneIdByChannelId(channelId, laneId);
}

int32_t TransTdcOnChannelOpened(const char *pkgName, int32_t pid, const char *sessionName,
    const ChannelInfo *channel)
{
    return GetTransTcpDirectMessageInterface()->TransTdcOnChannelOpened(pkgName, pid, sessionName, channel);
}

int32_t SetSessionConnStatusById(int32_t channelId, uint32_t status)
{
    return GetTransTcpDirectMessageInterface()->SetSessionConnStatusById(channelId, status);
}

int32_t TransTdcOnChannelBind(const char *pkgName, int32_t pid, int32_t channelId)
{
    return GetTransTcpDirectMessageInterface()->TransTdcOnChannelBind(pkgName, pid, channelId);
}

int32_t SoftBusEncryptData(AesGcmCipherKey *cipherKey, const unsigned char *input, uint32_t inLen,
    unsigned char *encryptData, uint32_t *encryptLen)
{
    return GetTransTcpDirectMessageInterface()->SoftBusEncryptData(cipherKey, input, inLen, encryptData, encryptLen);
}

int32_t SetIpTos(int32_t fd, uint32_t tos)
{
    return GetTransTcpDirectMessageInterface()->SetIpTos(fd, tos);
}

int32_t TransTdcOnMsgReceived(const char *pkgName, int32_t pid, int32_t channelId, TransReceiveData *receiveData)
{
    return GetTransTcpDirectMessageInterface()->TransTdcOnMsgReceived(pkgName, pid, channelId, receiveData);
}

int32_t LnnGetRemoteNodeInfoById(const char *id, IdCategory type, NodeInfo *info)
{
    return GetTransTcpDirectMessageInterface()->LnnGetRemoteNodeInfoById(id, type, info);
}

int32_t TransCheckServerAccessControl(uint32_t callingTokenId)
{
    return GetTransTcpDirectMessageInterface()->TransCheckServerAccessControl(callingTokenId);
}

int32_t TransTdcOnChannelClosed(const char *pkgName, int32_t pid, int32_t channelId)
{
    return GetTransTcpDirectMessageInterface()->TransTdcOnChannelClosed(pkgName, pid, channelId);
}
}
}
