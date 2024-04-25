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

SessionConn *GetSessionConnById(int32_t channelId, SessionConn *conn)
{
    return GetTransTcpDirectMessageInterface()->GetSessionConnById(channelId, conn);
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

char *TransTdcPackFastData(const AppInfo *appInfo, uint32_t *outLen)
{
    return GetTransTcpDirectMessageInterface()->TransTdcPackFastData(appInfo, outLen);
}

int32_t UnpackReplyErrCode(const cJSON *msg, int32_t *errCode)
{
    return GetTransTcpDirectMessageInterface()->UnpackReplyErrCode(msg, errCode);
}

int UnpackReply(const cJSON *msg, AppInfo *appInfo, uint16_t *fastDataSize)
{
    return GetTransTcpDirectMessageInterface()->UnpackReply(msg, appInfo, fastDataSize);
}

int SoftbusGetConfig(ConfigType type, unsigned char *val, uint32_t len)
{
    return GetTransTcpDirectMessageInterface()->SoftbusGetConfig(type, val, len);
}

int32_t SetAppInfoById(int32_t channelId, const AppInfo *appInfo)
{
    return GetTransTcpDirectMessageInterface()->SetAppInfoById(channelId, appInfo);
}

char *PackError(int errCode, const char *errDesc)
{
    return GetTransTcpDirectMessageInterface()->PackError(errCode, errDesc);
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

cJSON* cJSON_Parse(const char *value)
{
    return GetTransTcpDirectMessageInterface()->cJSON_Parse(value);
}

static struct WifiDirectManager g_manager = {
    .getLocalIpByRemoteIp = GetLocalIpByRemoteIp,
    .getRemoteUuidByIp = GetRemoteUuidByIp,
};

struct WifiDirectManager* GetWifiDirectManager(void)
{
    return &g_manager;
}
}
}
