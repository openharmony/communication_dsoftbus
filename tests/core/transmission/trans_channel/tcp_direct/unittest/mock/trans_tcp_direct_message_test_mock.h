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

#ifndef TRANS_TCP_DIRECT_MESSAGE_TEST_MOCK_H
#define TRANS_TCP_DIRECT_MESSAGE_TEST_MOCK_H

#include <gmock/gmock.h>

#include "auth_interface.h"
#include "bus_center_manager.h"
#include "softbus_feature_config.h"
#include "softbus_message_open_channel.h"
#include "softbus_socket.h"
#include "softbus_utils.h"
#include "trans_tcp_direct_callback.h"
#include "trans_tcp_direct_sessionconn.h"
#include "wifi_direct_manager.h"

namespace OHOS {
class TransTcpDirectMessageInterface {
public:
    TransTcpDirectMessageInterface() {};
    virtual ~TransTcpDirectMessageInterface() {};
    virtual SoftBusList *CreateSoftBusList() = 0;
    virtual int64_t GetAuthIdByChanId(int32_t channelId) = 0;
    virtual int32_t GetAuthHandleByChanId(int32_t channelId, AuthHandle *authHandle) = 0;
    virtual int32_t AuthEncrypt(AuthHandle *authHandle, const uint8_t *inData, uint32_t inLen, uint8_t *outData,
        uint32_t *outLen) = 0;
    virtual SessionConn *GetSessionConnById(int32_t channelId, SessionConn *conn) = 0;
    virtual ssize_t ConnSendSocketData(int32_t fd, const char *buf, size_t len, int32_t timeout) = 0;
    virtual ssize_t ConnRecvSocketData(int32_t fd, char *buf, size_t len, int32_t timeout) = 0;
    virtual int32_t TransTdcOnChannelOpenFailed(const char *pkgName,
        int32_t pid, int32_t channelId, int32_t errCode) = 0;
    virtual int32_t TransTdcGetPkgName(const char *sessionName, char *pkgName, uint16_t len) = 0;
    virtual int32_t LnnGetLocalStrInfo(InfoKey key, char *info, uint32_t len) = 0;
    virtual int32_t GetLocalIpByRemoteIp(const char *remoteIp, char *localIp, int32_t localIpSize) = 0;
    virtual char *TransTdcPackFastData(const AppInfo *appInfo, uint32_t *outLen) = 0;
    virtual int32_t UnpackReplyErrCode(const cJSON *msg, int32_t *errCode) = 0;
    virtual int UnpackReply(const cJSON *msg, AppInfo *appInfo, uint16_t *fastDataSize) = 0;
    virtual int SoftbusGetConfig(ConfigType type, unsigned char *val, uint32_t len) = 0;
    virtual int32_t SetAppInfoById(int32_t channelId, const AppInfo *appInfo) = 0;
    virtual char *PackError(int errCode, const char *errDesc) = 0;
    virtual int32_t AuthGetDeviceUuid(int64_t authId, char *uuid, uint16_t size) = 0;
    virtual int32_t UnpackRequest(const cJSON *msg, AppInfo *appInfo) = 0;
    virtual int32_t GetAppInfoById(int32_t channelId, AppInfo *appInfo) = 0;
    virtual int32_t GetRemoteUuidByIp(const char *remoteIp, char *localIp, int32_t localIpSize) = 0;
    virtual cJSON* cJSON_Parse(const char *value) = 0;
    virtual int32_t SetAuthHandleByChanId(int32_t channelId, AuthHandle *authHandle) = 0;
    virtual int32_t AuthDecrypt(AuthHandle *authHandle, const uint8_t *inData,
        uint32_t inLen, uint8_t *outData, uint32_t *outLen) = 0;
};

class TransTcpDirectMessageInterfaceMock : public TransTcpDirectMessageInterface {
public:
    TransTcpDirectMessageInterfaceMock();
    ~TransTcpDirectMessageInterfaceMock() override;
    MOCK_METHOD0(CreateSoftBusList, SoftBusList * ());
    MOCK_METHOD1(GetAuthIdByChanId, int64_t (int32_t channelId));
    MOCK_METHOD2(GetAuthHandleByChanId, int32_t (int32_t channelId, AuthHandle *authHandle));
    MOCK_METHOD5(AuthEncrypt, int32_t (AuthHandle *authHandle, const uint8_t *inData, uint32_t inLen, uint8_t *outData,
        uint32_t *outLen));
    MOCK_METHOD2(GetSessionConnById, SessionConn * (int32_t channelId, SessionConn *conn));
    MOCK_METHOD4(ConnSendSocketData, ssize_t (int32_t fd, const char *buf, size_t len, int32_t timeout));
    MOCK_METHOD4(ConnRecvSocketData, ssize_t (int32_t fd, char *buf, size_t len, int32_t timeout));
    MOCK_METHOD4(TransTdcOnChannelOpenFailed, int32_t (const char *pkgName,
        int32_t pid, int32_t channelId, int32_t errCode));
    MOCK_METHOD3(TransTdcGetPkgName, int32_t (const char *sessionName, char *pkgName, uint16_t len));
    MOCK_METHOD3(LnnGetLocalStrInfo, int32_t (InfoKey key, char *info, uint32_t len));
    MOCK_METHOD3(GetLocalIpByRemoteIp, int32_t (const char *remoteIp, char *localIp, int32_t localIpSize));
    MOCK_METHOD2(TransTdcPackFastData, char * (const AppInfo *appInfo, uint32_t *outLen));
    MOCK_METHOD2(UnpackReplyErrCode, int32_t (const cJSON *msg, int32_t *errCode));
    MOCK_METHOD3(UnpackReply, int (const cJSON *msg, AppInfo *appInfo, uint16_t *fastDataSize));
    MOCK_METHOD3(SoftbusGetConfig, int (ConfigType type, unsigned char *val, uint32_t len));
    MOCK_METHOD2(SetAppInfoById, int32_t (int32_t channelId, const AppInfo *appInfo));
    MOCK_METHOD2(PackError, char * (int errCode, const char *errDesc));
    MOCK_METHOD3(AuthGetDeviceUuid, int32_t (int64_t authId, char *uuid, uint16_t size));
    MOCK_METHOD2(UnpackRequest, int32_t (const cJSON *msg, AppInfo *appInfo));
    MOCK_METHOD2(GetAppInfoById, int32_t (int32_t channelId, AppInfo *appInfo));
    MOCK_METHOD3(GetRemoteUuidByIp, int32_t (const char *remoteIp, char *localIp, int32_t localIpSize));
    MOCK_METHOD1(cJSON_Parse, cJSON * (const char *value));
    MOCK_METHOD2(SetAuthHandleByChanId, int32_t (int32_t channelId, AuthHandle *authHandle));
    MOCK_METHOD5(AuthDecrypt, int32_t (AuthHandle *authHandle, const uint8_t *inData,
        uint32_t inLen, uint8_t *outData, uint32_t *outLen));
};
} // namespace OHOS
#endif // TRANS_TCP_DIRECT_MESSAGE_TEST_MOCK_H
