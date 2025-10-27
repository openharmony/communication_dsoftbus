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

#ifndef SOFTBUS_PROXYCHANNEL_MANAGER_MOCK_TEST_H
#define SOFTBUS_PROXYCHANNEL_MANAGER_MOCK_TEST_H

#include <gmock/gmock.h>

#include "bus_center_info_key.h"
#include "softbus_conn_interface_struct.h"
#include "softbus_feature_config.h"
#include "softbus_proxychannel_control.h"
#include "softbus_proxychannel_listener.h"
#include "softbus_proxychannel_manager.h"
#include "softbus_proxychannel_message.h"
#include "softbus_proxychannel_transceiver.h"
#include "softbus_utils.h"
#include "trans_auth_negotiation.h"
#include "trans_uk_manager.h"

class SoftbusTransProxyChannelManagerInterface {
public:
    virtual int32_t SoftbusGetConfig(ConfigType type, unsigned char *val, uint32_t len) = 0;
    virtual int32_t TransProxyUnPackHandshakeErrMsg(const char *msg, int32_t *errCode, int32_t len) = 0;
    virtual int32_t TransProxyUnpackHandshakeAckMsg(
        const char *msg, ProxyChannelInfo *chanInfo, int32_t len, uint16_t *fastDataSize) = 0;
    virtual int32_t TransProxyGetPkgName(const char *sessionName, char *pkgName, uint16_t len) = 0;
    virtual int32_t TransProxyGetUidAndPidBySessionName(const char *sessionName, int32_t *uid, int32_t *pid) = 0;
    virtual int32_t LnnGetLocalStrInfo(InfoKey key, char *info, uint32_t len) = 0;
    virtual int32_t TransProxyUnpackHandshakeMsg(const char *msg, ProxyChannelInfo *chan, int32_t len) = 0;
    virtual bool CheckSessionNameValidOnAuthChannel(const char *sessionName) = 0;
    virtual int32_t ConnGetConnectionInfo(uint32_t connectionId, ConnectionInfo *info) = 0;
    virtual int32_t TransCheckServerAccessControl(uint64_t callingTokenId) = 0;
    virtual int32_t ConnGetTypeByConnectionId(uint32_t connectionId, ConnectType *type) = 0;
    virtual int32_t TransProxyAckHandshake(uint32_t connId, ProxyChannelInfo *chan, int32_t retCode) = 0;
    virtual int32_t OnProxyChannelBind(int32_t channelId, const AppInfo *appInfo) = 0;
    virtual int32_t TransUkRequestGetRequestInfoByRequestId(uint32_t requestId, UkRequestNode *ukRequest) = 0;
    virtual int32_t GetLocalAccountUidByUserId(char *id, uint32_t idLen, uint32_t *len, int32_t userId) = 0;
    virtual int32_t GetAuthConnInfoByConnId(uint32_t connectionId, AuthConnInfo *authConnInfo) = 0;
    virtual int32_t TransReNegotiateSessionKey(const AuthConnInfo *authConnInfo, int32_t channelId) = 0;
    virtual int32_t TransProxyUnpackIdentity(const char *msg, char *identity, uint32_t identitySize, int32_t len) = 0;
    virtual int32_t TransProxyTransInit(void) = 0;
    virtual int32_t RegisterTimeoutCallback(int32_t timerFunId, TimerFunCallback callback) = 0;
    virtual int32_t TransGetPidAndPkgName(
        const char *sessionName, int32_t uid, int32_t *pid, char *pkgName, uint32_t len) = 0;
    virtual int32_t OnProxyChannelOpened(int32_t channelId, const AppInfo *appInfo, unsigned char isServer) = 0;
    virtual void TransCheckChannelOpenRemoveFromLooper(int32_t channelId) = 0;
    virtual int32_t ConnUpdateConnection(uint32_t connectionId, UpdateOption *option) = 0;
};

class SoftbusTransProxyChannelManagerMock : public SoftbusTransProxyChannelManagerInterface {
public:
    static SoftbusTransProxyChannelManagerMock &GetMockObj(void)
    {
        return *gmock_;
    }
    SoftbusTransProxyChannelManagerMock();
    ~SoftbusTransProxyChannelManagerMock();
    MOCK_METHOD(int32_t, SoftbusGetConfig, (ConfigType type, unsigned char *val, uint32_t len), (override));
    MOCK_METHOD(int32_t, TransProxyUnPackHandshakeErrMsg, (const char *msg, int32_t *errCode, int32_t len), (override));
    MOCK_METHOD(int32_t, TransProxyUnpackHandshakeAckMsg,
        (const char *msg, ProxyChannelInfo *chanInfo, int32_t len, uint16_t *fastDataSize), (override));
    MOCK_METHOD(int32_t, TransProxyGetPkgName, (const char *sessionName, char *pkgName, uint16_t len), (override));
    MOCK_METHOD(int32_t, TransProxyGetUidAndPidBySessionName, (const char *sessionName, int32_t *uid, int32_t *pid),
        (override));
    MOCK_METHOD(int32_t, LnnGetLocalStrInfo, (InfoKey key, char *info, uint32_t len), (override));
    MOCK_METHOD(
        int32_t, TransProxyUnpackHandshakeMsg, (const char *msg, ProxyChannelInfo *chan, int32_t len), (override));
    MOCK_METHOD(bool, CheckSessionNameValidOnAuthChannel, (const char *sessionName), (override));
    MOCK_METHOD(int32_t, ConnGetConnectionInfo, (uint32_t connectionId, ConnectionInfo *info), (override));
    MOCK_METHOD(int32_t, TransCheckServerAccessControl, (uint64_t callingTokenId), (override));
    MOCK_METHOD(int32_t, ConnGetTypeByConnectionId, (uint32_t connectionId, ConnectType *type), (override));
    MOCK_METHOD(int32_t, TransProxyAckHandshake,
        (uint32_t connId, ProxyChannelInfo *chan, int32_t retCode), (override));

    MOCK_METHOD(int32_t, OnProxyChannelBind, (int32_t channelId, const AppInfo *appInfo), (override));

    MOCK_METHOD(int32_t, TransUkRequestGetRequestInfoByRequestId,
        (uint32_t requestId, UkRequestNode *ukRequest), (override));

    MOCK_METHOD(int32_t, GetLocalAccountUidByUserId,
        (char *id, uint32_t idLen, uint32_t *len, int32_t userId), (override));

    MOCK_METHOD(int32_t, GetAuthConnInfoByConnId, (uint32_t connectionId, AuthConnInfo *authConnInfo), (override));

    MOCK_METHOD(int32_t, TransReNegotiateSessionKey, (const AuthConnInfo *authConnInfo, int32_t channelId), (override));

    MOCK_METHOD(int32_t, TransProxyUnpackIdentity,
        (const char *msg, char *identity, uint32_t identitySize, int32_t len), (override));

    MOCK_METHOD(int32_t, TransProxyTransInit, (), (override));

    MOCK_METHOD(int32_t, RegisterTimeoutCallback, (int32_t timerFunId, TimerFunCallback callback), (override));

    MOCK_METHOD(int32_t, TransGetPidAndPkgName,
        (const char *sessionName, int32_t uid, int32_t *pid, char *pkgName, uint32_t len), (override));

    MOCK_METHOD(int32_t, OnProxyChannelOpened, (int32_t channelId, const AppInfo *appInfo, unsigned char isServer));

    MOCK_METHOD(void, TransCheckChannelOpenRemoveFromLooper, (int32_t channelId));

    MOCK_METHOD(int32_t, ConnUpdateConnection, (uint32_t connectionId, UpdateOption *option));

private:
    static SoftbusTransProxyChannelManagerMock *gmock_;
};

#endif // SOFTBUS_PROXYCHANNEL_MANAGER_MOCK_TEST_H
