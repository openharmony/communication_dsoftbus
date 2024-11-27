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
#include "softbus_feature_config.h"
#include "softbus_proxychannel_message.h"

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

private:
    static SoftbusTransProxyChannelManagerMock *gmock_;
};

#endif // SOFTBUS_PROXYCHANNEL_MANAGER_MOCK_TEST_H
