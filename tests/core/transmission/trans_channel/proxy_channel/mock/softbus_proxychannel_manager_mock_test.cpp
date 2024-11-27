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

#include "softbus_proxychannel_manager_mock_test.h"

SoftbusTransProxyChannelManagerMock *SoftbusTransProxyChannelManagerMock::gmock_;

SoftbusTransProxyChannelManagerMock::SoftbusTransProxyChannelManagerMock()
{
    gmock_ = this;
}

SoftbusTransProxyChannelManagerMock::~SoftbusTransProxyChannelManagerMock()
{
    gmock_ = nullptr;
}

#ifdef __cplusplus
extern "C" {
#endif

int32_t SoftbusGetConfig(ConfigType type, unsigned char *val, uint32_t len)
{
    std::cout << "SoftbusGetConfig calling enter" << std::endl;
    return SoftbusTransProxyChannelManagerMock::GetMockObj().SoftbusGetConfig(type, val, len);
}

int32_t TransProxyUnPackHandshakeErrMsg(const char *msg, int32_t *errCode, int32_t len)
{
    std::cout << "TransProxyUnPackHandshakeErrMsg calling enter" << std::endl;
    return SoftbusTransProxyChannelManagerMock::GetMockObj().TransProxyUnPackHandshakeErrMsg(msg, errCode, len);
}

int32_t TransProxyUnpackHandshakeAckMsg(
    const char *msg, ProxyChannelInfo *chanInfo, int32_t len, uint16_t *fastDataSize)
{
    std::cout << "TransProxyUnpackHandshakeAckMsg calling enter" << std::endl;
    return SoftbusTransProxyChannelManagerMock::GetMockObj().TransProxyUnpackHandshakeAckMsg(
        msg, chanInfo, len, fastDataSize);
}

int32_t TransProxyGetPkgName(const char *sessionName, char *pkgName, uint16_t len)
{
    std::cout << "TransProxyGetPkgName calling enter" << std::endl;
    return SoftbusTransProxyChannelManagerMock::GetMockObj().TransProxyGetPkgName(sessionName, pkgName, len);
}

int32_t TransProxyGetUidAndPidBySessionName(const char *sessionName, int32_t *uid, int32_t *pid)
{
    std::cout << "TransProxyGetUidAndPidBySessionName calling enter" << std::endl;
    return SoftbusTransProxyChannelManagerMock::GetMockObj().TransProxyGetUidAndPidBySessionName(sessionName, uid, pid);
}

int32_t LnnGetLocalStrInfo(InfoKey key, char *info, uint32_t len)
{
    std::cout << "LnnGetLocalStrInfo calling enter" << std::endl;
    return SoftbusTransProxyChannelManagerMock::GetMockObj().LnnGetLocalStrInfo(key, info, len);
}

int32_t TransProxyUnpackHandshakeMsg(const char *msg, ProxyChannelInfo *chan, int32_t len)
{
    std::cout << "TransProxyUnpackHandshakeMsg calling enter" << std::endl;
    return SoftbusTransProxyChannelManagerMock::GetMockObj().TransProxyUnpackHandshakeMsg(msg, chan, len);
}

bool CheckSessionNameValidOnAuthChannel(const char *sessionName)
{
    std::cout << "CheckSessionNameValidOnAuthChannel calling enter" << std::endl;
    return SoftbusTransProxyChannelManagerMock::GetMockObj().CheckSessionNameValidOnAuthChannel(sessionName);
}

int32_t ConnGetConnectionInfo(uint32_t connectionId, ConnectionInfo *info)
{
    std::cout << "ConnGetConnectionInfo calling enter" << std::endl;
    return SoftbusTransProxyChannelManagerMock::GetMockObj().ConnGetConnectionInfo(connectionId, info);
}

int32_t TransCheckServerAccessControl(uint64_t callingTokenId)
{
    std::cout << "TransCheckServerAccessControl calling enter" << std::endl;
    return SoftbusTransProxyChannelManagerMock::GetMockObj().TransCheckServerAccessControl(callingTokenId);
}

int32_t ConnGetTypeByConnectionId(uint32_t connectionId, ConnectType *type)
{
    std::cout << "ConnGetTypeByConnectionId calling enter" << std::endl;
    return SoftbusTransProxyChannelManagerMock::GetMockObj().ConnGetTypeByConnectionId(connectionId, type);
}

#ifdef __cplusplus
}
#endif
