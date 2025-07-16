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

#ifndef SOFTBUS_PROXYCHANNEL_MANAGER_PAGING_TEST_H
#define SOFTBUS_PROXYCHANNEL_MANAGER_PAGING_TEST_H

#include <gmock/gmock.h>

#include "auth_apply_key_struct.h"
#include "cJSON.h"
#include "softbus_app_info.h"
#include "softbus_proxychannel_message_struct.h"


namespace OHOS {
class SoftbusProxychannelManagerPagingInterface {
public:
    SoftbusProxychannelManagerPagingInterface() {};
    virtual ~SoftbusProxychannelManagerPagingInterface() {};
    virtual void TransProxyPagingHandshakeMsgToLoop(int32_t channelId, uint8_t *authKey, uint32_t keyLen) = 0;
    virtual int32_t ConvertBytesToHexString(char *outBuf, uint32_t outBufLen, const unsigned char *inBuf,
        uint32_t inLen) = 0;
    virtual int32_t AuthGenApplyKey(
        const RequestBusinessInfo *info, uint32_t requestId, uint32_t connId, const GenApplyKeyCallback *genCb) = 0;
    virtual cJSON *cJSON_ParseWithLength(const char *value, size_t buffer_length) = 0;
    virtual int32_t TransPagingAckHandshake(ProxyChannelInfo *chan, int32_t retCode) = 0;
    virtual int32_t OnProxyChannelBind(int32_t channelId, const AppInfo *appInfo) = 0;
    virtual int32_t OnProxyChannelClosed(int32_t channelId, const AppInfo *appInfo) = 0;
    virtual void ReleaseProxyChannelId(int32_t channelId) = 0;
};

class SoftbusProxychannelManagerPagingInterfaceMock : public SoftbusProxychannelManagerPagingInterface {
public:
    SoftbusProxychannelManagerPagingInterfaceMock();
    ~SoftbusProxychannelManagerPagingInterfaceMock() override;
    MOCK_METHOD3(TransProxyPagingHandshakeMsgToLoop, void (int32_t channelId, uint8_t *authKey, uint32_t keyLen));
    MOCK_METHOD4(ConvertBytesToHexString, int32_t (char *outBuf, uint32_t outBufLen, const unsigned char *inBuf,
        uint32_t inLen));
    MOCK_METHOD4(AuthGenApplyKey, int32_t (
        const RequestBusinessInfo *info, uint32_t requestId, uint32_t connId, const GenApplyKeyCallback *genCb));
    MOCK_METHOD2(cJSON_ParseWithLength, cJSON* (const char *value, size_t buffer_length));
    MOCK_METHOD2(TransPagingAckHandshake, int32_t (ProxyChannelInfo *chan, int32_t retCode));
    MOCK_METHOD2(OnProxyChannelBind, int32_t (int32_t channelId, const AppInfo *appInfo));
    MOCK_METHOD2(OnProxyChannelClosed, int32_t (int32_t channelId, const AppInfo *appInfo));
    MOCK_METHOD1(ReleaseProxyChannelId, void (int32_t channelId));
};
} // namespace OHOS
#endif // SOFTBUS_PROXYCHANNEL_MANAGER_PAGING_TEST_H
