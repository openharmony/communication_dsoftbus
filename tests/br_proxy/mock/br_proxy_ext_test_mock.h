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

#ifndef BR_PROXY_EXT_TEST_MOCK_H
#define BR_PROXY_EXT_TEST_MOCK_H

#include <gmock/gmock.h>
#include "br_proxy.h"
#include "trans_client_proxy.h"

namespace OHOS {
class BrProxyExtInterface {
public:
    BrProxyExtInterface() {};
    virtual ~BrProxyExtInterface() {};
    virtual SoftBusList *CreateSoftBusList(void) = 0;
    virtual void DestroySoftBusList(SoftBusList *list) = 0;
    virtual int32_t ClientStubInit(void) = 0;
    virtual int32_t ClientRegisterBrProxyService(const char *pkgName) = 0;
    virtual int32_t ServerIpcOpenBrProxy(const char *brMac, const char *uuid) = 0;
    virtual int32_t ServerIpcIsProxyChannelEnabled(int32_t uid, bool *isEnable) = 0;
    virtual int32_t ServerIpcSendBrProxyData(int32_t channelId, char *data, uint32_t dataLen) = 0;
    virtual int32_t ServerIpcCloseBrProxy(int32_t channelId) = 0;
    virtual int32_t ServerIpcSetListenerState(int32_t channelId, int32_t type, bool CbEnabled) = 0;
};

class BrProxyExtInterfaceMock : public BrProxyExtInterface {
public:
    BrProxyExtInterfaceMock();
    ~BrProxyExtInterfaceMock() override;
    MOCK_METHOD0(CreateSoftBusList, SoftBusList * (void));
    MOCK_METHOD1(DestroySoftBusList, void (SoftBusList *));
    MOCK_METHOD0(ClientStubInit, int32_t (void));
    MOCK_METHOD1(ClientRegisterBrProxyService, int32_t (const char *));
    MOCK_METHOD2(ServerIpcOpenBrProxy, int32_t (const char *, const char *));
    MOCK_METHOD2(ServerIpcIsProxyChannelEnabled, int32_t (int32_t, bool *));
    MOCK_METHOD3(ServerIpcSendBrProxyData, int32_t (int32_t, char *, uint32_t));
    MOCK_METHOD1(ServerIpcCloseBrProxy, int32_t (int32_t));
    MOCK_METHOD3(ServerIpcSetListenerState, int32_t (int32_t, int32_t, bool));
};
} // namespace OHOS
#endif // BR_PROXY_EXT_TEST_MOCK_H