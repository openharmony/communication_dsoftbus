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

#ifndef BR_PROXY_TEST_MOCK_H
#define BR_PROXY_TEST_MOCK_H

#include <gmock/gmock.h>
#include "trans_client_proxy.h"
#include "br_proxy.h"

namespace OHOS {
class BrProxyInterface {
public:
    BrProxyInterface() {};
    virtual ~BrProxyInterface() {};
    virtual int32_t ClientIpcBrProxyOpened(const char *pkgName, int32_t channelId,
        const char *brMac, int32_t reason) = 0;
    virtual int32_t ConnectPeerDevice(BrProxyChannelInfo *channelInfo, uint32_t *requestId) = 0;
};

class BrProxyInterfaceMock : public BrProxyInterface {
public:
    BrProxyInterfaceMock();
    ~BrProxyInterfaceMock() override;
    MOCK_METHOD4(ClientIpcBrProxyOpened, int32_t (const char *pkgName, int32_t channelId,
        const char *brMac, int32_t reason));
    MOCK_METHOD2(ConnectPeerDevice, int32_t (BrProxyChannelInfo *channelInfo, uint32_t *requestId));
};
} // namespace OHOS
#endif // BR_PROXY_TEST_MOCK_H