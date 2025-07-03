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

#ifndef BR_PROXY_SERVER_MANAGER_TEST_MOCK_H
#define BR_PROXY_SERVER_MANAGER_TEST_MOCK_H

#include <gmock/gmock.h>
#include "br_proxy_common.h"
#include "trans_client_proxy.h"

namespace OHOS {
class BrProxyServerManagerInterface {
public:
    BrProxyServerManagerInterface() {};
    virtual ~BrProxyServerManagerInterface() {};

    virtual int32_t PullUpHap(const char *bundleName, const char *abilityName) = 0;
    virtual int32_t GetCallerHapInfo(char *bundleName, uint32_t bundleNamelen, char *abilityName,
        uint32_t abilityNameLen) = 0;
    virtual pid_t GetCallerPid() = 0;
    virtual pid_t GetCallerUid() = 0;
    virtual uint32_t GetCallerTokenId() = 0;
    virtual int32_t CheckPushPermission() = 0;
};

class BrProxyServerManagerInterfaceMock : public BrProxyServerManagerInterface {
public:
    BrProxyServerManagerInterfaceMock();
    ~BrProxyServerManagerInterfaceMock() override;

    MOCK_METHOD2(PullUpHap, int32_t (const char *, const char *));
    MOCK_METHOD4(GetCallerHapInfo, int32_t (char *, uint32_t, char *, uint32_t));
    MOCK_METHOD0(GetCallerPid, pid_t (void));
    MOCK_METHOD0(GetCallerUid, pid_t (void));
    MOCK_METHOD0(GetCallerTokenId, uint32_t (void));
    MOCK_METHOD0(CheckPushPermission, int32_t (void));
};
} // namespace OHOS
#endif // BR_PROXY_SERVER_MANAGER_TEST_MOCK_H