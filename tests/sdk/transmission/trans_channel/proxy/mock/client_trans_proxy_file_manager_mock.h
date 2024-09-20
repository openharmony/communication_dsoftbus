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

#ifndef CLIENT_TRANS_PROXY_FILE_MANAGER_MOCK_H
#define CLIENT_TRANS_PROXY_FILE_MANAGER_MOCK_H

#include <gmock/gmock.h>

namespace OHOS {
class ClientTransProxyFileManagerInterface {
public:
    ClientTransProxyFileManagerInterface() {};
    virtual ~ClientTransProxyFileManagerInterface() {};
    virtual uint32_t SoftBusLtoHl(uint32_t value) = 0;
    virtual uint32_t SoftBusHtoLl(uint32_t value) = 0;
    virtual uint64_t SoftBusLtoHll(uint64_t value) = 0;
    virtual uint64_t SoftBusHtoLll(uint64_t value) = 0;
};

class ClientTransProxyFileManagerInterfaceMock : public ClientTransProxyFileManagerInterface {
public:
    ClientTransProxyFileManagerInterfaceMock();
    ~ClientTransProxyFileManagerInterfaceMock() override;
    MOCK_METHOD1(SoftBusLtoHl, uint32_t (uint32_t value));
    MOCK_METHOD1(SoftBusHtoLl, uint32_t (uint32_t value));
    MOCK_METHOD1(SoftBusLtoHll, uint64_t (uint64_t value));
    MOCK_METHOD1(SoftBusHtoLll, uint64_t (uint64_t value));
};
} // namespace OHOS
#endif // CLIENT_TRANS_PROXY_FILE_MANAGER_MOCK_H
