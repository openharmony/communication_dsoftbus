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

#ifndef TRANS_TCP_DIRECT_MOCK_H
#define TRANS_TCP_DIRECT_MOCK_H

#include <gmock/gmock.h>

namespace OHOS {
class TransTcpDirectInterface {
public:
    TransTcpDirectInterface() {};
    virtual ~TransTcpDirectInterface() {};
    virtual int32_t SoftBusSocketGetError(int32_t socketFd) = 0;
    virtual int32_t GetErrCodeBySocketErr(int32_t transErrCode) = 0;
};

class TransTcpDirectInterfaceMock : public TransTcpDirectInterface {
public:
    TransTcpDirectInterfaceMock();
    ~TransTcpDirectInterfaceMock() override;
    MOCK_METHOD1(SoftBusSocketGetError, int32_t (int32_t socketFd));
    MOCK_METHOD1(GetErrCodeBySocketErr, int32_t (int32_t transErrCode));
};
} // namespace OHOS
#endif // TRANS_TCP_DIRECT_MOCK_H
