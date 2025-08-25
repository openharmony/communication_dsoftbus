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

#ifndef TRANS_TCP_DIRECT_COMMON_MOCK_H
#define TRANS_TCP_DIRECT_COMMON_MOCK_H

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "auth_interface_struct.h"

namespace OHOS {
class TransTcpDirectCommonInterface {
public:
    TransTcpDirectCommonInterface() {};
    virtual ~TransTcpDirectCommonInterface() {};
    virtual int32_t AuthMetaPostTransData(int64_t authId, const AuthTransData *dataInfo) = 0;
    virtual int32_t AuthMetaGetServerSide(int64_t authId, bool *isServer) = 0;
};

class TransTcpDirectCommonInterfaceMock : public TransTcpDirectCommonInterface {
public:
    TransTcpDirectCommonInterfaceMock();
    ~TransTcpDirectCommonInterfaceMock() override;
    MOCK_METHOD2(AuthMetaPostTransData, int32_t (int64_t authId, const AuthTransData *dataInfo));
    MOCK_METHOD2(AuthMetaGetServerSide, int32_t (int64_t authId, bool *isServer));
};
} // namespace OHOS
#endif // TRANS_TCP_DIRECT_COMMON_MOCK_H
