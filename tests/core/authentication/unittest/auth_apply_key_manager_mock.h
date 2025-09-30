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

#ifndef AUTH_APPLY_KEY_MANAGER_MOCK_H
#define AUTH_APPLY_KEY_MANAGER_MOCK_H

#include <gmock/gmock.h>

#include "g_enhance_lnn_func.h"
#include "g_enhance_lnn_func_pack.h"

namespace OHOS {
class MockInterface {
public:
    MockInterface() {};
    virtual ~MockInterface() {};
    virtual int32_t LnnAsyncSaveDeviceDataPacked(const char *data, LnnDataType dataType) = 0;
    virtual int32_t LnnRetrieveDeviceDataPacked(LnnDataType dataType, char **data, uint32_t *dataLen) = 0;
};

class AuthApplyKeyManagerMock : public MockInterface {
public:
    AuthApplyKeyManagerMock();
    ~AuthApplyKeyManagerMock() override;

    MOCK_METHOD(int32_t, LnnAsyncSaveDeviceDataPacked, (const char *data, LnnDataType dataType), (override));
    MOCK_METHOD(
        int32_t, LnnRetrieveDeviceDataPacked, (LnnDataType dataType, char **data, uint32_t *dataLen), (override));
    static AuthApplyKeyManagerMock& GetMock();

private:
    static AuthApplyKeyManagerMock *gMock;
};

void AuthApplyKeyManagerMockReg(void);
} // namespace OHOS
#endif // AUTH_APPLY_KEY_MANAGER_MOCK_H