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

#ifndef SOFTBUS_SERVER_STUB_TEST_MOCK_H
#define SOFTBUS_SERVER_STUB_TEST_MOCK_H

#include "softbus_client_info_manager.h"
#include <gmock/gmock.h>

namespace OHOS {
class SoftbusServerTestInterface {
public:
    SoftbusServerTestInterface() {};
    virtual ~SoftbusServerTestInterface() {};
    virtual bool IsValidString(const char *input, uint32_t maxLen) = 0;
};
class SoftbusServerTestInterfaceMock : public SoftbusServerTestInterface {
public:
    SoftbusServerTestInterfaceMock();
    ~SoftbusServerTestInterfaceMock() override;
    MOCK_METHOD2(IsValidString, bool (const char *input, uint32_t maxLen));
};
}

#endif