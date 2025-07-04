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

#ifndef TRANS_COMMON_MOCK_H
#define TRANS_COMMON_MOCK_H

#include <gmock/gmock.h>

#include "softbus_error_code.h"
#include "softbus_config_type.h"

namespace OHOS {
class TransCommInterface {
public:
    TransCommInterface() {};
    virtual ~TransCommInterface() {};

    virtual int SoftbusGetConfig(ConfigType type, unsigned char *val, uint32_t len) = 0;
};

class TransCommInterfaceMock : public TransCommInterface {
public:
    TransCommInterfaceMock();
    ~TransCommInterfaceMock() override;

    MOCK_METHOD3(SoftbusGetConfig, int(ConfigType type, unsigned char *val, uint32_t len));

    static int ActionOfSoftbusGetConfig(ConfigType type, unsigned char *val, uint32_t len);
};

} // namespace OHOS
#endif // TRANS_COMMON_MOCK_H
