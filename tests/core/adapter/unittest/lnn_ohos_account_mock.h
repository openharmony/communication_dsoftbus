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

#ifndef LNN_LANE_DEPS_MOCK_H
#define LNN_LANE_DEPS_MOCK_H

#include <gmock/gmock.h>
#include <mutex>
#include "softbus_adapter_crypto.h"
#include "bus_center_info_key.h"
#include "lnn_ohos_account_adapter.h"

namespace OHOS {
class LnnOhosAccountInterface {
public:
    LnnOhosAccountInterface() {};
    virtual ~LnnOhosAccountInterface() {};
    
    virtual int32_t SoftBusGenerateStrHash(const unsigned char *str, uint32_t len, unsigned char *hash) = 0;
    virtual int32_t GetOsAccountId(char *id, uint32_t idLen, uint32_t *len) = 0;
    virtual int32_t LnnGetLocalByteInfo(InfoKey key, uint8_t *info, uint32_t len) = 0;
    virtual int32_t UpdateRecoveryDeviceInfoFromDb(void) = 0;
};

class LnnOhosAccountInterfaceMock : public LnnOhosAccountInterface {
public:
    LnnOhosAccountInterfaceMock();
    ~LnnOhosAccountInterfaceMock() override;

    MOCK_METHOD3(SoftBusGenerateStrHash, int32_t (const unsigned char *str, uint32_t len, unsigned char *hash));
    MOCK_METHOD3(GetOsAccountId, int32_t (char *id, uint32_t idLen, uint32_t *len));
    MOCK_METHOD3(LnnGetLocalByteInfo, int32_t (InfoKey key, uint8_t *info, uint32_t len));
    MOCK_METHOD0(UpdateRecoveryDeviceInfoFromDb, int32_t (void));
};
} // namespace OHOS
#endif