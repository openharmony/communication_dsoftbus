/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#ifndef LNN_AUTH_MOCK_H
#define LNN_AUTH_MOCK_H

#include <gmock/gmock.h>
#include <mutex>

#include "auth_interface.h"

namespace OHOS {
class LnnAuthInterface {
public:
    LnnAuthInterface() {};
    virtual ~LnnAuthInterface() {};
    virtual int32_t AuthStartVerify(const AuthConnInfo *connInfo, uint32_t requestId,
        const AuthVerifyCallback *callback, AuthVerifyModule module, bool isFastAuth) = 0;
    virtual int32_t AuthGetVersion(int64_t authId, SoftBusVersion *version) = 0;
    virtual int32_t RegGroupChangeListener(const GroupChangeListener *listener) = 0;
};

class LnnAuthtInterfaceMock : public LnnAuthInterface {
public:
    LnnAuthtInterfaceMock();
    ~LnnAuthtInterfaceMock() override;
    MOCK_METHOD5(
        AuthStartVerify, int32_t(const AuthConnInfo *, uint32_t, const AuthVerifyCallback *, AuthVerifyModule, bool));
    MOCK_METHOD2(AuthGetVersion, int32_t(int64_t, SoftBusVersion *));
    MOCK_METHOD1(RegGroupChangeListener, int32_t(const GroupChangeListener *));
};
} // namespace OHOS
#endif // LNN_AUTH_MOCK_H