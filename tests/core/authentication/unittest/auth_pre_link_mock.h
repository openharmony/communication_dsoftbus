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

#ifndef AUTH_PRE_LINK_MOCK_H
#define AUTH_PRE_LINK_MOCK_H

#include <gmock/gmock.h>

#include "auth_pre_link.h"

namespace OHOS {
class AuthPreLinkInterface {
public:
    AuthPreLinkInterface() {};
    virtual ~AuthPreLinkInterface() {};

    virtual struct WifiDirectManager *GetWifiDirectManager(void) = 0;
};

class AuthPreLinkInterfaceMock : public AuthPreLinkInterface {
public:
    AuthPreLinkInterfaceMock();
    ~AuthPreLinkInterfaceMock() override;

    MOCK_METHOD0(GetWifiDirectManager, struct WifiDirectManager *(void));
};
} // namespace OHOS
#endif // AUTH_PRE_LINK_MOCK_H
