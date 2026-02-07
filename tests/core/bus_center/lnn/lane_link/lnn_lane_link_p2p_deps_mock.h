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

#ifndef LNN_LANE_LINK_P2P_DEPS_MOCK_H
#define LNN_LANE_LINK_P2P_DEPS_MOCK_H

#include <gmock/gmock.h>
#include "g_enhance_lnn_func.h"

namespace OHOS {
class LaneLinkP2pDepsInterface {
public:
    LaneLinkP2pDepsInterface() {};
    virtual ~LaneLinkP2pDepsInterface() {};

    virtual LnnEnhanceFuncList *LnnEnhanceFuncListGet(void) = 0;
    virtual bool IsEnhancedWifiDirectSupported(const char *networkId) = 0;
};

class LaneLinkP2pDepsInterfaceMock : public LaneLinkP2pDepsInterface {
public:
    LaneLinkP2pDepsInterfaceMock();
    ~LaneLinkP2pDepsInterfaceMock() override;

    MOCK_METHOD0(LnnEnhanceFuncListGet, LnnEnhanceFuncList *(void));
    MOCK_METHOD1(IsEnhancedWifiDirectSupported, bool (const char *networkId));
};
} // namespace OHOS
#endif // LNN_LANE_LINK_P2P_DEPS_MOCK_H
