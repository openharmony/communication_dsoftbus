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

#ifndef LNN_WIFI_ADPTER_MOCK_H
#define LNN_WIFI_ADPTER_MOCK_H

#include <gmock/gmock.h>
#include <mutex>

#include "softbus_wifi_api_adapter.h"

namespace OHOS {
class LnnWifiAdpterInterface {
public:
    LnnWifiAdpterInterface() {};
    virtual ~LnnWifiAdpterInterface() {};
    virtual int32_t SoftBusGetLinkedInfo(SoftBusWifiLinkedInfo *info) = 0;
    virtual SoftBusBand SoftBusGetLinkBand(void) = 0;
};

class LnnWifiAdpterInterfaceMock : public LnnWifiAdpterInterface {
public:
    LnnWifiAdpterInterfaceMock();
    ~LnnWifiAdpterInterfaceMock() override;
    MOCK_METHOD1(SoftBusGetLinkedInfo, int32_t (SoftBusWifiLinkedInfo*));
    MOCK_METHOD0(SoftBusGetLinkBand, SoftBusBand ());

    void SetDefaultResult(void);
};

} // namespace OHOS
#endif // LNN_WIFI_ADPTER_MOCK_H