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

#include "lnn_wifi_adpter_mock.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
void *g_wifiAdpterInterface;
LnnWifiAdpterInterfaceMock::LnnWifiAdpterInterfaceMock()
{
    g_wifiAdpterInterface = reinterpret_cast<void *>(this);
}

LnnWifiAdpterInterfaceMock::~LnnWifiAdpterInterfaceMock()
{
    g_wifiAdpterInterface = nullptr;
}

static LnnWifiAdpterInterface *GetWifiAdpterInterface()
{
    return reinterpret_cast<LnnWifiAdpterInterface *>(g_wifiAdpterInterface);
}

void LnnWifiAdpterInterfaceMock::SetDefaultResult()
{
    EXPECT_CALL(*this, SoftBusGetLinkBand).WillRepeatedly(Return(BAND_UNKNOWN));
}

extern "C" {
int32_t SoftBusGetLinkedInfo(SoftBusWifiLinkedInfo *info)
{
    return GetWifiAdpterInterface()->SoftBusGetLinkedInfo(info);
}

SoftBusBand SoftBusGetLinkBand(void)
{
    return GetWifiAdpterInterface()->SoftBusGetLinkBand();
}
}
}