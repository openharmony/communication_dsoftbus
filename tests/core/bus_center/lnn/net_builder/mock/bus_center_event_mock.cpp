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

#include "bus_center_event_mock.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
void *g_busCenterMock;
BusCenterEventMock::BusCenterEventMock()
{
    g_busCenterMock = reinterpret_cast<void *>(this);
}

BusCenterEventMock::~BusCenterEventMock()
{
    g_busCenterMock = nullptr;
}

static BusCenterEventInterface *GetBusEventInterface()
{
    return reinterpret_cast<BusCenterEventInterface *>(g_busCenterMock);
}

extern "C" {
void LnnNotifyJoinResult(ConnectionAddr *addr, const char *networkId, int32_t retCode)
{
    GetBusEventInterface()->LnnNotifyJoinResult(addr, networkId, retCode);
}
}
}