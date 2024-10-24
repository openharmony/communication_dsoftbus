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

#include "softbus_server_test_mock.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {

static void *g_softbusServerInterface = nullptr;

SoftbusServerTestInterfaceMock::SoftbusServerTestInterfaceMock()
{
    g_softbusServerInterface = reinterpret_cast<void *>(this);
}

SoftbusServerTestInterfaceMock::~SoftbusServerTestInterfaceMock()
{
    g_softbusServerInterface = nullptr;
}

static SoftbusServerTestInterface *GetSoftbusServerTestInterface()
{
    return reinterpret_cast<SoftbusServerTestInterface *>(g_softbusServerInterface);
}

extern "C" {
bool IsValidString(const char *input, uint32_t maxLen)
{
    return GetSoftbusServerTestInterface()->IsValidString(input, maxLen);
}
}
}