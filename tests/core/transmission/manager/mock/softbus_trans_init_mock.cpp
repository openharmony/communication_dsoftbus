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

#include "softbus_trans_init_mock.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
static void *g_softbusTransInitMock;
SoftbusTransInitInterfaceMock::SoftbusTransInitInterfaceMock()
{
    g_softbusTransInitMock = reinterpret_cast<void *>(this);
}

SoftbusTransInitInterfaceMock::~SoftbusTransInitInterfaceMock()
{
    g_softbusTransInitMock = nullptr;
}

static SoftbusTransInitInterface *GetSoftbusTransInitInterface()
{
    return reinterpret_cast<SoftbusTransInitInterface *>(g_softbusTransInitMock);
}

extern "C" {
int32_t SoftBusDlsym(const void *DllHandle, const char *funcName, void **funcHandle)
{
    return GetSoftbusTransInitInterface()->SoftBusDlsym(DllHandle, funcName, funcHandle);
}
}
}
