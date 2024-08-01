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

#include "softbus_server_stub_test_mock.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
static void *g_softbusServerStubInterface = nullptr;
SoftbusServerStubTestInterfaceMock::SoftbusServerStubTestInterfaceMock()
{
    g_softbusServerStubInterface = reinterpret_cast<void *>(this);
}

SoftbusServerStubTestInterfaceMock::~SoftbusServerStubTestInterfaceMock()
{
    g_softbusServerStubInterface = nullptr;
}

static SoftbusServerStubTestInterface *GetSoftbusServerStubTestInterface()
{
    return reinterpret_cast<SoftbusServerStubTestInterface *>(g_softbusServerStubInterface);
}

extern "C" {
int32_t CheckTransPermission(pid_t callingUid, pid_t callingPid, const char *pkgName,
    const char *sessionName, uint32_t actions)
{
    return GetSoftbusServerStubTestInterface()->CheckTransPermission(callingUid, callingPid, pkgName,
        sessionName, actions);
}
int32_t CheckTransSecLevel(const char *mySessionName, const char *peerSessionName)
{
    return GetSoftbusServerStubTestInterface()->CheckTransSecLevel(mySessionName, peerSessionName);
}
}
}