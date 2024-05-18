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

#include "auth_mock.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
void *g_authMock;
AuthInterfaceMock::AuthInterfaceMock()
{
    g_authMock = reinterpret_cast<void *>(this);
}

AuthInterfaceMock::~AuthInterfaceMock()
{
    g_authMock = nullptr;
}

static AuthInterface *GetAuthInterface()
{
    return reinterpret_cast<AuthInterface *>(g_authMock);
}

extern "C" {
void AuthHandleLeaveLNN(AuthHandle authHandle)
{
    GetAuthInterface()->AuthHandleLeaveLNN(authHandle);
}

uint32_t AuthGenRequestId(void)
{
    return GetAuthInterface()->AuthGenRequestId();
}

int32_t AuthStartVerify(const AuthConnInfo *connInfo, uint32_t requestId, const AuthVerifyCallback *callback,
    AuthVerifyModule module, bool isFastAuth)
{
    return GetAuthInterface()->AuthStartVerify(connInfo, requestId, callback, module, isFastAuth);
}

int32_t AuthGetVersion(int64_t authId, SoftBusVersion *version)
{
    return GetAuthInterface()->AuthGetVersion(authId, version);
}

int32_t AuthGetDeviceUuid(int64_t authId, char *uuid, uint16_t size)
{
    return GetAuthInterface()->AuthGetDeviceUuid(authId, uuid, size);
}

int32_t RegAuthTransListener(int32_t module, const AuthTransListener *listener)
{
    return GetAuthInterface()->RegAuthTransListener(module, listener);
}

void UnregAuthTransListener(int32_t module)
{
    return GetAuthInterface()->UnregAuthTransListener(module);
}

int32_t AuthPostTransData(AuthHandle authHandle, const AuthTransData *dataInfo)
{
    return GetAuthInterface()->AuthPostTransData(authHandle, dataInfo);
}

int64_t AuthGetIdByConnInfo(const AuthConnInfo *connInfo, bool isServer, bool isMeta)
{
    return GetAuthInterface()->AuthGetIdByConnInfo(connInfo, isServer, isMeta);
}
int32_t AuthFlushDevice(const char *uuid)
{
    return GetAuthInterface()->AuthFlushDevice(uuid);
}
int32_t AuthSendKeepaliveOption(const char *uuid, ModeCycle cycle)
{
    return GetAuthInterface()->AuthSendKeepaliveOption(uuid, cycle);
}
}
}