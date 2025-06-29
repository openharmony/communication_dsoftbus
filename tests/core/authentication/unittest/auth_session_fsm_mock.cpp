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

#include "auth_session_fsm_mock.h"

namespace OHOS {
void *g_authSessionFsmInterface;
AuthSessionFsmInterfaceMock::AuthSessionFsmInterfaceMock()
{
    g_authSessionFsmInterface = reinterpret_cast<void *>(this);
}

AuthSessionFsmInterfaceMock::~AuthSessionFsmInterfaceMock()
{
    g_authSessionFsmInterface = nullptr;
}

static AuthSessionFsmInterfaceMock *GetAuthSessionFsmInterface()
{
    return reinterpret_cast<AuthSessionFsmInterfaceMock *>(g_authSessionFsmInterface);
}

extern "C" {
int32_t SoftBusGetBrState(void)
{
    return GetAuthSessionFsmInterface()->SoftBusGetBrState();
}

bool GetUdidShortHash(const AuthSessionInfo *info, char *udidBuf, uint32_t bufLen)
{
    return GetAuthSessionFsmInterface()->GetUdidShortHash(info, udidBuf, bufLen);
}

int32_t LnnRetrieveDeviceInfoPacked(const char *udid, NodeInfo *deviceInfo)
{
    return GetAuthSessionFsmInterface()->LnnRetrieveDeviceInfoPacked(udid, deviceInfo);
}

bool IsSupportFeatureByCapaBit(uint32_t feature, AuthCapability capaBit)
{
    return GetAuthSessionFsmInterface()->IsSupportFeatureByCapaBit(feature, capaBit);
}
}
}