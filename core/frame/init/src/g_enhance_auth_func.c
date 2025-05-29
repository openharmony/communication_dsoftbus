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

#include "g_enhance_auth_func.h"

#include <securec.h>
#include <dlfcn.h>
AuthEnhanceFuncList g_authEnhanceFuncList = { NULL };

AuthEnhanceFuncList *AuthEnhanceFuncListGet(void)
{
    return &g_authEnhanceFuncList;
}

int32_t AuthRegisterEnhanceFunc(void *soHandle)
{
    g_authEnhanceFuncList.authMetaInit = dlsym(soHandle, "AuthMetaInit");
    g_authEnhanceFuncList.authMetaNotifyDataReceived = dlsym(soHandle, "AuthMetaNotifyDataReceived");

    g_authEnhanceFuncList.isNeedUDIDAbatement = dlsym(soHandle, "IsNeedUDIDAbatement");
    g_authEnhanceFuncList.generateCertificate = dlsym(soHandle, "GenerateCertificate");
    g_authEnhanceFuncList.verifyCertificate = dlsym(soHandle, "VerifyCertificate");
    g_authEnhanceFuncList.authUpdateNormalizeKeyIndex = dlsym(soHandle, "AuthUpdateNormalizeKeyIndex");

    g_authEnhanceFuncList.delAuthMetaManagerByConnectionId = dlsym(soHandle, "DelAuthMetaManagerByConnectionId");
    g_authEnhanceFuncList.authMetaGetConnInfoBySide = dlsym(soHandle, "AuthMetaGetConnInfoBySide");
    g_authEnhanceFuncList.authIsLatestNormalizeKeyInTime = dlsym(soHandle, "AuthIsLatestNormalizeKeyInTime");
    g_authEnhanceFuncList.authClearDeviceKey = dlsym(soHandle, "AuthClearDeviceKey");
    return SOFTBUS_OK;
}