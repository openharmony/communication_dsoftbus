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

#include "g_enhance_sdk_func.h"

#include <dlfcn.h>

ClientEnhanceFuncList g_clientEnhanceFuncList = { NULL };

ClientEnhanceFuncList *ClientEnhanceFuncListGet(void)
{
    return &g_clientEnhanceFuncList;
}

int32_t ClientRegisterEnhanceFunc(void *soHandle)
{
    g_clientEnhanceFuncList.busCenterExProxyDeInit = dlsym(soHandle, "BusCenterExProxyDeInit");
    g_clientEnhanceFuncList.discRecoveryPolicy = dlsym(soHandle, "DiscRecoveryPolicy");
    g_clientEnhanceFuncList.checkFileSchema = dlsym(soHandle, "CheckFileSchema");
    g_clientEnhanceFuncList.setSchemaCallback = dlsym(soHandle, "SetSchemaCallback");
    g_clientEnhanceFuncList.setExtSocketOpt = dlsym(soHandle, "SetExtSocketOpt");
    g_clientEnhanceFuncList.getExtSocketOpt = dlsym(soHandle, "GetExtSocketOpt");
    g_clientEnhanceFuncList.transFileSchemaInit = dlsym(soHandle, "TransFileSchemaInit");
    g_clientEnhanceFuncList.transFileSchemaDeinit = dlsym(soHandle, "TransFileSchemaDeinit");
    g_clientEnhanceFuncList.vtpSetSocketMultiLayer = dlsym(soHandle, "VtpSetSocketMultiLayer");
    g_clientEnhanceFuncList.isVtpFrameSentEvt = dlsym(soHandle, "IsVtpFrameSentEvt");
    g_clientEnhanceFuncList.handleVtpFrameEvt = dlsym(soHandle, "HandleVtpFrameEvt");
    g_clientEnhanceFuncList.transOnPagingConnect = dlsym(soHandle, "TransOnPagingConnect");

    return SOFTBUS_OK;
}