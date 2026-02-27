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

#include "g_enhance_trans_func.h"

#include <dlfcn.h>
#include <securec.h>

TransEnhanceFuncList g_transEnhanceFuncList = { NULL };

TransEnhanceFuncList *TransEnhanceFuncListGet(void)
{
    return &g_transEnhanceFuncList;
}

int32_t TransRegisterEnhanceFunc(void *soHandle)
{
    g_transEnhanceFuncList.initQos = dlsym(soHandle, "InitQos");
    g_transEnhanceFuncList.notifyQosChannelOpened = dlsym(soHandle, "NotifyQosChannelOpened");
    g_transEnhanceFuncList.notifyQosChannelClosed = dlsym(soHandle, "NotifyQosChannelClosed");
    g_transEnhanceFuncList.getExtQosInfo = dlsym(soHandle, "GetExtQosInfo");
    g_transEnhanceFuncList.setDefaultQdisc = dlsym(soHandle, "SetDefaultQdisc");

    g_transEnhanceFuncList.transReversePullUp = dlsym(soHandle, "TransReversePullUp");
    g_transEnhanceFuncList.transGetPkgnameByBusinessFlag = dlsym(soHandle, "TransGetPkgnameByBusinessFlag");
    g_transEnhanceFuncList.initSoftbusPagingResPull = dlsym(soHandle, "InitSoftbusPagingResPull");
    g_transEnhanceFuncList.deInitSoftbusPagingResPull = dlsym(soHandle, "DeInitSoftbusPagingResPull");
    g_transEnhanceFuncList.initSoftbusPaging = dlsym(soHandle, "InitSoftbusPaging");
    g_transEnhanceFuncList.deInitSoftbusPaging = dlsym(soHandle, "DeInitSoftbusPaging");
    g_transEnhanceFuncList.transPagingDeathCallback = dlsym(soHandle, "TransPagingDeathCallback");
    g_transEnhanceFuncList.transPagingHasListenAndGetInfo = dlsym(soHandle, "TransPagingHasListenAndGetInfo");
    g_transEnhanceFuncList.transPagingGetPidAndDataByFlg = dlsym(soHandle, "TransPagingGetPidAndDataByFlg");
    g_transEnhanceFuncList.transDelPagingInfoByBusinessFlag = dlsym(soHandle, "TransDelPagingInfoByBusinessFlag");
    g_transEnhanceFuncList.clientOpenHtpChannel = dlsym(soHandle, "ClientOpenHtpChannel");
    g_transEnhanceFuncList.serverOpenHtpChannel = dlsym(soHandle, "ServerOpenHtpChannel");
    g_transEnhanceFuncList.closeHtpChannel = dlsym(soHandle, "CloseHtpChannel");
    g_transEnhanceFuncList.serverUpdateHtpChannel = dlsym(soHandle, "ServerUpdateHtpChannel");
    g_transEnhanceFuncList.checkHtpPermission = dlsym(soHandle, "CheckHtpPermission");
    g_transEnhanceFuncList.transProcessGroupTalkieInfo = dlsym(soHandle, "TransProcessGroupTalkieInfo");
    g_transEnhanceFuncList.isInWhitelist = dlsym(soHandle, "IsInWhitelist");
    g_transEnhanceFuncList.checkAuthChannelSessionNameValid = dlsym(soHandle, "CheckAuthChannelSessionNameValid");
    g_transEnhanceFuncList.transCheckNetworkDelegate = dlsym(soHandle, "TransCheckNetworkDelegate");
    g_transEnhanceFuncList.transCheckP2pOnly = dlsym(soHandle, "TransCheckP2pOnly");
    g_transEnhanceFuncList.transCheckDcTriggerVirtualLink = dlsym(soHandle, "TransCheckDcTriggerVirtualLink");
    g_transEnhanceFuncList.loadTransPermissionJson = dlsym(soHandle, "LoadTransPermissionJson");
    g_transEnhanceFuncList.transD2dQosUnregister = dlsym(soHandle, "TransD2dQosUnregister");
    g_transEnhanceFuncList.isMultipathWhitelist = dlsym(soHandle, "IsMultipathWhitelist");
    return SOFTBUS_OK;
}
