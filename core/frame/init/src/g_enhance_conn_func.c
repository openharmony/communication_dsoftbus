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

#include "g_enhance_conn_func.h"

#include <securec.h>
#include <dlfcn.h>

ConnEnhanceFuncList g_connEnhanceFuncList = { NULL };

ConnEnhanceFuncList *ConnEnhanceFuncListGet(void)
{
    return &g_connEnhanceFuncList;
}

int32_t ConnRegisterEnhanceFunc(void *soHandle)
{
    g_connEnhanceFuncList.connCocClientConnect = dlsym(soHandle, "ConnCocClientConnect");
    g_connEnhanceFuncList.connCocClientDisconnect = dlsym(soHandle, "ConnCocClientDisconnect");
    g_connEnhanceFuncList.connCocClientSend = dlsym(soHandle, "ConnCocClientSend");
    g_connEnhanceFuncList.connCocClientUpdatePriority = dlsym(soHandle, "ConnCocClientUpdatePriority");
    g_connEnhanceFuncList.connCocServerStartService = dlsym(soHandle, "ConnCocServerStartService");
    g_connEnhanceFuncList.connCocServerStopService = dlsym(soHandle, "ConnCocServerStopService");
    g_connEnhanceFuncList.connCocServerSend = dlsym(soHandle, "ConnCocServerSend");
    g_connEnhanceFuncList.connCocServerDisconnect = dlsym(soHandle, "ConnCocServerDisconnect");
    g_connEnhanceFuncList.connCocServerConnect = dlsym(soHandle, "ConnCocServerConnect");
    g_connEnhanceFuncList.connCocInitClientModule = dlsym(soHandle, "ConnCocInitClientModule");
    g_connEnhanceFuncList.connCocInitServerModule = dlsym(soHandle, "ConnCocInitServerModule");
    g_connEnhanceFuncList.connBleDirectConnectDevice = dlsym(soHandle, "ConnBleDirectConnectDevice");
    g_connEnhanceFuncList.connBleDirectIsEnable = dlsym(soHandle, "ConnBleDirectIsEnable");
    g_connEnhanceFuncList.connBleDirectInit = dlsym(soHandle, "ConnBleDirectInit");

    g_connEnhanceFuncList.connCoapStopServerListen = dlsym(soHandle, "ConnCoapStopServerListen");
    g_connEnhanceFuncList.connCoapStartServerListen = dlsym(soHandle, "ConnCoapStartServerListen");
    g_connEnhanceFuncList.softbusBleConflictRegisterListener = dlsym(soHandle, "SoftbusBleConflictRegisterListener");
    g_connEnhanceFuncList.softbusBleConflictNotifyDateReceive = dlsym(soHandle, "SoftbusBleConflictNotifyDateReceive");
    g_connEnhanceFuncList.softbusBleConflictNotifyDisconnect = dlsym(soHandle, "SoftbusBleConflictNotifyDisconnect");
    g_connEnhanceFuncList.softbusBleConflictNotifyConnectResult = dlsym(soHandle,
        "SoftbusBleConflictNotifyConnectResult");
    g_connEnhanceFuncList.connSleInit = dlsym(soHandle, "ConnSleInit");
    g_connEnhanceFuncList.connDirectConnectDevice = dlsym(soHandle, "ConnDirectConnectDevice");

    return SOFTBUS_OK;
}