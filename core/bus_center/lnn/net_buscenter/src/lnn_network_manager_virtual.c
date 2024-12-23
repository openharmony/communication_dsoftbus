/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include "lnn_network_manager.h"

#include "lnn_log.h"
#include "softbus_error_code.h"

int32_t LnnInitNetworkManager(void)
{
    LNN_LOGI(LNN_INIT, "init virtual lnn network manager");
    return SOFTBUS_OK;
}

int32_t LnnInitNetworkManagerDelay(void)
{
    return SOFTBUS_OK;
}

void LnnDeinitNetworkManager(void)
{
}

void RestartCoapDiscovery(void)
{
    return;
}

int32_t LnnGetNetIfTypeByName(const char *ifName, LnnNetIfType *type)
{
    (void)ifName;
    (void)type;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t LnnGetAddrTypeByIfName(const char *ifName, ConnectionAddrType *type)
{
    (void)ifName;
    (void)type;
    return SOFTBUS_NOT_IMPLEMENT;
}

void LnnGetDataShareInitResult(bool *isDataShareInit)
{
    (void)isDataShareInit;
}

void LnnSetUnlockState(void) {}

bool LnnVisitNetif(VisitNetifCallback callback, void *data)
{
    (void)callback;
    (void)data;
    return false;
}

int32_t LnnRegistProtocol(LnnProtocolManager *impl)
{
    (void)impl;
    return SOFTBUS_NOT_IMPLEMENT;
}

ListenerModule LnnGetProtocolListenerModule(ProtocolType protocol, ListenerMode mode)
{
    (void)protocol;
    (void)mode;
    return UNUSE_BUTT;
}