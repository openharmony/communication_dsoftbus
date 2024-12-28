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
#include "lnn_physical_subnet_manager.h"

#include "softbus_error_code.h"

int32_t LnnRegistPhysicalSubnet(LnnPhysicalSubnet *manager)
{
    (void)manager;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t LnnUnregistPhysicalSubnetByType(ProtocolType type)
{
    (void)type;
    return SOFTBUS_NOT_IMPLEMENT;
}

void LnnNotifyPhysicalSubnetStatusChanged(const char *ifName, ProtocolType type, void *status)
{
    (void)ifName;
    (void)type;
    (void)status;
}

bool LnnVisitPhysicalSubnet(LnnVisitPhysicalSubnetCallback callback, void *data)
{
    (void)callback;
    (void)data;
    return false;
}

void LnnNotifyAllTypeOffline(ConnectionAddrType type)
{
    (void)type;
}