/*
 * Copyright (c) 2024-2025 Huawei Device Co., Ltd.
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

#include "lnn_event_monitor_impl.h"

#include "lnn_init_monitor.h"
#include "softbus_error_code.h"

int32_t ConfigNetLinkUp(const char *ifName)
{
    (void)ifName;
    return SOFTBUS_FUNC_NOT_SUPPORT;
}

int32_t ConfigLocalIp(const char *ifName, const char *localIp)
{
    (void)ifName;
    (void)localIp;
    return SOFTBUS_FUNC_NOT_SUPPORT;
}

int32_t ConfigRoute(const int32_t id, const char *ifName, const char *destination, const char *gateway)
{
    (void)id;
    (void)ifName;
    (void)destination;
    (void)gateway;
    return SOFTBUS_FUNC_NOT_SUPPORT;
}

int32_t ConfigLocalIpv6(const char *ifName, const char *localIpv6)
{
    (void)ifName;
    (void)localIpv6;
    return SOFTBUS_FUNC_NOT_SUPPORT;
}

int32_t LnnInitNetManagerMonitorImpl(void)
{
    LnnInitModuleStatusSet(INIT_DEPS_USB, DEPS_STATUS_FAILED);
    return SOFTBUS_OK;
}

void LnnDeinitNetManagerMonitorImpl(void)
{}