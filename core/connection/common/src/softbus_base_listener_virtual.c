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

#include "softbus_base_listener.h"

#include "conn_log.h"

int32_t InitBaseListener(void)
{
    CONN_LOGE(CONN_COMMON, "not support");
	// in order to init completely
    return SOFTBUS_OK;
}

void DeinitBaseListener(void)
{
    CONN_LOGE(CONN_COMMON, "not support");
}

int32_t StartBaseClient(ListenerModule module, const SoftbusBaseListener *listener)
{
    (void)module;
    (void)listener;
    CONN_LOGE(CONN_COMMON, "not support");
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t AddTrigger(ListenerModule module, int32_t fd, TriggerType trigger)
{
    (void)module;
    (void)fd;
    (void)trigger;
    CONN_LOGE(CONN_COMMON, "not support");
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t DelTrigger(ListenerModule module, int32_t fd, TriggerType trigger)
{
    (void)module;
    (void)fd;
    (void)trigger;
    CONN_LOGE(CONN_COMMON, "not support");
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t StartBaseListener(const LocalListenerInfo *info, const SoftbusBaseListener *listener)
{
    (void)info;
    (void)listener;
    CONN_LOGE(CONN_COMMON, "not support");
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t StopBaseListener(ListenerModule module)
{
    (void)module;
    CONN_LOGE(CONN_COMMON, "not support");
    return SOFTBUS_NOT_IMPLEMENT;
}

bool IsListenerNodeExist(ListenerModule module)
{
    (void)module;
    CONN_LOGE(CONN_COMMON, "not support");
    return false;
}