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

#include "lnn_discovery_manager.h"

#include "lnn_log.h"
#include "softbus_error_code.h"

int32_t LnnInitDiscoveryManager(void)
{
    LNN_LOGI(LNN_BUILDER, "init virtual discovery manager");
    return SOFTBUS_OK;
}

int32_t LnnStartPublish(void)
{
    return SOFTBUS_NOT_IMPLEMENT;
}

void LnnStopPublish(void)
{
}

int32_t LnnStartDiscovery(void)
{
    return SOFTBUS_NOT_IMPLEMENT;
}

void LnnStopDiscovery(void)
{
}