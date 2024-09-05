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
#include "lnn_oobe_manager.h"

#include "softbus_errcode.h"

int32_t LnnGetOOBEState(SoftBusOOBEState *state)
{
    if (state == nullptr) {
        return SOFTBUS_INVALID_PARAM;
    }

    *state = SOFTBUS_OOBE_END;
    return SOFTBUS_OK;
}

void LnnInitOOBEStateMonitorImpl(void)
{
}

void RegisterOOBEMonitor(void *para)
{
    (void)para;
}