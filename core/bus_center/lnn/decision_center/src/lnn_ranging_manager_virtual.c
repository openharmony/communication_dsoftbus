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

#include "lnn_ranging_manager.h"

#include "lnn_log.h"
#include "softbus_error_code.h"

int32_t LnnStartRange(const RangeConfig *config)
{
    (void)config;
    LNN_LOGI(LNN_INIT, "sle start range success");
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t LnnStopRange(const RangeConfig *config)
{
    (void)config;
    LNN_LOGI(LNN_INIT, "sle stop range success");
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t RegistAuthTransListener()
{
    LNN_LOGI(LNN_BUILDER, "regist auth listner success");
    return SOFTBUS_OK;
}

int32_t UnregistAuthTransListener()
{
    LNN_LOGI(LNN_BUILDER, "unregist auth listner success");
    return SOFTBUS_OK;
}

int32_t SendAuthResult(AuthHandle authHandle, int64_t seq, const uint8_t *data, uint32_t len)
{
    (void)authHandle;
    LNN_LOGI(LNN_BUILDER, "send auth data success");
    return SOFTBUS_NOT_IMPLEMENT;
}