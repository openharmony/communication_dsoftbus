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

#include "session_ipc_adapter.h"

#include "softbus_error_code.h"

int32_t SoftBusGetSelfTokenId(uint64_t *selfTokenId)
{
    (void)selfTokenId;
    return SOFTBUS_OK;
}

int32_t SoftBusGetCallingTokenId(uint32_t *callingTokenId)
{
    (void)callingTokenId;
    return SOFTBUS_OK;
}

int32_t SoftBusGetCallingFullTokenId(uint64_t *callingFullTokenId)
{
    (void)callingFullTokenId;
    return SOFTBUS_OK;
}
