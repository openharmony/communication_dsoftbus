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

#include <string>

#include "ipc_skeleton.h"
#include "softbus_error_code.h"
#include "trans_log.h"

int32_t SoftBusGetSelfTokenId(uint64_t *selfTokenId)
{
    if (selfTokenId == nullptr) {
        TRANS_LOGE(TRANS_SDK, "invalid param, selfTokenId is nullptr");
        return SOFTBUS_INVALID_PARAM;
    }
    *selfTokenId = OHOS::IPCSkeleton::GetSelfTokenID();
    return SOFTBUS_OK;
}

int32_t SoftBusGetCallingTokenId(uint32_t *callingTokenId)
{
    if (callingTokenId == nullptr) {
        TRANS_LOGE(TRANS_SDK, "invalid param, callingTokenId is nullptr");
        return SOFTBUS_INVALID_PARAM;
    }
    *callingTokenId = OHOS::IPCSkeleton::GetCallingTokenID();
    return SOFTBUS_OK;
}

int32_t SoftBusGetCallingFullTokenId(uint64_t *callingFullTokenId)
{
    if (callingFullTokenId == nullptr) {
        TRANS_LOGE(TRANS_SDK, "invalid param, callingFullTokenId is nullptr");
        return SOFTBUS_INVALID_PARAM;
    }
    *callingFullTokenId = OHOS::IPCSkeleton::GetCallingFullTokenID();
    return SOFTBUS_OK;
}
