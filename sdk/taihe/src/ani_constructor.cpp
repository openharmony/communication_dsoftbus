/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
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

#include "ohos.distributedsched.linkEnhance.ani.hpp"
#include "link_enhance_utils_taihe.h"
#include "softbus_error_code.h"
ANI_EXPORT ani_status ANI_Constructor(ani_vm *vm, uint32_t *result)
{
    if (vm == nullptr) {
        COMM_LOGE(COMM_SDK, "vm is null");
        return ANI_ERROR;
    }
    if (result == nullptr) {
        COMM_LOGE(COMM_SDK, "result is null");
        return ANI_ERROR;
    }
    ani_env *env = nullptr;
    if (ANI_OK != vm->GetEnv(ANI_VERSION_1, &env)) {
        COMM_LOGE(COMM_SDK, "get env fail");
        return ANI_ERROR;
    }
    if (ANI_OK != ohos::distributedsched::linkEnhance::ANIRegister(env)) {
        COMM_LOGE(COMM_SDK, "register fail");
        return ANI_ERROR;
    }
    int32_t ret = Communication::OHOS::Softbus::Init();
    if (ret != SOFTBUS_OK) {
        COMM_LOGE(COMM_SDK, "init fail");
        return ANI_ERROR;
    }
    *result = ANI_VERSION_1;
    return ANI_OK;
}