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
#include "softbus_lnn_init.h"
#include "softbus_init_common.h"
#include "softbus_error_code.h"
#include "comm_log.h"

int32_t LnnOpenFuncInit(void *soHandle)
{
    if (soHandle == NULL) {
        return SOFTBUS_NETWORK_DLOPEN_FAILED;
    }
    int32_t (*lnnRegisterOpenfunc)(void);

    int ret = SOFTBUS_OK;

    ret = SoftBusDlsym(soHandle, "LnnRegisterOpenFunc", (void**)&lnnRegisterOpenfunc);
    if (ret != SOFTBUS_OK) {
        COMM_LOGE(COMM_SVC, "dlsym LnnRegisterOpenFunc failed, ret=%d", ret);
        return ret;
    }

    ret = lnnRegisterOpenfunc();
    if (ret != SOFTBUS_OK) {
        COMM_LOGE(COMM_SVC, "LnnRegisterOpenFunc return failed, ret=%d", ret);
        return ret;
    }

    return ret;
}