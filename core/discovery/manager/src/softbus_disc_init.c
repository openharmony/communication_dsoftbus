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

#include "softbus_disc_init.h"
#include "softbus_init_common.h"
#include "softbus_error_code.h"
#include "comm_log.h"

int32_t DiscOpenFuncInit(void *soHandle)
{
    if (soHandle == NULL) {
        COMM_LOGE(COMM_SVC, "libdsoftbus_server_plugin.z.so soHandle is null");
        return SOFTBUS_NETWORK_DLOPEN_FAILED;
    }
    int32_t (*discRegisterOpenfunc)(void);

    int ret = SOFTBUS_OK;

    ret = SoftBusDlsym(soHandle, "DiscRegisterOpenFunc", (void**)&discRegisterOpenfunc);
    if (ret != SOFTBUS_OK) {
        COMM_LOGE(COMM_SVC, "dlsym DiscRegisterOpenFunc fail, ret=%d", ret);
        return SOFTBUS_NETWORK_DLSYM_FAILED;
    }

    if (discRegisterOpenfunc() != SOFTBUS_OK) {
        COMM_LOGE(COMM_SVC, "DiscRegisterOpenFunc return fail, ret=%d", ret);
        return SOFTBUS_NETWORK_DISC_OPEN_FUNC_INIT_FAILED;
    }

    return ret;
}