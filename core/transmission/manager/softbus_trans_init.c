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

#include "softbus_trans_init.h"
#include "comm_log.h"

int32_t TransOpenFuncInit(void *soHandle)
{
    if (soHandle == NULL) {
        COMM_LOGE(COMM_SVC, "libdsoftbus_server_plugin.z.so soHandle is null");
        return SOFTBUS_NETWORK_DLOPEN_FAILED;
    }
    int32_t (*transRegisterOpenfunc)(void);

    int32_t ret = SOFTBUS_OK;

    ret = SoftBusDlsym(soHandle, "TransRegisterOpenFunc", (void **)&transRegisterOpenfunc);
    if (ret != SOFTBUS_OK) {
        COMM_LOGE(COMM_SVC, "dlsym TransRegisterOpenFunc failed, ret=%d", ret);
        return SOFTBUS_NETWORK_DLSYM_FAILED;
    }

    if (transRegisterOpenfunc() != SOFTBUS_OK) {
        COMM_LOGE(COMM_SVC, "TransRegisterOpenFunc return failed, ret=%d", ret);
        return SOFTBUS_NETWORK_TRANS_OPEN_FUNC_INIT_FAILED;
    }

    return ret;
}