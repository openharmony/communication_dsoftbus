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

#include "softbus_conn_init.h"

#include "comm_log.h"
#include "g_reg_conn_func.h"
#include "g_enhance_conn_func.h"
#include "softbus_conn_ble_manager.h"
#include "softbus_conn_interface.h"
#include "softbus_base_listener.h"

int32_t ConnOpenFuncInit(void *soHandle)
{
    if (soHandle == NULL) {
        COMM_LOGE(COMM_SVC, "libdsoftbus_server_plugin.z.so soHandle is null");
        return SOFTBUS_NETWORK_DLOPEN_FAILED;
    }
    int32_t (*connRegisterOpenfunc)(void);

    int ret = SOFTBUS_OK;

    ret = SoftBusDlsym(soHandle, "ConnRegisterOpenFunc", (void**)&connRegisterOpenfunc);
    if (ret != SOFTBUS_OK) {
        COMM_LOGE(COMM_SVC, "dlsym ConnRegisterOpenFunc failed, ret=%d", ret);
        return SOFTBUS_NETWORK_DLSYM_FAILED;
    }

    if (connRegisterOpenfunc() != SOFTBUS_OK) {
        COMM_LOGE(COMM_SVC, "ConnRegisterOpenFunc return failed, ret=%d", ret);
        return SOFTBUS_NETWORK_CONN_OPEN_FUNC_INIT_FAILED;
    }

    return ret;
}