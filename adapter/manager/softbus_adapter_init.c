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

#include "softbus_adapter_init.h"

#include "auth_interface.h"
#include "auth_connection.h"
#include "bus_center_event.h"
#include "comm_log.h"

int32_t AdapterOpenFuncInit(void *soHandle)
{
    if (soHandle == NULL) {
        COMM_LOGE(COMM_SVC, "libdsoftbus_server_plugin.z.so soHandle is null");
        return SOFTBUS_NETWORK_DLOPEN_FAILED;
    }
    int32_t (*adapterRegisterOpenfunc)(void);

    int32_t ret = SOFTBUS_OK;

    ret = SoftBusDlsym(soHandle, "AdapterRegisterOpenFunc", (void **)&adapterRegisterOpenfunc);
    if (ret != SOFTBUS_OK) {
        COMM_LOGE(COMM_SVC, "dlsym AdapterRegisterOpenFunc failed, ret=%d", ret);
        return SOFTBUS_NETWORK_DLSYM_FAILED;
    }

    ret = adapterRegisterOpenfunc();
    if (ret != SOFTBUS_OK) {
        COMM_LOGE(COMM_SVC, "AdapterRegisterOpenFunc return failed, ret=%d", ret);
        return SOFTBUS_NETWORK_ADAPTER_OPEN_FUNC_INIT_FAILED;
    }

    return ret;
}