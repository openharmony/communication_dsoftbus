/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "bus_center_ex_obj_stub.h"

#include <dlfcn.h>

#include "lnn_log.h"
#include "softbus_init_common.h"
namespace OHOS {
#ifdef __aarch64__
static constexpr const char *SOFTBUS_SERVER_PLUGIN_PATH_NAME = "/system/lib64/libdsoftbus_server_plugin.z.so";
#else
static constexpr const char *SOFTBUS_SERVER_PLUGIN_PATH_NAME = "/system/lib/libdsoftbus_server_plugin.z.so";
#endif

bool BusCenterExObjStub::OpenSoftbusPluginSo()
{
    std::lock_guard<std::mutex> lockGuard(loadSoMutex_);

    if (isLoaded_ && (soHandle_ != nullptr)) {
        return true;
    }

    (void)SoftBusDlopen(SOFTBUS_HANDLE_SERVER_PLUGIN, &soHandle_);
    if (soHandle_ == nullptr) {
        LNN_LOGE(LNN_EVENT, "dlopen %{public}s failed, err msg:%{public}s", SOFTBUS_SERVER_PLUGIN_PATH_NAME, dlerror());
        return false;
    }

    isLoaded_ = true;
    LNN_LOGI(LNN_EVENT, "dlopen %{public}s SOFTBUS_CLIENT_SUCCESS", SOFTBUS_SERVER_PLUGIN_PATH_NAME);

    return true;
}

int32_t BusCenterExObjStub::OnRemoteRequest(uint32_t code,
    MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    if (onRemoteRequestFunc_ != nullptr) {
        return onRemoteRequestFunc_(code, data, reply, option);
    }

    if (!OpenSoftbusPluginSo()) {
        return SOFTBUS_BUS_CENTER_EX_OBJ_PROXY_DLOPEN_FAILED;
    }

    onRemoteRequestFunc_ = (OnRemoteRequestFunc)dlsym(soHandle_, "OnRemoteRequestByDlsym");
    if (onRemoteRequestFunc_ == nullptr) {
        LNN_LOGE(LNN_EVENT, "dlsym OnRemoteRequest fail, err msg:%{public}s", dlerror());
        return SOFTBUS_BUS_CENTER_EX_OBJ_PROXY_DLSYM_FAILED;
    }

    return onRemoteRequestFunc_(code, data, reply, option);
}
} // namespace OHOS