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
#include "lnn_log.h"
#include "lnn_usb_adapter.h"
#include "softbus_error_code.h"
#include "usb_srv_client.h"
#include "usb_srv_support.h"

int32_t StartUsbNcmAdapter(int32_t mode)
{
    LNN_LOGI(LNN_STATE, "StartUsbNcmAdapter entered! mode= %{public}d", mode);
    if (mode == NCM_DEVICE_MODE) {
        int32_t ret = OHOS::USB::UsbSrvClient::GetInstance().SetCurrentFunctions(
            OHOS::USB::UsbSrvSupport::Function::FUNCTION_NCM);
        if (ret != SOFTBUS_OK) {
            LNN_LOGE(LNN_STATE, "Failed ret = %{public}d", ret);
        }
        return ret;
    } else if (mode == NCM_HOST_MODE) {
        return SOFTBUS_OK;
    }
    LNN_LOGE(LNN_STATE, "mode invalid!");
    return SOFTBUS_NETWORK_USB_MODE_INVALID;
}