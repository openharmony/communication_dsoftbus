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

#include "null_processor.h"

#include "conn_log.h"
#include "softbus_error_code.h"

#include "utils/wifi_direct_anonymous.h"
#include "wifi_direct_executor.h"

namespace OHOS::SoftBus {
NullProcessor::NullProcessor(const std::string &remoteDeviceId, const int32_t reason)
    : WifiDirectProcessor(remoteDeviceId), reason_(reason)
{
    CONN_LOGI(CONN_WIFI_DIRECT, "Create null processor, because do not have handle processpr");
}

[[noreturn]] void NullProcessor::Run()
{
    for (;;) {
        CONN_LOGI(CONN_WIFI_DIRECT, "null");
        executor_->WaitEvent().Handle<std::shared_ptr<ConnectCommand>>([this] (auto &command) {
            command->OnFailure(reason_);
            throw ProcessorTerminate();
        }).Handle<std::shared_ptr<DisconnectCommand>>([this] (auto &command) {
            command->OnSuccess();
            throw ProcessorTerminate();
        }).Handle<std::shared_ptr<NegotiateCommand>>([this] (auto &command) {
            throw ProcessorTerminate();
        });
    }
}
}