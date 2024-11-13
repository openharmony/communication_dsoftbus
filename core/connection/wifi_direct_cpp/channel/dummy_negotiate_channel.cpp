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
#include "dummy_negotiate_channel.h"
#include "conn_log.h"
#include "softbus_error_code.h"

namespace OHOS::SoftBus {
DummyNegotiateChannel::~DummyNegotiateChannel() { }

int DummyNegotiateChannel::SendMessage(const NegotiateMessage &msg) const
{
    CONN_LOGI(CONN_WIFI_DIRECT, "Empty implementation");
    return SOFTBUS_OK;
}

std::string DummyNegotiateChannel::GetRemoteDeviceId() const
{
    CONN_LOGI(CONN_WIFI_DIRECT, "Empty implementation");
    return "";
}
} // namespace OHOS::SoftBus