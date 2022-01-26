/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include "if_softbus_client.h"

#include "softbus_log.h"
#include "softbus_errcode.h"

namespace OHOS {
void ISoftBusClient::OnPublishLNNResult(int32_t publishId, int32_t reason)
{
    (void)publishId;
    (void)reason;
    SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_INFO, "OnPublishLNNResult ipc default impl");
}

void ISoftBusClient::OnRefreshLNNResult(int32_t refreshId, int32_t reason)
{
    (void)refreshId;
    (void)reason;
    SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_INFO, "OnRefreshLNNResult ipc default impl");
}

void ISoftBusClient::OnRefreshDeviceFound(const void *device, uint32_t deviceLen)
{
    (void)device;
    (void)deviceLen;
    SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_INFO, "OnRefreshDeviceFound ipc default impl");
}
} // namespace OHOS