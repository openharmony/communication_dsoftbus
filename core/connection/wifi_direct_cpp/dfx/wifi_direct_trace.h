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

#ifndef WIFI_DIRECT_TRACE_H
#define WIFI_DIRECT_TRACE_H

#include <string>

namespace OHOS::SoftBus {
class WifiDirectTrace {
public:
    static void StartTrace(const std::string &requestDeviceId, const std::string &receiverDeviceId);
    static void StopTrace();
    static void SetRequestId(uint64_t requestId);
};

} // namespace OHOS::SoftBus
#endif // WIFI_DIRECT_TRACE_H
