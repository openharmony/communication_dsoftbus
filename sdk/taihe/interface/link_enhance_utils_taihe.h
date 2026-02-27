/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
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

#ifndef TAIHE_SOFTBUS_LINK_ENHANCE_UTILS_H_
#define TAIHE_SOFTBUS_LINK_ENHANCE_UTILS_H_

#include "comm_log.h"
#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <map>
#include <mutex>
#include <string>
#include <vector>
#include "uv.h"
#include "securec.h"
#include "softbus_adapter_mem.h"

#define SOFTBUS_NAME_MAX_LEN 255
namespace Communication {
namespace OHOS::Softbus {
inline static const std::string PKG_NAME = "ohos.distributedschedule.dms";
enum class ConnectionState {
    STATE_BASE = 0,
    STATE_CONNECTING = 1,
    STATE_CONNECTED = 2,
    STATE_DISCONNECTED = 3,
};

int32_t ConvertToJsErrcode(int32_t err);
bool CheckAccessToken(void);
void ThrowException(int32_t err);
int32_t Init();
} // namespace Softbus
} // namespace Communication
#endif /* TAIHE_SOFTBUS_LINK_ENHANCE_UTILS_H_ */