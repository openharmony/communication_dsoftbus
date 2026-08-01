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

#ifndef TAIHE_AGENT_COMMUNICATION_UTILS_H_
#define TAIHE_AGENT_COMMUNICATION_UTILS_H_

#include <cstdint>
#include <string>
#include "softbus_agent_communication.h"

namespace Communication {
namespace OHOS::Softbus {

int32_t ConvertToJsErrcode(int32_t err);
void ThrowBusinessException(int32_t err);
bool IsSystemApp(void);
bool CheckPermission(void);
void FillConversationBusiness(ConversationBusiness &business, const std::string &bundleName,
    const std::string &abilityName);

} // namespace Softbus
} // namespace Communication
#endif /* TAIHE_AGENT_COMMUNICATION_UTILS_H_ */
