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
 
#ifndef NAPI_SOFTBUS_AGENT_CONMMUNICACTION_UTILS_H_
#define NAPI_SOFTBUS_AGENT_CONMMUNICACTION_UTILS_H_
 
#include "napi/native_api.h"
#include "napi/native_node_api.h"
 
#include "comm_log.h"
 
namespace Communication {
namespace OHOS::Softbus {
 
constexpr size_t ARGS_SIZE_TWO = 2;
constexpr size_t SEND_ARGS_SIZE = 4;
constexpr size_t REGISTER_ARGS_SIZE = 3;
 
bool ParseString(napi_env env, std::string &param, napi_value args);
int32_t ConvertToJsErrcode(int32_t err);
void ThrowBusinessError(const napi_env &env, int32_t errCode);
 
} // namespace Softbus
} // namespace Communication
#endif /* NAPI_SOFTBUS_AGENT_CONMMUNICACTION_UTILS_H_ */