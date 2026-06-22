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
 
#ifndef NAPI_SOFTBUS_AGENT_CONMMUNICACTION_H_
#define NAPI_SOFTBUS_AGENT_CONMMUNICACTION_H_
 
 
#include "napi_agent_communication_utils.h"
#include "softbus_agent_communication.h"
 
namespace Communication {
namespace OHOS::Softbus {
 
struct DataCallbackData {
    std::string deviceId;
    uint8_t *data;
    uint32_t dataLen;
};
 
struct SendMsgContext {
    napi_env env;
    napi_async_work work;
    napi_deferred deferred;
 
    std::string deviceId;
    std::string bundleName;
    std::string abilityName;
    uint8_t *msg;
    uint32_t msgLen;
 
    ConversationBusiness business;
 
    int32_t resultCode;
};
 
static napi_value NapiGetTrustedDevicesWrapper(napi_env env, napi_callback_info info);
static napi_value NapiPostConversationDataAsync(napi_env env, napi_callback_info info);
static napi_value NapiRegisterConversationListenerWarpper(napi_env env, napi_callback_info info);
static napi_value NapiUnregisterConversationListenerWarpper(napi_env env, napi_callback_info info);
 
} // namespace Softbus
} // namespace Communication
#endif /* NAPI_SOFTBUS_AGENT_CONMMUNICACTION_UTILS_H_ */