/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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

#ifndef NAPI_SOFTBUS_LINK_ENHANCE_SERVER_H_
#define NAPI_SOFTBUS_LINK_ENHANCE_SERVER_H_

#include "napi_link_enhance_utils.h"

namespace Communication {
namespace OHOS::Softbus {
class NapiLinkEnhanceServer {

public:
    static napi_value Create(napi_env env, napi_callback_info info);
    static void DefineJSClass(napi_env env);
    static napi_value Constructor(napi_env env, napi_callback_info info);

    static napi_value On(napi_env env, napi_callback_info info);
    static napi_value Off(napi_env env, napi_callback_info info);

    static napi_value Start(napi_env env, napi_callback_info info);
    static napi_value Stop(napi_env env, napi_callback_info info);
    static napi_value Close(napi_env env, napi_callback_info info);

    NapiLinkEnhanceServer(const std::string &name)
    {
        this->name_ = name;
    }
    ~NapiLinkEnhanceServer() = default;
    bool IsAcceptedEnable();
    bool IsStopEnable();
    static std::unordered_map<std::string, NapiLinkEnhanceServer *> enhanceServerMap_;
    static std::mutex serverMapMutex_;

    static thread_local napi_ref consRef_;

    napi_ref acceptConnectRef_ = nullptr;
    napi_ref serverStopRef_ = nullptr;
    napi_env env_ = nullptr;

    std::string name_ = "";
private:
    std::recursive_timed_mutex lock_;
    bool isAcceptedEnable_ = false;
    bool isStopEnable_ = false;
    void SetAcceptedEnable(bool isAcceptedEnable)
    {
        this->lock_.lock();
        this->isAcceptedEnable_ = isAcceptedEnable;
        this->lock_.unlock();
    }
    void SetStopEnable(bool isStopEnable)
    {
        this->lock_.lock();
        this->isStopEnable_ = isStopEnable;
        this->lock_.unlock();
    }
};
} // namespace SoftBus
} // namespace Communication
#endif /* NAPI_SOFTBUS_LINK_ENHANCE_SERVER_H_ */
 