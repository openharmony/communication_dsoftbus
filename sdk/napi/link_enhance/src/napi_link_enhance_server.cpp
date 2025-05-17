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
#include "napi_link_enhance_server.h"

#include "napi_link_enhance_error_code.h"
#include "napi_link_enhance_utils.h"
#include "softbus_error_code.h"
#include "softbus_connection.h"

namespace Communication {
namespace OHOS::Softbus {

thread_local napi_ref NapiLinkEnhanceServer::consRef_ = nullptr;

std::unordered_map<std::string, NapiLinkEnhanceServer *> NapiLinkEnhanceServer::enhanceServerMap_;
std::mutex NapiLinkEnhanceServer::serverMapMutex_;

static napi_status CheckCreateServerParams(napi_env env, napi_callback_info info, napi_value &outResult)
{
    size_t argc = ARGS_SIZE_ONE;
    napi_value argv[ARGS_SIZE_ONE] = { 0 };

    NAPI_SOFTBUS_CALL_RETURN(napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr));
    NAPI_SOFTBUS_RETURN_IF(
        argc != ARGS_SIZE_ONE, "expect 1 args", napi_invalid_arg);

    std::string name {};
    if (!ParseString(env, name, argv[ARGS_SIZE_ZERO])) {
        COMM_LOGE(COMM_SDK, "expect string");
        return napi_string_expected;
    }

    napi_value constructor = nullptr;
    if (NapiLinkEnhanceServer::consRef_ == nullptr) {
        return napi_string_expected;
    }
    NAPI_SOFTBUS_CALL_RETURN(napi_get_reference_value(env, NapiLinkEnhanceServer::consRef_, &constructor));
    NAPI_SOFTBUS_CALL_RETURN(napi_new_instance(env, constructor, argc, argv, &outResult));
    return napi_ok;
}

napi_value NapiLinkEnhanceServer::Create(napi_env env, napi_callback_info info)
{
    napi_value result;
    auto status = CheckCreateServerParams(env, info, result);
    if (status != napi_ok) {
        HandleSyncErr(env, LINK_ENHANCE_PARAMETER_INVALID);
        return NapiGetUndefinedRet(env);
    }
    return result;
}

void NapiLinkEnhanceServer::DefineJSClass(napi_env env)
{
    napi_property_descriptor serverDesc[] = {
        DECLARE_NAPI_FUNCTION("start", Start),
        DECLARE_NAPI_FUNCTION("stop", Stop),
        DECLARE_NAPI_FUNCTION("close", Close),
        DECLARE_NAPI_FUNCTION("on", On),
        DECLARE_NAPI_FUNCTION("off", Off),
    };

    napi_value constructor = nullptr;
    napi_define_class(env, "Server", NAPI_AUTO_LENGTH, Constructor, nullptr,
        sizeof(serverDesc) / sizeof(serverDesc[0]), serverDesc, &constructor);
    napi_create_reference(env, constructor, 1, &consRef_);
}

napi_value NapiLinkEnhanceServer::Constructor(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;

    size_t argc = ARGS_SIZE_ONE;
    napi_value argv[ARGS_SIZE_ONE] = {0};

    napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    if (argc != ARGS_SIZE_ONE) {
        COMM_LOGE(COMM_SDK, "expect one args");
        return NapiGetUndefinedRet(env);
    }
    std::string name;
    if (!ParseString(env, name, argv[PARAM0])) {
        COMM_LOGE(COMM_SDK, "Parse name failed ");
        return NapiGetUndefinedRet(env);
    }
    {
        std::lock_guard<std::mutex> guard(serverMapMutex_);
        if (enhanceServerMap_.find(name) != enhanceServerMap_.end()) {
            HandleSyncErr(env, LINK_ENHANCE_DUPLICATE_SERVER_NAME);
            return NapiGetUndefinedRet(env);
        }
    }
    NapiLinkEnhanceServer* enhanceServer = new NapiLinkEnhanceServer(name);
    if (enhanceServer == nullptr) {
        COMM_LOGE(COMM_SDK, "new enhanceServer failed");
        return NapiGetUndefinedRet(env);
    }
    auto status = napi_wrap(
        env, thisVar, enhanceServer,
        [](napi_env env, void* data, void* hint) {
            NapiLinkEnhanceServer* server = static_cast<NapiLinkEnhanceServer*>(data);
            if (server) {
                delete server;
                server = nullptr;
            }
        },
        nullptr,
        nullptr);
    if (status != napi_ok) {
        COMM_LOGE(COMM_SDK, "napi_wrap failed");
        delete enhanceServer;
        enhanceServer = nullptr;
        return thisVar;
    }
    enhanceServer->env_ = env;
    {
        std::lock_guard<std::mutex> guard(serverMapMutex_);
        enhanceServerMap_[name] = enhanceServer;
    }

    return thisVar;
}

static NapiLinkEnhanceServer *NapiGetEnhanceServer(napi_env env, napi_value thisVar)
{
    NapiLinkEnhanceServer *enhanceServer = nullptr;
    auto status = napi_unwrap(env, thisVar, (void **)&enhanceServer);
    if (status != napi_ok) {
        return nullptr;
    }
    return enhanceServer;
}

static NapiLinkEnhanceServer *NapiGetEnhanceServer(napi_env env, napi_callback_info info)
{
    size_t argc = 0;
    napi_value thisVar = nullptr;
    if (napi_get_cb_info(env, info, &argc, nullptr, &thisVar, nullptr) != napi_ok) {
        return nullptr;
    }
    return NapiGetEnhanceServer(env, thisVar);
}

napi_value NapiLinkEnhanceServer::On(napi_env env, napi_callback_info info)
{
    size_t argc = ARGS_SIZE_TWO;
    NapiLinkEnhanceServer *enhanceServer = NapiGetEnhanceServer(env, info);
    if (enhanceServer == nullptr) {
        HandleSyncErr(env, LINK_ENHANCE_PARAMETER_INVALID);
        return NapiGetUndefinedRet(env);
    }
    napi_value args[ARGS_SIZE_TWO];
    napi_status status = napi_get_cb_info(env, info, &argc, args, nullptr, nullptr);
    if (status != napi_ok || argc != ARGS_SIZE_TWO) {
        HandleSyncErr(env, LINK_ENHANCE_PARAMETER_INVALID);
        return NapiGetUndefinedRet(env);
    }
    char type[ARGS_TYPE_MAX_LEN];
    size_t typeLen = 0;
    status = napi_get_value_string_utf8(env, args[ARGS_SIZE_ZERO], type, sizeof(type), &typeLen);
    if (status != napi_ok) {
        HandleSyncErr(env, LINK_ENHANCE_PARAMETER_INVALID);
        return NapiGetUndefinedRet(env);
    }
    if (strcmp(type, "connectionAccepted") == 0) {
        COMM_LOGE(COMM_SDK, "register connectionAccepted");
        if (enhanceServer->acceptConnectRef_ != nullptr) {
            napi_delete_reference(env, enhanceServer->acceptConnectRef_);
        }
        napi_create_reference(env, args[ARGS_SIZE_ONE], 1, &(enhanceServer->acceptConnectRef_));
        enhanceServer->SetAcceptedEnable(true);
    } else if (strcmp(type, "serverStopped") == 0) {
        COMM_LOGE(COMM_SDK, "register serverStopped");
        if (enhanceServer->serverStopRef_ != nullptr) {
            napi_delete_reference(env, enhanceServer->serverStopRef_);
        }
        napi_create_reference(env, args[ARGS_SIZE_ONE], 1, &(enhanceServer->serverStopRef_));
        enhanceServer->SetStopEnable(true);
    } else {
        HandleSyncErr(env, LINK_ENHANCE_PARAMETER_INVALID);
        return NapiGetUndefinedRet(env);
    }
    return NapiGetUndefinedRet(env);
}

napi_value NapiLinkEnhanceServer::Off(napi_env env, napi_callback_info info)
{
    NapiLinkEnhanceServer* enhanceServer = NapiGetEnhanceServer(env, info);
    if (enhanceServer == nullptr) {
        HandleSyncErr(env, LINK_ENHANCE_PARAMETER_INVALID);
        return NapiGetUndefinedRet(env);
    }
    size_t argc = ARGS_SIZE_TWO;
    napi_value args[ARGS_SIZE_TWO];
    napi_status status = napi_get_cb_info(env, info, &argc, args, nullptr, nullptr);
    if (status != napi_ok || argc != ARGS_SIZE_TWO) {
        HandleSyncErr(env, LINK_ENHANCE_PARAMETER_INVALID);
        return NapiGetUndefinedRet(env);
    }

    char type[ARGS_TYPE_MAX_LEN];
    size_t typeLen = 0;
    status = napi_get_value_string_utf8(env, args[ARGS_SIZE_ZERO], type, sizeof(type), &typeLen);
    if (status != napi_ok) {
        HandleSyncErr(env, LINK_ENHANCE_PARAMETER_INVALID);
        return NapiGetUndefinedRet(env);
    }
    if (strcmp(type, "onAcceptConnect") == 0) {
        if (enhanceServer->acceptConnectRef_ != nullptr) {
            napi_delete_reference(env, enhanceServer->acceptConnectRef_);
        }
        enhanceServer->acceptConnectRef_ = nullptr;
        enhanceServer->SetAcceptedEnable(false);
    } else if (strcmp(type, "serverStopped") == 0) {
        if (enhanceServer->serverStopRef_ != nullptr) {
            napi_delete_reference(env, enhanceServer->serverStopRef_);
        }
        enhanceServer->serverStopRef_ = nullptr;
        enhanceServer->SetStopEnable(false);
    } else {
        HandleSyncErr(env, LINK_ENHANCE_PARAMETER_INVALID);
        return NapiGetUndefinedRet(env);
    }
    return NapiGetUndefinedRet(env);
}

napi_value NapiLinkEnhanceServer::Start(napi_env env, napi_callback_info info)
{
    size_t argc = 0;
    napi_status status = napi_get_cb_info(env, info, &argc, nullptr, nullptr, nullptr);
    if (status != napi_ok || argc > ARGS_SIZE_ZERO) {
        HandleSyncErr(env, LINK_ENHANCE_INTERVAL_ERR);
        return NapiGetUndefinedRet(env);
    }
    NapiLinkEnhanceServer *enhanceServer = NapiGetEnhanceServer(env, info);
    if (enhanceServer == nullptr) {
        HandleSyncErr(env, LINK_ENHANCE_INTERVAL_ERR);
        return NapiGetUndefinedRet(env);
    }
    int32_t ret = GeneralCreateServer(PKG_NAME.c_str(), enhanceServer->name_.c_str());
    if (ret != 0) {
        COMM_LOGE(COMM_SDK, "create server failed, ret=%{public}d", ret);
        int32_t errCode = ConvertToJsErrcode(ret);
        HandleSyncErr(env, errCode);
    }
    return NapiGetUndefinedRet(env);
}

napi_value NapiLinkEnhanceServer::Stop(napi_env env, napi_callback_info info)
{
    size_t argc = 0;
    napi_status status = napi_get_cb_info(env, info, &argc, nullptr, nullptr, nullptr);
    if (status != napi_ok || argc > ARGS_SIZE_ZERO) {
        COMM_LOGE(COMM_SDK, "no needed arguments");
        return NapiGetUndefinedRet(env);
    }
    NapiLinkEnhanceServer *enhanceServer = NapiGetEnhanceServer(env, info);
    if (enhanceServer == nullptr) {
        COMM_LOGE(COMM_SDK, "get server failed");
        return NapiGetUndefinedRet(env);
    }
    enhanceServer->lock_.lock();
    enhanceServer->isAcceptedEnable_ = false;
    enhanceServer->isStopEnable_ = false;
    enhanceServer->lock_.unlock();

    int32_t ret = GeneralRemoveServer(PKG_NAME.c_str(), enhanceServer->name_.c_str());
    if (ret != 0) {
        COMM_LOGE(COMM_SDK, "remove server failed, ret=%{public}d", ret);
        if (ConvertToJsErrcode(ret) == LINK_ENHANCE_PERMISSION_DENIED) {
            HandleSyncErr(env, LINK_ENHANCE_PERMISSION_DENIED);
        }
    }
    return NapiGetUndefinedRet(env);
}

napi_value NapiLinkEnhanceServer::Close(napi_env env, napi_callback_info info)
{
    COMM_LOGI(COMM_SDK, "enter");
    size_t argc = 0;
    napi_status status = napi_get_cb_info(env, info, &argc, nullptr, nullptr, nullptr);
    if (status != napi_ok || argc > ARGS_SIZE_ZERO) {
        COMM_LOGE(COMM_SDK, "no needed arguments");
        return NapiGetUndefinedRet(env);
    }
    NapiLinkEnhanceServer *enhanceServer = NapiGetEnhanceServer(env, info);
    if (enhanceServer == nullptr) {
        COMM_LOGE(COMM_SDK, "get server failed");
        return NapiGetUndefinedRet(env);
    }
    int32_t ret = GeneralRemoveServer(PKG_NAME.c_str(), enhanceServer->name_.c_str());
    if (ret != 0) {
        COMM_LOGE(COMM_SDK, "remove server failed, ret=%{public}d", ret);
        if (ConvertToJsErrcode(ret) == LINK_ENHANCE_PERMISSION_DENIED) {
            HandleSyncErr(env, LINK_ENHANCE_PERMISSION_DENIED);
        }
    }
    enhanceServer->lock_.lock();
    enhanceServer->isAcceptedEnable_ = false;
    enhanceServer->isStopEnable_ = false;
    enhanceServer->lock_.unlock();
    if (enhanceServer->acceptConnectRef_ != nullptr) {
        napi_delete_reference(env, enhanceServer->acceptConnectRef_);
        enhanceServer->acceptConnectRef_ = nullptr;
    }
    if (enhanceServer->serverStopRef_ != nullptr) {
        napi_delete_reference(env, enhanceServer->serverStopRef_);
        enhanceServer->serverStopRef_ = nullptr;
    }
    {
        std::lock_guard<std::mutex> guard(serverMapMutex_);
        if (enhanceServerMap_.find(enhanceServer->name_) != enhanceServerMap_.end()) {
            enhanceServerMap_.erase(enhanceServer->name_);
        }
    }
    return NapiGetUndefinedRet(env);
}

bool NapiLinkEnhanceServer::IsAcceptedEnable()
{
    this->lock_.lock();
    bool isEnable = this->isAcceptedEnable_;
    this->lock_.unlock();
    return isEnable;
}

bool NapiLinkEnhanceServer::IsStopEnable()
{
    this->lock_.lock();
    bool isEnable = this->isStopEnable_;
    this->lock_.unlock();
    return isEnable;
}
} // namespace SoftBus
} // namespace Communication