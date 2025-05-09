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

#ifndef NAPI_SOFTBUS_LINK_ENHANCE_CONNECTION_H_
#define NAPI_SOFTBUS_LINK_ENHANCE_CONNECTION_H_

#include "napi_link_enhance_utils.h"

namespace Communication {
namespace OHOS::Softbus {
class NapiLinkEnhanceConnection {
public:
    static napi_value Create(napi_env env, napi_callback_info info);
    static void DefineJSClass(napi_env env);
    static napi_value Constructor(napi_env env, napi_callback_info info);

    static napi_value On(napi_env env, napi_callback_info info);
    static napi_value Off(napi_env env, napi_callback_info info);

    static napi_value Connect(napi_env env, napi_callback_info info);
    static napi_value Disconnect(napi_env env, napi_callback_info info);
    static napi_value Close(napi_env env, napi_callback_info info);

    static napi_value GetPeerDeviceId(napi_env env, napi_callback_info info);
    static napi_value SendData(napi_env env, napi_callback_info info);

    explicit NapiLinkEnhanceConnection(const std::string &deviceId, const std::string &name)
        : deviceId_(deviceId), name_(name) { }

    explicit NapiLinkEnhanceConnection(const std::string &deviceId, const std::string &name, const int32_t handle)
        : deviceId_(deviceId), name_(name), handle_(handle) { }
    ~NapiLinkEnhanceConnection() = default;
    
    static std::vector<NapiLinkEnhanceConnection *> connectionList_;
    static std::mutex connectionListMutex_;
    bool IsConnectResultEnable();
    bool IsDataReceiveEnable();
    bool IsDisconnectEnable();
    static thread_local napi_ref consRef_;
    napi_ref connectResultRef_ = nullptr;
    napi_ref dataReceivedRef_ = nullptr;
    napi_ref disconnectRef_ = nullptr;
    napi_env env_;

    std::string deviceId_;
    std::string name_;
    uint32_t handle_ = 0;
    enum ConnectionState state_ = ConnectionState::STATE_BASE;
private:
    std::recursive_timed_mutex lock_;
    bool isEnableConnectResult_ = false;
    bool isEnableData_ = false;
    bool isEnableDisconnect_ = false;
    void SetConnectResultEnable(bool isEnableConnectResult)
    {
        this->lock_.lock();
        this->isEnableConnectResult_ = isEnableConnectResult;
        this->lock_.unlock();
    }

    void SetEnableData(bool isEnableData)
    {
        this->lock_.lock();
        this->isEnableData_ = isEnableData;
        this->lock_.unlock();
    }

    void SetEnableDisconnect(bool isEnableDisconnect)
    {
        this->lock_.lock();
        this->isEnableDisconnect_ = isEnableDisconnect;
        this->lock_.unlock();
    }
};
} // namespace SoftBus
} // namespace Communication
#endif /* NAPI_SOFTBUS_LINK_ENHANCE_CONNECTION_H_ */