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

#include "ohos.distributedsched.linkEnhance.proj.hpp"
#include "ohos.distributedsched.linkEnhance.impl.hpp"
#include "stdexcept"
#include <thread>

#include "link_enhance_utils_taihe.h"
#include "taihe/runtime.hpp"

#define LINK_ENHANCE_DEVICE_NOT_SUPPORT 32390300
#define LINK_ENHANCE_DESCRIPTION        "device not support"

namespace Communication {
namespace OHOS::Softbus {
class ServerImpl;
class ConnectionImpl;
static std::vector<::ohos::distributedsched::linkEnhance::Connection> connectionList_;
static std::mutex connectionLock_;
static std::vector<::ohos::distributedsched::linkEnhance::Server> serverList_;
static std::mutex serverLock_;

class ServerImpl {
public:
    explicit ServerImpl()
    {
    }
    explicit ServerImpl(const std::string name)
    {
        this->name_ = name;
    }
    void Start()
    {
        taihe::set_business_error(LINK_ENHANCE_DEVICE_NOT_SUPPORT, LINK_ENHANCE_DESCRIPTION);
    }

    void Stop()
    {
        taihe::set_business_error(LINK_ENHANCE_DEVICE_NOT_SUPPORT, LINK_ENHANCE_DESCRIPTION);
    }

    void Close()
    {
        taihe::set_business_error(LINK_ENHANCE_DEVICE_NOT_SUPPORT, LINK_ENHANCE_DESCRIPTION);
    }

    void OnConnectionAccepted(::taihe::callback_view<void(
        ::ohos::distributedsched::linkEnhance::weak::Connection connection)> callback)
    {
        taihe::set_business_error(LINK_ENHANCE_DEVICE_NOT_SUPPORT, LINK_ENHANCE_DESCRIPTION);
    }

    void OffConnectionAccepted(::taihe::optional_view<::taihe::callback<void(
        ::ohos::distributedsched::linkEnhance::weak::Connection connection)>> callback)
    {
        taihe::set_business_error(LINK_ENHANCE_DEVICE_NOT_SUPPORT, LINK_ENHANCE_DESCRIPTION);
    }

    void OnServerStopped(::taihe::callback_view<void(int32_t result)> callback)
    {
        taihe::set_business_error(LINK_ENHANCE_DEVICE_NOT_SUPPORT, LINK_ENHANCE_DESCRIPTION);
    }

    void OffServerStopped(::taihe::optional_view<::taihe::callback<void(int32_t result)>> callback)
    {
        taihe::set_business_error(LINK_ENHANCE_DEVICE_NOT_SUPPORT, LINK_ENHANCE_DESCRIPTION);
    }
    int64_t GetServerImpl()
    {
        return reinterpret_cast<int64_t>(this);
    }
    std::string name_ = "";
    
private:
    std::recursive_timed_mutex lock_;
};

class ConnectionImpl {
public:
    explicit ConnectionImpl()
    {
        taihe::set_business_error(LINK_ENHANCE_DEVICE_NOT_SUPPORT, LINK_ENHANCE_DESCRIPTION);
    }
    explicit ConnectionImpl(const std::string name, uint32_t handle)
    {
        taihe::set_business_error(LINK_ENHANCE_DEVICE_NOT_SUPPORT, LINK_ENHANCE_DESCRIPTION);
    }
    explicit ConnectionImpl(const std::string deviceId, const std::string name)
    {
        this->deviceId_ = deviceId;
        this->name_ = name;
    }
    void Connect()
    {
        taihe::set_business_error(LINK_ENHANCE_DEVICE_NOT_SUPPORT, LINK_ENHANCE_DESCRIPTION);
    }

    void Disconnect()
    {
        taihe::set_business_error(LINK_ENHANCE_DEVICE_NOT_SUPPORT, LINK_ENHANCE_DESCRIPTION);
    }

    void Close()
    {
        taihe::set_business_error(LINK_ENHANCE_DEVICE_NOT_SUPPORT, LINK_ENHANCE_DESCRIPTION);
    }

    ::taihe::string GetPeerDeviceId()
    {
        taihe::set_business_error(LINK_ENHANCE_DEVICE_NOT_SUPPORT, LINK_ENHANCE_DESCRIPTION);
        return taihe::string("");
    }

    void SendData(::taihe::array_view<uint8_t> data)
    {
        taihe::set_business_error(LINK_ENHANCE_DEVICE_NOT_SUPPORT, LINK_ENHANCE_DESCRIPTION);
    }

    void OnConnectResult(::taihe::callback_view<void(
        ::ohos::distributedsched::linkEnhance::ConnectResult const& connectResult)> callback)
    {
        taihe::set_business_error(LINK_ENHANCE_DEVICE_NOT_SUPPORT, LINK_ENHANCE_DESCRIPTION);
    }

    void OffConnectResult(::taihe::optional_view<::taihe::callback<void(
        ::ohos::distributedsched::linkEnhance::ConnectResult const& connectResult)>> callback)
    {
        taihe::set_business_error(LINK_ENHANCE_DEVICE_NOT_SUPPORT, LINK_ENHANCE_DESCRIPTION);
    }
    
    void OnDisconnected(::taihe::callback_view<void(int32_t result)> callback)
    {
        taihe::set_business_error(LINK_ENHANCE_DEVICE_NOT_SUPPORT, LINK_ENHANCE_DESCRIPTION);
    }

    void OffDisconnected(::taihe::optional_view<::taihe::callback<void(int32_t result)>> callback)
    {
        taihe::set_business_error(LINK_ENHANCE_DEVICE_NOT_SUPPORT, LINK_ENHANCE_DESCRIPTION);
    }

    void OnDataReceived(::taihe::callback_view<void(::taihe::array_view<uint8_t> arrayBuffer)> callback)
    {
        taihe::set_business_error(LINK_ENHANCE_DEVICE_NOT_SUPPORT, LINK_ENHANCE_DESCRIPTION);
    }

    void OffDataReceived(::taihe::optional_view<::taihe::callback<void(
        ::taihe::array_view<uint8_t> arrayBuffer)>> callback)
    {
        taihe::set_business_error(LINK_ENHANCE_DEVICE_NOT_SUPPORT, LINK_ENHANCE_DESCRIPTION);
    }

    int64_t GetConnectionImpl()
    {
        return reinterpret_cast<int64_t>(this);
    }
    
    std::string deviceId_ = "";
    std::string name_ = "";
    
private:
    std::recursive_timed_mutex lock_;
};

::ohos::distributedsched::linkEnhance::Server CreateServer(::taihe::string_view name)
{
    taihe::set_business_error(LINK_ENHANCE_DEVICE_NOT_SUPPORT, LINK_ENHANCE_DESCRIPTION);
    auto server = taihe::make_holder<ServerImpl,
    ::ohos::distributedsched::linkEnhance::Server>((const std::string) name);
    return server;
}

::ohos::distributedsched::linkEnhance::Connection CreateConnection(
    ::taihe::string_view deviceId, ::taihe::string_view name)
{
    taihe::set_business_error(LINK_ENHANCE_DEVICE_NOT_SUPPORT, LINK_ENHANCE_DESCRIPTION);
    auto connection = taihe::make_holder<ConnectionImpl,
    ::ohos::distributedsched::linkEnhance::Connection>((const std::string)deviceId, (const std::string)name);
    return connection;
}

int32_t Init()
{
    return ANI_OK;
}
}
}

TH_EXPORT_CPP_API_CreateServer(Communication::OHOS::Softbus::CreateServer);
TH_EXPORT_CPP_API_CreateConnection(Communication::OHOS::Softbus::CreateConnection);