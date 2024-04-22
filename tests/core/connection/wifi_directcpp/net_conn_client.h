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

#ifndef NET_CONN_CLIENT
#define NET_CONN_CLIENT
#include <atomic>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <cstdint>
#include <string>

namespace OHOS::NetManagerStandard {
class NetConnClient {
public:
    NetConnClient() = default;
    virtual ~NetConnClient() = default;
    static NetConnClient &GetInstance()
    {
        static NetConnClient client;
        return client;
    }

    virtual int32_t AddStaticArp(const std::string &ipAddr, const std::string &macAddr, const std::string &ifName);
    virtual int32_t DelStaticArp(const std::string &ipAddr, const std::string &macAddr, const std::string &ifName);
    virtual int32_t AddNetworkRoute(
        int32_t netId, const std::string &ifName, const std::string &destination, const std::string &nextHop);
    virtual int32_t RemoveNetworkRoute(
        int32_t netId, const std::string &ifName, const std::string &destination, const std::string &nextHop);
    virtual int32_t AddInterfaceAddress(const std::string &ifName, const std::string &ipAddr, int32_t prefixLength);
    virtual int32_t DelInterfaceAddress(const std::string &ifName, const std::string &ipAddr, int32_t prefixLength);
};

class MockNetConnClient : public NetManagerStandard::NetConnClient {
public:
    MockNetConnClient();
    ~MockNetConnClient() override;
    MOCK_METHOD3(
        AddStaticArp, int32_t(const std::string &ipAddr, const std::string &macAddr, const std::string &ifName));
    MOCK_METHOD3(
        AddInterfaceAddress, int32_t(const std::string &ifName, const std::string &ipAddr, int32_t prefixLength));
    MOCK_METHOD3(
        DelStaticArp, int32_t(const std::string &ipAddr, const std::string &macAddr, const std::string &ifName));
    MOCK_METHOD4(AddNetworkRoute,
        int32_t(int32_t netId, const std::string &ifName, const std::string &destination, const std::string &nextHop));
    MOCK_METHOD3(
        DelInterfaceAddress, int32_t(const std::string &ifName, const std::string &ipAddr, int32_t prefixLength));

    MOCK_METHOD4(RemoveNetworkRoute,
        int32_t(int32_t netId, const std::string &ifName, const std::string &destination, const std::string &nextHop));

    static MockNetConnClient *GetMock()
    {
        return mock.load();
    }

private:
    static inline std::atomic<MockNetConnClient *> mock = nullptr;
};
} // namespace OHOS::NetManagerStandard
#endif
