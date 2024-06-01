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
enum {
    NETMANAGER_ERR_PERMISSION_DENIED = 201,
    NETMANAGER_ERR_NOT_SYSTEM_CALL = 202,
    NETMANAGER_ERR_PARAMETER_ERROR = 401,
    NETMANAGER_ERR_CAPABILITY_NOT_SUPPORTED = 801,
    NETMANAGER_SUCCESS = 0,
    NETMANAGER_ERR_INVALID_PARAMETER = 2100001,
    NETMANAGER_ERR_OPERATION_FAILED = 2100002,
    NETMANAGER_ERR_INTERNAL = 2100003,
    NETMANAGER_ERR_MEMCPY_FAIL = 2100101,
    NETMANAGER_ERR_MEMSET_FAIL = 2100102,
    NETMANAGER_ERR_STRCPY_FAIL = 2100103,
    NETMANAGER_ERR_STRING_EMPTY = 2100104,
    NETMANAGER_ERR_LOCAL_PTR_NULL = 2100105,
    NETMANAGER_ERR_DESCRIPTOR_MISMATCH = 2100201,
    NETMANAGER_ERR_WRITE_DESCRIPTOR_TOKEN_FAIL = 2100202,
    NETMANAGER_ERR_WRITE_DATA_FAIL = 2100203,
    NETMANAGER_ERR_WRITE_REPLY_FAIL = 2100204,
    NETMANAGER_ERR_READ_DATA_FAIL = 2100205,
    NETMANAGER_ERR_READ_REPLY_FAIL = 2100206,
    NETMANAGER_ERR_IPC_CONNECT_STUB_FAIL = 2100207,
    NETMANAGER_ERR_GET_PROXY_FAIL = 2100208,
    NETMANAGER_ERR_STATUS_EXIST = 2100209,
};
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
