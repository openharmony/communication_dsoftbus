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
#include "net_conn_client.h"

int32_t OHOS::NetManagerStandard::NetConnClient::AddStaticArp(
    const std::string &ipAddr, const std::string &macAddr, const std::string &ifName)
{
    auto mock = OHOS::NetManagerStandard::MockNetConnClient::GetMock();
    if (mock == nullptr) {
        return -1;
    }
    return mock->AddStaticArp(ipAddr, macAddr, ifName);
}

int32_t OHOS::NetManagerStandard::NetConnClient::DelStaticArp(
    const std::string &ipAddr, const std::string &macAddr, const std::string &ifName)
{
    auto mock = OHOS::NetManagerStandard::MockNetConnClient::GetMock();
    if (mock == nullptr) {
        return -1;
    }
    return mock->DelStaticArp(ipAddr, macAddr, ifName);
}

int32_t OHOS::NetManagerStandard::NetConnClient::AddNetworkRoute(
    int32_t netId, const std::string &ifName, const std::string &destination, const std::string &nextHop)
{
    auto mock = OHOS::NetManagerStandard::MockNetConnClient::GetMock();
    if (mock == nullptr) {
        return -1;
    }
    return mock->AddNetworkRoute(netId, ifName, destination, nextHop);
}

int32_t OHOS::NetManagerStandard::NetConnClient::RemoveNetworkRoute(
    int32_t netId, const std::string &ifName, const std::string &destination, const std::string &nextHop)
{
    auto mock = OHOS::NetManagerStandard::MockNetConnClient::GetMock();
    if (mock == nullptr) {
        return -1;
    }
    return mock->RemoveNetworkRoute(netId, ifName, destination, nextHop);
}

int32_t OHOS::NetManagerStandard::NetConnClient::AddInterfaceAddress(
    const std::string &ifName, const std::string &ipAddr, int32_t prefixLength)
{
    auto mock = OHOS::NetManagerStandard::MockNetConnClient::GetMock();
    if (mock == nullptr) {
        return -1;
    }
    return mock->AddInterfaceAddress(ifName, ipAddr, prefixLength);
}

int32_t OHOS::NetManagerStandard::NetConnClient::DelInterfaceAddress(
    const std::string &ifName, const std::string &ipAddr, int32_t prefixLength)
{
    auto mock = OHOS::NetManagerStandard::MockNetConnClient::GetMock();
    if (mock == nullptr) {
        return -1;
    }
    return mock->DelInterfaceAddress(ifName, ipAddr, prefixLength);
}

namespace OHOS::NetManagerStandard {
MockNetConnClient::MockNetConnClient()
{
    mock.store(this);
}

MockNetConnClient::~MockNetConnClient()
{
    mock.store(nullptr);
}
} // namespace OHOS::NetManagerStandard