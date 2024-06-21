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

#include "ipv4_info.h"
#include "conn_log.h"
#include "softbus_common.h"
#include "softbus_error_code.h"
#include <arpa/inet.h>

namespace OHOS::SoftBus {
Ipv4Info::Ipv4Info(const std::string &ip)
{
    FromIpString(ip);
}

bool Ipv4Info::operator==(const Ipv4Info &other) const
{
    if (ip_ == other.ip_ && prefixLength_ == other.prefixLength_) {
        return true;
    }
    return false;
}

int Ipv4Info::Marshalling(std::vector<uint8_t> &output) const
{
    auto ip = ntohl(ip_);
    auto p = reinterpret_cast<uint8_t *>(&ip);
    output.insert(output.begin(), p, p + sizeof(ip));
    output.push_back(prefixLength_);
    return SOFTBUS_OK;
}

int Ipv4Info::Unmarshalling(const uint8_t *input, size_t size)
{
    if (size < Ipv4InfoSize()) {
        return SOFTBUS_INVALID_PARAM;
    }

    auto p = (uint8_t *)(&ip_);
    std::copy(input, input + sizeof(ip_), p);
    prefixLength_ = input[Ipv4InfoSize() - 1];
    ip_ = htonl(ip_);
    return SOFTBUS_OK;
}

int Ipv4Info::FromIpString(const std::string &ipString)
{
    if (ipString.empty()) {
        ip_ = 0;
        return SOFTBUS_OK;
    }
    if (inet_pton(AF_INET, ipString.c_str(), &ip_) != 1) {
        CONN_LOGW(CONN_WIFI_DIRECT, "inet_pton failed");
        return SOFTBUS_CONN_INET_PTON_FAILED;
    }
    ip_ = htonl(ip_);
    return SOFTBUS_OK;
}

std::string Ipv4Info::ToIpString() const
{
    if (ip_ == 0) {
        return "";
    }
    uint32_t ip = ntohl(ip_);
    char ipStr[IP_STR_MAX_LEN] {};
    const char *ret = inet_ntop(AF_INET, &ip, ipStr, IP_STR_MAX_LEN);
    CONN_CHECK_AND_RETURN_RET_LOGW(ret != nullptr, "", CONN_WIFI_DIRECT, "inet_ntop failed");
    return ipStr;
}

uint32_t Ipv4Info::GetSubNet() const
{
    return (ip_ >> SUBNET_SHIFT) & 0xFF;
}
} // namespace OHOS::SoftBus
