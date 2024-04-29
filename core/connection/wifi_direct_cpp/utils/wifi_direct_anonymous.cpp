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
#include "wifi_direct_anonymous.h"
#include "wifi_direct_utils.h"

namespace OHOS::SoftBus {
static constexpr int MAC_ANONYMOUS_START = 6;
static constexpr int MAC_ANONYMOUS_END = 11;
static constexpr int DEVICE_ID_PREFIX_LEN = 4;
static constexpr int DEVICE_ID_SUFFIX_LEN = 4;
static constexpr int IPV6_START = 5;
static constexpr int IPV6_END = 15;

std::string WifiDirectAnonymizeMac(const std::string &mac)
{
    if (mac.empty()) {
        return "";
    }
    std::string result = mac;
    result.replace(MAC_ANONYMOUS_START, MAC_ANONYMOUS_END - MAC_ANONYMOUS_START, "**:**");
    return result;
}

std::string WifiDirectAnonymizeMac(const std::vector<uint8_t> &mac)
{
    return WifiDirectAnonymizeMac(WifiDirectUtils::MacArrayToString(mac));
}

std::string AnonymizeIpv4(const std::string &ip)
{
    if (ip.empty()) {
        return "";
    }
    std::string result = ip;
    auto s = result.find_first_of('.');
    if (s == std::string::npos) {
        return "";
    }
    auto e = result.find_last_of('.');
    if (e == s) {
        return "";
    }
    e = result.find_last_of('.', e - 1);
    if (e == s) {
        return "";
    }
    result.replace(s, e - s, "**");

    return result;
}

static std::string AnonymizeIpv6(const std::string &ip)
{
    if (ip.empty()) {
        return "";
    }
    auto result = ip;
    result.replace(IPV6_START, IPV6_END - IPV6_START, "***");
    return result;
}

std::string WifiDirectAnonymizeIp(const std::string &ip)
{
    if (ip.find(':') == std::string::npos) {
        return AnonymizeIpv4(ip);
    }
    return AnonymizeIpv6(ip);
}

std::string WifiDirectAnonymizeDeviceId(const std::string &deviceId)
{
    if (deviceId.empty()) {
        return "";
    }
    std::string result = deviceId;
    result.replace(DEVICE_ID_PREFIX_LEN, result.length() - DEVICE_ID_SUFFIX_LEN - DEVICE_ID_PREFIX_LEN, "**");
    return result;
}
}
