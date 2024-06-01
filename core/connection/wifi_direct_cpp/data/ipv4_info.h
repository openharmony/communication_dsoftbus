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
#ifndef WIFI_DIRECT_IPV4_INFO_H
#define WIFI_DIRECT_IPV4_INFO_H

#include "serializable.h"

namespace OHOS::SoftBus {
static constexpr int DEFAULT_PREFIX_VALUE = 24;
static constexpr int SUBNET_SHIFT = 8;

class Ipv4Info {
public:
    Ipv4Info() = default;
    explicit Ipv4Info(const std::string &ip);
    ~Ipv4Info() = default;
    bool operator==(const Ipv4Info &other) const;

    int Marshalling(std::vector<uint8_t> &output) const;
    int Unmarshalling(const uint8_t *input, size_t size);

    int FromIpString(const std::string &ipString);
    std::string ToIpString() const;
    uint32_t GetSubNet() const;
    void SetIp(uint32_t ip)
    {
        ip_ = ip;
    }
    void SetPrefixLength(int32_t prefixLen)
    {
        prefixLength_ = prefixLen;
    }
    int32_t GetPrefixLength() const
    {
        return prefixLength_;
    }

    static constexpr int Ipv4InfoSize() { return sizeof(ip_) + sizeof(prefixLength_); }

private:
    uint32_t ip_ {}; /* net order */
    uint8_t prefixLength_ { DEFAULT_PREFIX_VALUE };
};
}
#endif
