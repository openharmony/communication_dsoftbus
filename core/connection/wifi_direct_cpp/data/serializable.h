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
#ifndef WIFI_DIRECT_SERIALIZATION_H
#define WIFI_DIRECT_SERIALIZATION_H

#include <any>
#include <string>
#include <vector>

namespace OHOS::SoftBus {
class WifiDirectProtocol;
class Serializable {
public:
    enum class ValueType {
        BOOL = 0,
        INT = 1,
        UINT = 2,
        STRING = 3,
        BYTE_ARRAY = 4,
        INT_ARRAY = 5,
        IPV4_INFO = 6,
        IPV4_INFO_ARRAY = 7,
        INTERFACE_INFO_ARRAY = 8,
        LINK_INFO = 9,
        INNER_LINK = 10,
        BYTE = 11,
    };

    virtual int Marshalling(WifiDirectProtocol &protocol, std::vector<uint8_t> &output) const = 0;
    virtual int Unmarshalling(WifiDirectProtocol &protocol, const std::vector<uint8_t> &input) = 0;
    virtual ~Serializable() = default;
};
}
#endif
