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
#ifndef WIFI_DIRECT_PROTOCOL_H
#define WIFI_DIRECT_PROTOCOL_H

#include <string>
#include <vector>
#include "data/serializable.h"

namespace OHOS::SoftBus {
struct ProtocolFormat {
    uint32_t tagSize;
    uint32_t lengthSize;
};

enum class ProtocolType {
    JSON,
    TLV,
};

class WifiDirectProtocol {
public:
    virtual ProtocolType GetType() = 0;
    virtual void SetFormat(const ProtocolFormat &format) = 0;
    virtual ProtocolFormat GetFormat() const = 0;

    virtual void Write(int key, Serializable::ValueType type, const uint8_t *value, size_t size) = 0;
    virtual bool Read(int &key, uint8_t *&value, size_t &size) = 0;

    virtual void SetInput(const std::vector<uint8_t> &input) = 0;
    virtual void GetOutput(std::vector<uint8_t> &output) = 0;

    virtual ~WifiDirectProtocol() = default;
};
}
#endif
