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
#ifndef WIFI_DIRECT_JSON_PROTOCOL_H
#define WIFI_DIRECT_JSON_PROTOCOL_H

#include "data/serializable.h"
#include "protocol/wifi_direct_protocol.h"
#include "nlohmann/json.hpp"

namespace OHOS::SoftBus {
class JsonProtocol : public WifiDirectProtocol {
public:
    ProtocolType GetType() override { return ProtocolType::JSON; };
    void SetFormat(const ProtocolFormat &format) override;
    ProtocolFormat GetFormat() const override;

    void Write(int key, Serializable::ValueType type, const uint8_t *value, size_t size) override;
    bool Read(int &key, uint8_t *&value, size_t &size) override;

    void SetInput(const std::vector<uint8_t> &input) override;
    void GetOutput(std::vector<uint8_t> &output) override;

private:
    ProtocolFormat format_;
    nlohmann::json jsonObject_;
    nlohmann::json::iterator readPos_;
    static constexpr int DEFAULT_CAPACITY = 256;
    uint8_t data_[DEFAULT_CAPACITY];
};
}
#endif
