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
#ifndef WIFI_DIRECT_TLV_PROTOCOL_H
#define WIFI_DIRECT_TLV_PROTOCOL_H

#include "wifi_direct_protocol.h"

namespace OHOS::SoftBus {
class TlvProtocol : public WifiDirectProtocol {
public:
    ProtocolType GetType() override { return ProtocolType::TLV; };
    void SetFormat(const ProtocolFormat &format) override;
    ProtocolFormat GetFormat() const override;

    void Write(int key, Serializable::ValueType type, const uint8_t *value, size_t size) override;
    bool Read(int &key, uint8_t *&value, size_t &size) override;

    void SetInput(const std::vector<uint8_t> &input) override;
    void GetOutput(std::vector<uint8_t> &output) override;

    static constexpr int TLV_TAG_SIZE = 1;
    static constexpr int TLV_LENGTH_SIZE1 = 1;
    static constexpr int TLV_LENGTH_SIZE2 = 2;

private:
    size_t readPos_ = 0;
    std::vector<uint8_t> data_;
    ProtocolFormat format_ { TLV_TAG_SIZE, TLV_LENGTH_SIZE2 };
};
}

#endif
