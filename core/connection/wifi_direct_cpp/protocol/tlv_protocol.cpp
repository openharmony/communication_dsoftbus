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
#include "tlv_protocol.h"
#include "conn_log.h"
#include "utils/wifi_direct_utils.h"

namespace OHOS::SoftBus {
void TlvProtocol::SetFormat(const ProtocolFormat &format)
{
    format_ = format;
}

ProtocolFormat TlvProtocol::GetFormat() const
{
    return format_;
}

void TlvProtocol::Write(int key, Serializable::ValueType type, const uint8_t *value, size_t size)
{
    CONN_CHECK_AND_RETURN_LOGW(value != nullptr, CONN_WIFI_DIRECT, "invalid param, value is null");
    if (size == 0) {
        return;
    }

    std::vector<uint8_t> tagVector;
    WifiDirectUtils::IntToBytes(key, format_.tagSize, tagVector);
    data_.insert(data_.end(), tagVector.begin(), tagVector.end());

    std::vector<uint8_t> lengthVector;
    WifiDirectUtils::IntToBytes(size, format_.lengthSize, lengthVector);
    data_.insert(data_.end(), lengthVector.begin(), lengthVector.end());

    data_.insert(data_.end(), value, value + size);
}

bool TlvProtocol::Read(int &key, uint8_t *&value, size_t &size)
{
    if (data_.size() - readPos_ < format_.tagSize + format_.lengthSize) {
        return false;
    }

    key = (int)WifiDirectUtils::BytesToInt(data_.data() + readPos_, format_.tagSize);
    readPos_ += format_.tagSize;
    size = WifiDirectUtils::BytesToInt(data_.data() + readPos_, format_.lengthSize);
    readPos_ += format_.lengthSize;
    if (readPos_ >= data_.size() || data_.size() - readPos_ < size) {
        CONN_LOGE(CONN_WIFI_DIRECT, "readPos is invalid. readPos=%{public}zu", readPos_);
        return false;
    }
    value = data_.data() + readPos_;
    readPos_ += size;
    return true;
}

void TlvProtocol::SetInput(const std::vector<uint8_t> &input)
{
    data_ = input;
}

void TlvProtocol::GetOutput(std::vector<uint8_t> &output)
{
    output = data_;
}
}
