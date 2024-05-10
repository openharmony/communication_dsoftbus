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

#include <iostream>
#include "json_protocol.h"
#include "nlohmann/json.hpp"
#include "conn_log.h"
#include "data/negotiate_message.h"

namespace OHOS::SoftBus {
void JsonProtocol::SetFormat(const ProtocolFormat &format)
{
    format_ = format;
}

ProtocolFormat JsonProtocol::GetFormat() const
{
    return format_;
}

void JsonProtocol::Write(int key, Serializable::ValueType type, const uint8_t *value, size_t size)
{
    auto keyStr = NegotiateMessage::keyStringTable_[NegotiateMessageKey(key)];
    switch (type) {
        case Serializable::ValueType::BOOL:
            jsonObject_[keyStr] = *(bool *)value;
            break;
        case Serializable::ValueType::INT:
            jsonObject_[keyStr] = *(int32_t *)value;
            break;
        case Serializable::ValueType::STRING:
            jsonObject_[keyStr] = (char *)value;
            break;
        default:
            CONN_LOGE(CONN_WIFI_DIRECT, "invalid type=%{public}d", type);
    }
}

bool JsonProtocol::Read(int &key, uint8_t *&value, size_t &size)
{
    if (readPos_ == jsonObject_.end()) {
        CONN_LOGE(CONN_WIFI_DIRECT, "read to end");
        return false;
    }

    bool found = false;
    std::string jsonKey = readPos_.key();
    for (const auto& [intKey, strKey] : NegotiateMessage::keyStringTable_) {
        if (jsonKey == strKey) {
            key = static_cast<int>(intKey);
            found = true;
            break;
        }
    }
    if (!found) {
        CONN_LOGE(CONN_WIFI_DIRECT, "not find key=%{public}s", jsonKey.c_str());
        return false;
    }

    bool ret = true;
    switch ((*readPos_).type()) {
        case nlohmann::detail::value_t::boolean:
            *(bool *)data_ = *readPos_;
            value = data_;
            size = sizeof(bool);
            break;
        case nlohmann::detail::value_t::number_unsigned:
        case nlohmann::detail::value_t::number_integer:
            *(int *)data_ = *readPos_;
            value = data_;
            size = sizeof(int);
            break;
        case nlohmann::detail::value_t::string: {
            std::string orgValue = *readPos_;
            std::copy(orgValue.begin(), orgValue.end(), data_);
            value = data_;
            size = orgValue.length();
        }
            break;
        default:
            CONN_LOGE(CONN_WIFI_DIRECT, "invalid type");
            ret = false;
            break;
    }
    readPos_++;
    return ret;
}

void JsonProtocol::SetInput(const std::vector<uint8_t> &input)
{
    std::string inputString;
    inputString.insert(inputString.end(), input.begin(), input.end());
    jsonObject_ = nlohmann::json::parse(inputString, nullptr, false, false);
    readPos_ = jsonObject_.begin();
    if (jsonObject_.is_discarded()) {
        CONN_LOGE(CONN_WIFI_DIRECT, "parse json failed");
        readPos_ = jsonObject_.end();
    }
}

void JsonProtocol::GetOutput(std::vector<uint8_t> &output)
{
    std::string outputString = jsonObject_.dump();
    output.insert(output.end(), outputString.begin(), outputString.end());
}
}
