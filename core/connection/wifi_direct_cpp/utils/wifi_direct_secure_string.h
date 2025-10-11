/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef WIFI_DIRECT_SECURE_STRING_H
#define WIFI_DIRECT_SECURE_STRING_H

#include "securec.h"
#include <algorithm>
#include <cstring>
#include <string>
#include <vector>

class SecureString final {
public:
    SecureString() = default;

    explicit SecureString(const char *str)
    {
        if (str) {
            data_.assign(str, str + std::strlen(str));
        }
    }

    explicit SecureString(const std::string &str)
    {
        data_.assign(str.begin(), str.end());
    }

    [[nodiscard]] const char *Data() const
    {
        return data_.data();
    }

    [[nodiscard]] std::vector<char> VectorData() const
    {
        return data_;
    }

    void Append(const std::string &str)
    {
        data_.insert(data_.end(), str.begin(), str.end());
    }

    void Append(const std::vector<char> &vec)
    {
        data_.insert(data_.end(), vec.begin(), vec.end());
    }

    void PushBack(char c)
    {
        data_.push_back(c);
    }

    void Clear()
    {
        (void)memset_s(data_.data(), data_.size(), 0, data_.size());
        data_.clear();
        data_.shrink_to_fit();
    }

    ~SecureString()
    {
        Clear();
    }

    SecureString(const SecureString &) = delete;

    SecureString &operator=(const SecureString &) = delete;

    SecureString(SecureString &&other) noexcept : data_(std::move(other.data_))
    {
        other.Clear();
    }

    SecureString &operator=(SecureString &&other) noexcept
    {
        if (this != &other) {
            data_ = std::move(other.data_);
            other.Clear();
        }
        return *this;
    }

private:
    std::vector<char> data_;
};

#endif