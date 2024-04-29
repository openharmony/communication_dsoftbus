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

#ifndef INFO_CONTAINER_H
#define INFO_CONTAINER_H

#include <map>

#include "serializable.h"

namespace OHOS::SoftBus {
template<typename Key>
class InfoContainer {
protected:
    void Set(Key key, const std::any &value)
    {
        values_[key] = value;
    }

    template<typename T>
    T Get(Key key, const T &defaultValue) const
    {
        const auto it = values_.find(key);
        return it != values_.end() ? std::any_cast<T>(it->second) : defaultValue;
    }

    using KeyTypeTable = std::map<Key, Serializable::ValueType>;

    static KeyTypeTable keyTypeTable_;
    std::map<Key, std::any> values_;
};
}
#endif
