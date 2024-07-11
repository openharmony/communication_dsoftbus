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
#ifndef ENTITY_FACTORY_H
#define ENTITY_FACTORY_H

#include <functional>

#include "data/inner_link.h"
#include "entity/p2p_entity.h"
#include "entity/wifi_direct_entity.h"

namespace OHOS::SoftBus {
class EntityFactory {
public:
    static EntityFactory& GetInstance()
    {
        static EntityFactory instance;
        return instance;
    }

    using Creator = std::function<WifiDirectEntity&(InnerLink::LinkType)>;
    void Register(const Creator &creator)
    {
        creator_ = creator;
    }

    WifiDirectEntity& GetEntity(InnerLink::LinkType type)
    {
        if (creator_ == nullptr) {
            return P2pEntity::GetInstance();
        }
        return creator_(type);
    }

private:
    EntityFactory() = default;
    Creator creator_;
};
}
#endif
