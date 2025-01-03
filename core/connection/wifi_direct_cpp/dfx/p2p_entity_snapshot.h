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

#ifndef P2P_ENTITY_SNAPSHOT_H
#define P2P_ENTITY_SNAPSHOT_H

#include <list>
#include <nlohmann/json.hpp>
#include <string>

#include "entity/p2p_entity.h"
#include "wifi_direct_snapshot.h"

namespace OHOS::SoftBus {
class P2pEntity;
class P2pEntitySnapshot : WifiDirectSnapshot {
public:
    friend P2pEntity;
    void Marshalling(nlohmann::json &output) override;

private:
    std::string state_;
    int frequency_;
    std::string joiningClients_;
};
} // namespace OHOS::SoftBus
#endif