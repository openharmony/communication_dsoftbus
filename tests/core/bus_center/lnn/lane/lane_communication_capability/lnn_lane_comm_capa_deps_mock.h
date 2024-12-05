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

#ifndef LNN_LANE_COMM_CAPA_DEPS_MOCK_H
#define LNN_LANE_COMM_CAPA_DEPS_MOCK_H

#include <gmock/gmock.h>

#include "lnn_lane_link.h"

namespace OHOS {
class LaneCommCapaDepsInterface {
public:
    LaneCommCapaDepsInterface() {};
    virtual ~LaneCommCapaDepsInterface() {};

    virtual int32_t LnnGetLocalNumU64Info(InfoKey key, uint64_t *info) = 0;
    virtual int32_t LnnGetRemoteNumU64Info(const char *networkId, InfoKey key, uint64_t *info) = 0;
    virtual int32_t LnnGetRemoteNodeInfoById(const char *id, IdCategory type, NodeInfo *info) = 0;
    virtual bool LnnHasDiscoveryType(const NodeInfo *info, DiscoveryType type) = 0;
};

class LaneCommCapaDepsInterfaceMock : public LaneCommCapaDepsInterface {
public:
    LaneCommCapaDepsInterfaceMock();
    ~LaneCommCapaDepsInterfaceMock() override;

    MOCK_METHOD2(LnnGetLocalNumU64Info, int32_t (InfoKey, uint64_t *));
    MOCK_METHOD3(LnnGetRemoteNumU64Info, int32_t (const char *, InfoKey, uint64_t *));
    MOCK_METHOD3(LnnGetRemoteNodeInfoById, int32_t (const char *, IdCategory, NodeInfo *));
    MOCK_METHOD2(LnnHasDiscoveryType, bool (const NodeInfo *, DiscoveryType));
};
} // namespace OHOS
#endif // LNN_LANE_COMM_CAPA_DEPS_MOCK_H
