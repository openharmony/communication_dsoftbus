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

#include "lnn_distributed_net_ledger.h"
#include "lnn_node_info.h"
#include "softbus_wifi_api_adapter.h"

namespace OHOS {
class LaneCommCapaDepsInterface {
public:
    LaneCommCapaDepsInterface() {};
    virtual ~LaneCommCapaDepsInterface() {};

    virtual int32_t LnnGetLocalNumU32Info(InfoKey key, uint32_t *info) = 0;
    virtual int32_t LnnGetRemoteNumU32Info(const char *networkId, InfoKey key, uint32_t *info) = 0;
    virtual int32_t LnnGetRemoteNodeInfoById(const char *id, IdCategory type, NodeInfo *info) = 0;
    virtual bool LnnHasDiscoveryType(const NodeInfo *info, DiscoveryType type) = 0;
    virtual SoftBusWifiDetailState SoftBusGetWifiState(void) = 0;
    virtual int32_t LnnGetNetworkIdByUdid(const char *udid, char *buf, uint32_t len) = 0;
};

class LaneCommCapaDepsInterfaceMock : public LaneCommCapaDepsInterface {
public:
    LaneCommCapaDepsInterfaceMock();
    ~LaneCommCapaDepsInterfaceMock() override;

    MOCK_METHOD2(LnnGetLocalNumU32Info, int32_t (InfoKey, uint32_t *));
    MOCK_METHOD3(LnnGetRemoteNumU32Info, int32_t (const char *, InfoKey, uint32_t *));
    MOCK_METHOD3(LnnGetRemoteNodeInfoById, int32_t (const char *, IdCategory, NodeInfo *));
    MOCK_METHOD2(LnnHasDiscoveryType, bool (const NodeInfo *, DiscoveryType));
    MOCK_METHOD0(SoftBusGetWifiState, SoftBusWifiDetailState (void));
    MOCK_METHOD3(LnnGetNetworkIdByUdid, int32_t (const char *, char *, uint32_t));
};
} // namespace OHOS
#endif // LNN_LANE_COMM_CAPA_DEPS_MOCK_H
