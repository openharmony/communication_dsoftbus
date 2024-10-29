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

#ifndef LNN_LANE_QUERY_DEPS_MOCK_H
#define LNN_LANE_QUERY_DEPS_MOCK_H

#include <gmock/gmock.h>

#include "bus_center_manager.h"
#include "lnn_distributed_net_ledger.h"
#include "lnn_feature_capability.h"
#include "softbus_wifi_api_adapter.h"
#include "wifi_direct_manager.h"

namespace OHOS {
class LaneQueryDepsInterface {
public:
    LaneQueryDepsInterface() {};
    virtual ~LaneQueryDepsInterface() {};

    virtual int32_t LnnGetRemoteNodeInfoById(const char *id, IdCategory type, NodeInfo *info) = 0;
    virtual bool LnnHasDiscoveryType(const NodeInfo *info, DiscoveryType type) = 0;
    virtual struct WifiDirectManager* GetWifiDirectManager(void) = 0;
    virtual int32_t LnnGetRemoteNumU32Info(const char *networkId, InfoKey key, uint32_t *info) = 0;
    virtual int32_t LnnGetLocalNumU32Info(InfoKey key, uint32_t *info) = 0;
    virtual SoftBusWifiDetailState SoftBusGetWifiState(void) = 0;
    virtual bool SoftBusIsWifiActive(void) = 0;
    virtual bool IsFeatureSupport(uint64_t feature, FeatureCapability capaBit) = 0;
    virtual int32_t LnnGetRemoteBoolInfo(const char *networkId, InfoKey key, bool *info) = 0;
    virtual uint64_t LnnGetFeatureCapabilty(void) = 0;
    virtual bool LnnGetOnlineStateById(const char *id, IdCategory type) = 0;
};

class LaneQueryDepsInterfaceMock : public LaneQueryDepsInterface {
public:
    LaneQueryDepsInterfaceMock();
    ~LaneQueryDepsInterfaceMock() override;

    MOCK_METHOD3(LnnGetRemoteNodeInfoById, int32_t (const char *id, IdCategory type, NodeInfo *info));
    MOCK_METHOD2(LnnHasDiscoveryType, bool (const NodeInfo *info, DiscoveryType type));
    MOCK_METHOD0(GetWifiDirectManager, struct WifiDirectManager* (void));
    MOCK_METHOD3(LnnGetRemoteNumU32Info, int32_t (const char *networkId, InfoKey key, uint32_t *info));
    MOCK_METHOD2(LnnGetLocalNumU32Info, int32_t (InfoKey key, uint32_t *info));
    MOCK_METHOD0(SoftBusGetWifiState, SoftBusWifiDetailState (void));
    MOCK_METHOD0(SoftBusIsWifiActive, bool (void));
    MOCK_METHOD2(IsFeatureSupport, bool (uint64_t feature, FeatureCapability capaBit));
    MOCK_METHOD3(LnnGetRemoteBoolInfo, int32_t (const char *networkId, InfoKey key, bool *info));
    MOCK_METHOD0(LnnGetFeatureCapabilty, uint64_t (void));
    MOCK_METHOD2(LnnGetOnlineStateById, bool(const char *, IdCategory));
};
} // namespace OHOS
#endif // LNN_LANE_QUERY_DEPS_MOCK_H