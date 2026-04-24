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

#ifndef LNN_HEARTBEAT_DEVICE_RISK_MOCK_H
#define LNN_HEARTBEAT_DEVICE_RISK_MOCK_H

#include <gmock/gmock.h>
#include <securec.h>
#include <cstdlib>
#include "cJSON.h"

#include "bus_center_adapter.h"
#include "bus_center_manager_struct.h"
#include "lnn_connection_fsm_struct.h"
#include "lnn_decision_db_struct.h"
#include "lnn_distributed_net_ledger_struct.h"
#include "lnn_net_builder_struct.h"
#include "lnn_node_info_struct.h"
#include "softbus_adapter_mem.h"
#include "softbus_bus_center.h"
#include "softbus_error_code.h"

namespace OHOS {
class LnnHeatbeatDeviceRiskInterface {
public:
    LnnHeatbeatDeviceRiskInterface() {};
    virtual ~LnnHeatbeatDeviceRiskInterface() {};

    virtual int32_t LnnRequestLeaveSpecific(const char *networkId, ConnectionAddrType addrType,
        DeviceLeaveReason leaveReason) = 0;
    virtual int32_t LnnGetAllOnlineNodeInfo(NodeBasicInfo **info, int32_t *infoNum) = 0;
    virtual int32_t LnnGetRemoteNodeInfoById(const char *id, IdCategory type, NodeInfo *info) = 0;
};

class LnnHeatbeatDeviceRiskInterfaceMock : public LnnHeatbeatDeviceRiskInterface {
public:
    LnnHeatbeatDeviceRiskInterfaceMock();
    ~LnnHeatbeatDeviceRiskInterfaceMock() override;
    MOCK_METHOD2(LnnGetAllOnlineNodeInfo, int32_t(NodeBasicInfo **, int32_t *));
    MOCK_METHOD3(LnnRequestLeaveSpecific, int32_t(const char *, ConnectionAddrType, DeviceLeaveReason));
    MOCK_METHOD3(LnnGetRemoteNodeInfoById, int32_t(const char *id, IdCategory type, NodeInfo *info));
};
} // namespace OHOS
#endif // LNN_HEARTBEAT_SATIC_MOCK_H