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

#ifndef BUS_CENTER_DECISION_CENTER_MOCK_H
#define BUS_CENTER_DECISION_CENTER_MOCK_H

#include <gmock/gmock.h>
#include <mutex>

#include "bus_center_decision_center.h"
#include "bus_center_manager.h"
#include "lnn_connection_addr_utils.h"
#include "lnn_distributed_net_ledger.h"
#include "lnn_local_net_ledger.h"
#include "softbus_utils.h"

namespace OHOS {
class BusCenterDecisionCenterInterface {
public:
    BusCenterDecisionCenterInterface() {};
    virtual ~BusCenterDecisionCenterInterface() {};
    virtual int32_t LnnGetNetworkIdByBtMac(const char *btMac, char *buf, uint32_t len) = 0;
    virtual int32_t LnnGetRemoteNodeInfoById(const char *id, IdCategory type, NodeInfo *info) = 0;
};
class BusCenterDecisionCenterInterfaceMock : public BusCenterDecisionCenterInterface {
public:
    BusCenterDecisionCenterInterfaceMock();
    ~BusCenterDecisionCenterInterfaceMock() override;
    MOCK_METHOD3(LnnGetNetworkIdByBtMac, int32_t(const char *, char *, uint32_t));
    MOCK_METHOD3(LnnGetRemoteNodeInfoById, int32_t(const char *id, IdCategory type, NodeInfo *info));
};
} // namespace OHOS
#endif // BUS_CENTER_DECISION_CENTER_MOCK_H