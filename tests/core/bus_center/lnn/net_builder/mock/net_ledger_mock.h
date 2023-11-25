/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#ifndef NET_LEDGER_MOCK_H
#define NET_LEDGER_MOCK_H

#include <gmock/gmock.h>

#include "lnn_node_info.h"

namespace OHOS {
class NetLedgerInterface {
public:
    NetLedgerInterface() {};
    virtual ~NetLedgerInterface() {};

    virtual int32_t LnnSetP2pRole(NodeInfo *info, int32_t role) = 0;
    virtual int32_t LnnSetP2pMac(NodeInfo *info, const char *p2pMac) = 0;
    virtual int32_t LnnSetP2pGoMac(NodeInfo *info, const char *goMac) = 0;
    virtual int32_t LnnGetAllOnlineAndMetaNodeInfo(NodeBasicInfo **info, int32_t *infoNum) = 0;
    virtual int32_t LnnSetWifiDirectAddr(NodeInfo *info, const char *wifiDirectAddr) = 0;
};
class NetLedgerMock : public NetLedgerInterface {
public:
    NetLedgerMock();
    ~NetLedgerMock() override;
    MOCK_METHOD(int32_t, LnnSetP2pRole, (NodeInfo *, int32_t), (override));
    MOCK_METHOD(int32_t, LnnSetP2pMac, (NodeInfo *, const char *), (override));
    MOCK_METHOD(int32_t, LnnSetP2pGoMac, (NodeInfo *, const char *), (override));
    MOCK_METHOD(int32_t, LnnGetAllOnlineAndMetaNodeInfo, (NodeBasicInfo **, int32_t *), (override));
    MOCK_METHOD(int32_t, LnnSetWifiDirectAddr, (NodeInfo *, const char *), (override));

    void SetupDefaultResult();
};
} // namespace OHOS
#endif // NET_LEDGER_MOCK_H