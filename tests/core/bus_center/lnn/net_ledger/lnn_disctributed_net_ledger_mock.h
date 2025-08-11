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

#ifndef LNN_DISCTRIBUTED_NET_LEDGER_MOCK_H
#define LNN_DISCTRIBUTED_NET_LEDGER_MOCK_H

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "lnn_node_info_struct.h"

namespace OHOS {
class LnnDisctributedNetLedgerInterface {
public:
    LnnDisctributedNetLedgerInterface() {};
    virtual ~LnnDisctributedNetLedgerInterface() {};
    virtual int32_t LnnSaveRemoteDeviceInfo(const NodeInfo *deviceInfo) = 0;
    virtual int32_t LnnRetrieveDeviceInfo(const char *udid, NodeInfo *deviceInfo) = 0;
    virtual int32_t LnnFindDeviceUdidTrustedInfoFromDb(const char *udid) = 0;
};

class LnnDisctributedNetLedgerInterfaceMock : public LnnDisctributedNetLedgerInterface {
public:
    LnnDisctributedNetLedgerInterfaceMock();
    ~LnnDisctributedNetLedgerInterfaceMock() override;
    MOCK_METHOD1(LnnSaveRemoteDeviceInfo, int32_t (const NodeInfo *deviceInfo));
    MOCK_METHOD2(LnnRetrieveDeviceInfo, int32_t (const char *udid, NodeInfo *deviceInfo));
    MOCK_METHOD1(LnnFindDeviceUdidTrustedInfoFromDb, int32_t (const char *));
};
} // namespace OHOS
#endif // LNN_DISCTRIBUTED_NET_LEDGER_MOCK_H
