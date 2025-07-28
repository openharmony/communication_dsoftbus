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

#ifndef LNN_DECISION_DB_DEPS_MOCK_H
#define LNN_DECISION_DB_DEPS_MOCK_H

#include <gmock/gmock.h>

#include "lnn_distributed_net_ledger_common.h"
#include "lnn_distributed_net_ledger.h"
#include "lnn_node_info.h"

namespace OHOS {
class LnnDistributedNetLedgerManagerInterface {
public:
    LnnDistributedNetLedgerManagerInterface() {};
    virtual ~LnnDistributedNetLedgerManagerInterface() {};

    virtual NodeInfo *LnnGetNodeInfoById(const char *id, IdCategory type) = 0;
    virtual int32_t LnnSaveRemoteDeviceInfo(const NodeInfo *deviceInfo) = 0;
    virtual int32_t LnnSetWifiDirectAddr(NodeInfo *info, const char *wifiDirectAddr) = 0;
    virtual int32_t SoftBusGenerateStrHash(const unsigned char *str, uint32_t len, unsigned char *hash) = 0;
    virtual int32_t ConvertBytesToHexString(
        char *outBuf, uint32_t outBufLen, const unsigned char *inBuf, uint32_t inLen) = 0;
    virtual bool LnnIsNodeOnline(const NodeInfo *info) = 0;
    virtual NodeInfo *GetNodeInfoFromMap(const DoubleHashMap *map, const char *id) = 0;
    virtual int32_t LnnRetrieveDeviceInfo(const char *udidHash, NodeInfo *deviceInfo) = 0;
};

class LnnDistributedNetLedgerManagerInterfaceMock : public LnnDistributedNetLedgerManagerInterface {
public:
    LnnDistributedNetLedgerManagerInterfaceMock();
    ~LnnDistributedNetLedgerManagerInterfaceMock() override;

    MOCK_METHOD2(LnnGetNodeInfoById, NodeInfo *(const char *, IdCategory));
    MOCK_METHOD1(LnnSaveRemoteDeviceInfo, int32_t(const NodeInfo *));
    MOCK_METHOD2(LnnSetWifiDirectAddr, int32_t(NodeInfo *, const char *));
    MOCK_METHOD3(SoftBusGenerateStrHash, int32_t(const unsigned char *, uint32_t, unsigned char *));
    MOCK_METHOD4(ConvertBytesToHexString, int32_t(char *, uint32_t, const unsigned char *, uint32_t));
    MOCK_METHOD1(LnnIsNodeOnline, bool(const NodeInfo *));
    MOCK_METHOD2(GetNodeInfoFromMap, NodeInfo *(const DoubleHashMap *, const char *));
    MOCK_METHOD2(LnnRetrieveDeviceInfo, int32_t(const char *, NodeInfo *));
};
extern "C" {
    int32_t LnnSaveRemoteDeviceInfo(const NodeInfo *deviceInfo);
    NodeInfo *LnnGetNodeInfoById(const char *id, IdCategory type);
}
} // namespace OHOS
#endif // LNN_DECISION_DB_DEPS_MOCK_H
