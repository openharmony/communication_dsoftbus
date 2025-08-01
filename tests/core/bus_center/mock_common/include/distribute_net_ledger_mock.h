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

#ifndef DISTRIBUTE_NET_LEDGER_MOCK_H
#define DISTRIBUTE_NET_LEDGER_MOCK_H

#include <gmock/gmock.h>
#include <mutex>

#include "bus_center_manager.h"
#include "lnn_distributed_net_ledger.h"

namespace OHOS {
class DistributeLedgerInterface {
public:
    DistributeLedgerInterface() {};
    virtual ~DistributeLedgerInterface() {};

    virtual int32_t LnnGetDLHeartbeatTimestamp(const char *networkId, uint64_t *timestamp) = 0;
    virtual int32_t LnnSetDLHeartbeatTimestamp(const char *networkId, const uint64_t timestamp) = 0;
    virtual int32_t LnnGetRemoteStrInfo(const char *netWorkId, InfoKey key, char *info, uint32_t len) = 0;
    virtual bool LnnGetOnlineStateById(const char *id, IdCategory type) = 0;
    virtual int32_t LnnGetRemoteStrInfoByIfnameIdx(const char *netWorkId, InfoKey key, char *info,
        uint32_t len, int32_t ifIdx) = 0;
    virtual int32_t LnnGetRemoteNumInfoByIfnameIdx(const char *netWorkId, InfoKey key, int32_t *info,
        int32_t ifIdx) = 0;
    virtual int32_t LnnGetRemoteNumU32Info(const char *networkId, InfoKey key, uint32_t *info) = 0;
    virtual int32_t LnnGetRemoteNumInfo(const char *netWorkId, InfoKey key, int32_t *info) = 0;
    virtual int32_t LnnGetRemoteNum16Info(const char *networkId, InfoKey key, int16_t *info) = 0;
    virtual int32_t LnnGetRemoteBoolInfo(const char *networkId, InfoKey key, bool *info) = 0;
    virtual int32_t LnnGetRemoteNumU64Info(const char *networkId, InfoKey key, uint64_t *info) = 0;
    virtual const char *LnnConvertDLidToUdid(const char *id, IdCategory type) = 0;
    virtual int32_t ConvertBtMacToBinary(const char *, uint32_t, uint8_t *, uint32_t) = 0;
    virtual int32_t LnnGetDLSleHbTimestamp(const char *networkId, uint64_t *timestamp) = 0;
    virtual int32_t LnnSetDLSleHbTimestamp(const char *networkId, const uint64_t timestamp) = 0;
};
class DistributeLedgerInterfaceMock : public DistributeLedgerInterface {
public:
    DistributeLedgerInterfaceMock();
    ~DistributeLedgerInterfaceMock() override;

    MOCK_METHOD2(LnnGetDLHeartbeatTimestamp, int32_t(const char *, uint64_t *));
    MOCK_METHOD2(LnnSetDLHeartbeatTimestamp, int32_t(const char *, const uint64_t));
    MOCK_METHOD4(LnnGetRemoteStrInfo, int32_t(const char *, InfoKey, char *, uint32_t));
    MOCK_METHOD5(LnnGetRemoteStrInfoByIfnameIdx, int32_t(const char *, InfoKey, char *, uint32_t, int32_t));
    MOCK_METHOD4(LnnGetRemoteNumInfoByIfnameIdx, int32_t (const char *, InfoKey, int32_t *, int32_t));
    MOCK_METHOD3(LnnGetRemoteNumU32Info, int32_t (const char *, InfoKey, uint32_t *));
    MOCK_METHOD3(LnnGetRemoteNumInfo, int32_t (const char*, InfoKey, int32_t*));
    MOCK_METHOD3(LnnGetRemoteNum16Info, int32_t (const char*, InfoKey, int16_t*));
    MOCK_METHOD3(LnnGetRemoteBoolInfo, int32_t (const char *, InfoKey, bool *));
    MOCK_METHOD3(LnnGetRemoteNumU64Info, int32_t(const char *, InfoKey, uint64_t *));
    MOCK_METHOD2(LnnGetOnlineStateById, bool(const char *, IdCategory));
    MOCK_METHOD2(LnnConvertDLidToUdid, const char *(const char *, IdCategory));
    MOCK_METHOD4(ConvertBtMacToBinary, int32_t(const char *, uint32_t, uint8_t *, uint32_t));
    MOCK_METHOD2(LnnGetDLSleHbTimestamp, int32_t(const char *, uint64_t *));
    MOCK_METHOD2(LnnSetDLSleHbTimestamp, int32_t(const char *, const uint64_t));
};
} // namespace OHOS
#endif // AUTH_CONNECTION_MOCK_H