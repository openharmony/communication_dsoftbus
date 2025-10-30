
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

#ifndef LNN_DISTRIBUTED_NET_LEDGER_MOCK_H
#define LNN_DISTRIBUTED_NET_LEDGER_MOCK_H

#include <gmock/gmock.h>

#include "lnn_distributed_net_ledger.h"

namespace OHOS {
class LnnDistributedNetLedgerInterface {
public:
    LnnDistributedNetLedgerInterface() {}
    virtual ~LnnDistributedNetLedgerInterface() {}

    virtual void LnnNotifyBasicInfoChanged(const NodeBasicInfo *, NodeBasicInfoType) = 0;
    virtual void Anonymize(const char *, char **) = 0;
    virtual void AnonymizeFree(char *) = 0;
    virtual const char* AnonymizeWrapper(const char*) = 0;
    virtual int32_t SoftBusGenerateStrHash(const uint8_t *, uint32_t, uint8_t *) = 0;
    virtual int32_t ConvertBytesToHexString(char *, uint32_t, const uint8_t *, uint32_t) = 0;
    virtual int32_t LnnRetrieveDeviceInfoPacked(const char *, NodeInfo *) = 0;
    virtual int32_t LnnSaveRemoteDeviceInfoPacked(const NodeInfo *) = 0;
    virtual void LnnDumpRemotePtk(const char *, const char *, const char *) = 0;
    virtual void LnnInsertLinkFinderInfoPacked(const char *) = 0;
    virtual void NotifyForegroundUseridChange(const char *, DiscoveryType, bool) = 0;
    virtual int32_t LnnSetDLConnUserIdCheckSum(const char *, int32_t) = 0;
    virtual DiscoveryType ConvertToDiscoveryType(AuthLinkType) = 0;
    virtual const NodeInfo *LnnGetLocalNodeInfo(void) = 0;
    virtual int32_t ConnPreventConnection(const ConnectOption *, uint32_t) = 0;
    virtual void LnnNotifyMigrate(bool, const NodeBasicInfo *) = 0;
    virtual void UpdateProfile(NodeInfo *) = 0;
    virtual void InsertToProfile(NodeInfo *) = 0;
    virtual int64_t LnnUpTimeMs(void) = 0;
    virtual int32_t LnnGetLocalNum64Info(InfoKey, int64_t *) = 0;
    virtual int32_t GetActiveOsAccountIds(void) = 0;
    virtual bool LnnIsDefaultOhosAccount(void) = 0;
    virtual int32_t LnnFindDeviceUdidTrustedInfoFromDb(const char *) = 0;
    virtual bool DpHasAccessControlProfile(const char *, bool, int32_t) = 0;
    virtual void LnnInsertSpecificTrustedDevInfo(const char *) = 0;
    virtual uint32_t AuthGetGroupType(const char *, const char *) = 0;
    virtual DiscoveryType LnnConvAddrTypeToDiscType(ConnectionAddrType) = 0;
};

class LnnDistributedNetLedgerInterfaceMock : public LnnDistributedNetLedgerInterface {
public:
    LnnDistributedNetLedgerInterfaceMock();
    ~LnnDistributedNetLedgerInterfaceMock() override;

    MOCK_METHOD(void, LnnNotifyBasicInfoChanged, (const NodeBasicInfo *, NodeBasicInfoType), (override));
    MOCK_METHOD(void, Anonymize, (const char *, char **), (override));
    MOCK_METHOD(void, AnonymizeFree, (char *), (override));
    MOCK_METHOD(const char*, AnonymizeWrapper, (const char*), (override));
    MOCK_METHOD(int32_t, SoftBusGenerateStrHash, (const uint8_t *, uint32_t, uint8_t *), (override));
    MOCK_METHOD(int32_t, ConvertBytesToHexString, (char *, uint32_t, const uint8_t *, uint32_t), (override));
    MOCK_METHOD(int32_t, LnnRetrieveDeviceInfoPacked, (const char *, NodeInfo *), (override));
    MOCK_METHOD(int32_t, LnnSaveRemoteDeviceInfoPacked, (const NodeInfo *), (override));
    MOCK_METHOD(void, LnnDumpRemotePtk, (const char *, const char *, const char *), (override));
    MOCK_METHOD(void, LnnInsertLinkFinderInfoPacked, (const char *), (override));
    MOCK_METHOD(void, NotifyForegroundUseridChange, (const char *, DiscoveryType, bool), (override));
    MOCK_METHOD(int32_t, LnnSetDLConnUserIdCheckSum, (const char *, int32_t), (override));
    MOCK_METHOD(DiscoveryType, ConvertToDiscoveryType, (AuthLinkType), (override));
    MOCK_METHOD(const NodeInfo *, LnnGetLocalNodeInfo, (), (override));
    MOCK_METHOD(int32_t, ConnPreventConnection, (const ConnectOption *, uint32_t), (override));
    MOCK_METHOD(void, LnnNotifyMigrate, (bool, const NodeBasicInfo *), (override));
    MOCK_METHOD(void, UpdateProfile, (NodeInfo *), (override));
    MOCK_METHOD(void, InsertToProfile, (NodeInfo *), (override));
    MOCK_METHOD(int64_t, LnnUpTimeMs, (), (override));
    MOCK_METHOD(int32_t, LnnGetLocalNum64Info, (InfoKey, int64_t *), (override));
    MOCK_METHOD(int32_t, GetActiveOsAccountIds, (), (override));
    MOCK_METHOD(bool, LnnIsDefaultOhosAccount, (), (override));
    MOCK_METHOD(int32_t, LnnFindDeviceUdidTrustedInfoFromDb, (const char *), (override));
    MOCK_METHOD(bool, DpHasAccessControlProfile, (const char *, bool, int32_t), (override));
    MOCK_METHOD(void, LnnInsertSpecificTrustedDevInfo, (const char *), (override));
    MOCK_METHOD(uint32_t, AuthGetGroupType, (const char *, const char *), (override));
    MOCK_METHOD(DiscoveryType, LnnConvAddrTypeToDiscType, (ConnectionAddrType), (override));
};
} // namespace OHOS

#endif // LNN_DISTRIBUTED_NET_LEDGER_MOCK_H
