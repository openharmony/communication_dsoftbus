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

#ifndef BUS_CENTER_EVENT_DEPS_MOCK_H
#define BUS_CENTER_EVENT_DEPS_MOCK_H

#include <gmock/gmock.h>

#include "bus_center_info_key.h"
#include "lnn_distributed_net_ledger.h"
#include "lnn_node_info.h"
#include "message_handler.h"
#include "softbus_common.h"
#include "softbus_utils.h"

namespace OHOS {
class BusCenterEventDepsInterface {
public:
    BusCenterEventDepsInterface() {};
    virtual ~BusCenterEventDepsInterface() {};

    virtual void Anonymize(const char *plainStr, char **anonymizedStr);
    virtual void AnonymizeFree(char *anonymizedStr);
    virtual int32_t SetDefaultQdisc(void);
    virtual int32_t LnnGetAllOnlineNodeNum(int32_t *nodeNum);
    virtual int32_t LnnGetLocalNum64Info(InfoKey key, int64_t *info);
    virtual int32_t LnnIpcNotifyDeviceNotTrusted(const char *msg);
    virtual int32_t LnnIpcNotifyJoinResult(void *addr, uint32_t addrTypeLen, const char *networkId,
        int32_t retCode);
    virtual int32_t LnnIpcNotifyLeaveResult(const char *networkId, int32_t retCode);
    virtual int32_t LnnIpcNotifyTimeSyncResult(const char *pkgName, int32_t pid, const void *info,
        uint32_t infoTypeLen, int32_t retCode);
    virtual int32_t LnnGetRemoteNodeInfoById(const char *id, IdCategory type, NodeInfo *info);
    virtual bool LnnHasDiscoveryType(const NodeInfo *info, DiscoveryType type);
    virtual DiscoveryType LnnConvAddrTypeToDiscType(ConnectionAddrType type);
    virtual SoftBusLooper *CreateNewLooper(const char *name);
    virtual int32_t LnnIpcNotifyOnlineState(bool isOnline, void *info, uint32_t infoTypeLen);
    virtual void LnnDCProcessOnlineState(bool isOnline, const NodeBasicInfo *info);
    virtual int32_t LnnIpcNotifyBasicInfoChanged(void *info, uint32_t infoTypeLen, int32_t type);
    virtual int32_t LnnGenLocalNetworkId(char *networkId, uint32_t len);
    virtual int32_t LnnIpcLocalNetworkIdChanged(void);
    virtual int32_t LnnSetLocalStrInfo(InfoKey key, const char *info);
    virtual void LnnUpdateAuthExchangeUdid(void);
};

class BusCenterEventDepsInterfaceMock : public BusCenterEventDepsInterface {
public:
    BusCenterEventDepsInterfaceMock();
    ~BusCenterEventDepsInterfaceMock() override;

    MOCK_METHOD2(Anonymize, void (const char *, char **));
    MOCK_METHOD1(AnonymizeFree, void (char *));
    MOCK_METHOD0(SetDefaultQdisc, int32_t (void));
    MOCK_METHOD1(LnnGetAllOnlineNodeNum, int32_t (int32_t *));
    MOCK_METHOD2(LnnGetLocalNum64Info, int32_t  (InfoKey key, int64_t *info));
    MOCK_METHOD1(LnnIpcNotifyDeviceNotTrusted, int32_t (const char *));
    MOCK_METHOD4(LnnIpcNotifyJoinResult, int32_t  (void *, uint32_t, const char *, int32_t));
    MOCK_METHOD2(LnnIpcNotifyLeaveResult, int32_t  (const char *, int32_t));
    MOCK_METHOD5(LnnIpcNotifyTimeSyncResult, int32_t  (const char *, int32_t, const void *, uint32_t, int32_t));
    MOCK_METHOD3(LnnGetRemoteNodeInfoById, int32_t  (const char *, IdCategory, NodeInfo *));
    MOCK_METHOD2(LnnHasDiscoveryType, bool  (const NodeInfo *, DiscoveryType));
    MOCK_METHOD1(LnnConvAddrTypeToDiscType, DiscoveryType (ConnectionAddrType));
    MOCK_METHOD1(CreateNewLooper, SoftBusLooper * (const char *));
    MOCK_METHOD3(LnnIpcNotifyOnlineState, int32_t (bool, void *, uint32_t));
    MOCK_METHOD2(LnnDCProcessOnlineState, void (bool, const NodeBasicInfo *));
    MOCK_METHOD3(LnnIpcNotifyBasicInfoChanged, int32_t (void *, uint32_t, int32_t));
    MOCK_METHOD2(LnnGenLocalNetworkId, int32_t (char *, uint32_t));
    MOCK_METHOD0(LnnIpcLocalNetworkIdChanged, int32_t (void));
    MOCK_METHOD2(LnnSetLocalStrInfo, int32_t (InfoKey, const char *));
    MOCK_METHOD0(LnnUpdateAuthExchangeUdid, void (void));
};
} // namespace OHOS
#endif // BUS_CENTER_EVENT_DEPS_MOCK_H
