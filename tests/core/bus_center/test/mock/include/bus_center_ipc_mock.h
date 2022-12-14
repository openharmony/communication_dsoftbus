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

#ifndef BUS_CENTER_IPC_H
#define BUS_CENTER_IPC_H

#include "bus_center_manager.h"
#include "lnn_connection_addr_utils.h"
#include "lnn_local_net_ledger.h"
#include <gmock/gmock.h>
#include <mutex>

namespace OHOS {
class BusCenterIpcInterface {
public:
    BusCenterIpcInterface() {};
    virtual ~BusCenterIpcInterface() {};

    virtual bool LnnIsSameConnectionAddr(const ConnectionAddr *addr1, const ConnectionAddr *addr2) = 0;
    virtual int32_t MetaNodeServerJoin(ConnectionAddr *addr, CustomData *customData) = 0;
    virtual int32_t MetaNodeServerLeave(const char *networkId) = 0;
    virtual int32_t LnnServerLeave(const char *networkId) = 0;
    virtual int32_t LnnGetAllOnlineNodeInfo(NodeBasicInfo **info, int32_t *infoNum) = 0;
    virtual int32_t LnnGetLocalDeviceInfo(NodeBasicInfo *info) = 0;
    virtual int32_t LnnGetNodeKeyInfo(const char *networkId, int key, uint8_t *info, uint32_t infoLen) = 0;
    virtual int32_t LnnSetNodeDataChangeFlag(const char *networkId, uint16_t dataChangeFlag) = 0;
    virtual int32_t LnnStartTimeSync(
        const char *pkgName, const char *targetNetworkId, TimeSyncAccuracy accuracy, TimeSyncPeriod period) = 0;
    virtual int32_t LnnStopTimeSync(const char *pkgName, const char *targetNetworkId) = 0;
    virtual int32_t LnnPublishService(const char *pkgName, const PublishInfo *info, bool isInnerRequest) = 0;
    virtual int32_t LnnUnPublishService(const char *pkgName, int32_t publishId, bool isInnerRequest) = 0;
    virtual void SetCallLnnStatus(bool flag) = 0;
    virtual int32_t LnnStartDiscDevice(
        const char *pkgName, const SubscribeInfo *info, const InnerCallback *cb, bool isInnerRequest) = 0;
    virtual int32_t LnnStopDiscDevice(const char *pkgName, int32_t subscribeId, bool isInnerRequest) = 0;
    virtual int32_t LnnActiveMetaNode(const MetaNodeConfigInfo *info, char *metaNodeId) = 0;
    virtual int32_t LnnDeactiveMetaNode(const char *metaNodeId) = 0;
    virtual int32_t LnnGetAllMetaNodeInfo(MetaNodeInfo *infos, int32_t *infoNum) = 0;
    virtual int32_t LnnShiftLNNGear(
        const char *pkgName, const char *callerId, const char *targetNetworkId, const GearMode *mode) = 0;
    virtual int32_t ClientOnJoinLNNResult(
        const char *pkgName, void *addr, uint32_t addrTypeLen, const char *networkId, int32_t retCode) = 0;
    virtual int32_t ClientOnJoinMetaNodeResult(
        const char *pkgName, void *addr, uint32_t addrTypeLen, const char *networkId, int32_t retCode) = 0;
    virtual int32_t ClientOnLeaveLNNResult(const char *pkgName, const char *networkId, int32_t retCode) = 0;
    virtual int32_t ClientOnLeaveMetaNodeResult(const char *pkgName, const char *networkId, int32_t retCode) = 0;
    virtual int32_t ClinetOnNodeOnlineStateChanged(bool isOnline, void *info, uint32_t infoTypeLen) = 0;
    virtual int32_t ClinetOnNodeBasicInfoChanged(void *info, uint32_t infoTypeLen, int32_t type) = 0;
    virtual int32_t ClientOnTimeSyncResult(
        const char *pkgName, const void *info, uint32_t infoTypeLen, int32_t retCode) = 0;
    virtual int32_t ClientOnPublishLNNResult(const char *pkgName, int32_t publishId, int32_t reason) = 0;
    virtual int32_t ClientOnRefreshLNNResult(const char *pkgName, int32_t refreshId, int32_t reason) = 0;
    virtual int32_t ClientOnRefreshDeviceFound(const char *pkgName, const void *device, uint32_t deviceLen) = 0;
    virtual int32_t LnnServerJoin(ConnectionAddr *addr) = 0;
};
class BusCenterIpcInterfaceMock : public BusCenterIpcInterface {
public:
    BusCenterIpcInterfaceMock();
    ~BusCenterIpcInterfaceMock() override;

    MOCK_METHOD2(LnnIsSameConnectionAddr, bool(const ConnectionAddr *, const ConnectionAddr *));
    MOCK_METHOD2(MetaNodeServerJoin, int32_t(ConnectionAddr *, CustomData *));
    MOCK_METHOD1(LnnServerLeave, int32_t(const char *));
    MOCK_METHOD1(MetaNodeServerLeave, int32_t(const char *));
    MOCK_METHOD2(LnnGetAllOnlineNodeInfo, int32_t(NodeBasicInfo **, int32_t *));
    MOCK_METHOD1(LnnGetLocalDeviceInfo, int32_t(NodeBasicInfo *));
    MOCK_METHOD4(LnnGetNodeKeyInfo, int32_t(const char *, int, uint8_t *, uint32_t));
    MOCK_METHOD2(LnnSetNodeDataChangeFlag, int32_t(const char *, uint16_t));
    MOCK_METHOD4(LnnStartTimeSync, int32_t(const char *, const char *, TimeSyncAccuracy, TimeSyncPeriod));
    MOCK_METHOD2(LnnStopTimeSync, int32_t(const char *, const char *));
    MOCK_METHOD3(LnnPublishService, int32_t(const char *, const PublishInfo *, bool));
    MOCK_METHOD3(LnnUnPublishService, int32_t(const char *, int32_t, bool));
    MOCK_METHOD1(SetCallLnnStatus, void(bool));
    MOCK_METHOD4(LnnStartDiscDevice, int32_t(const char *, const SubscribeInfo *, const InnerCallback *, bool));
    MOCK_METHOD3(LnnStopDiscDevice, int32_t(const char *, int32_t, bool));
    MOCK_METHOD2(LnnActiveMetaNode, int32_t(const MetaNodeConfigInfo *, char *));
    MOCK_METHOD1(LnnDeactiveMetaNode, int32_t(const char *));
    MOCK_METHOD2(LnnGetAllMetaNodeInfo, int32_t(MetaNodeInfo *, int32_t *));
    MOCK_METHOD4(LnnShiftLNNGear, int32_t(const char *, const char *, const char *, const GearMode *));
    MOCK_METHOD5(ClientOnJoinLNNResult, int32_t(const char *, void *, uint32_t, const char *, int32_t));
    MOCK_METHOD5(ClientOnJoinMetaNodeResult, int32_t(const char *, void *, uint32_t, const char *, int32_t));
    MOCK_METHOD3(ClientOnLeaveLNNResult, int32_t(const char *, const char *, int32_t));
    MOCK_METHOD3(ClientOnLeaveMetaNodeResult, int32_t(const char *, const char *, int32_t));
    MOCK_METHOD3(ClinetOnNodeOnlineStateChanged, int32_t(bool, void *, uint32_t));
    MOCK_METHOD3(ClinetOnNodeBasicInfoChanged, int32_t(void *, uint32_t, int32_t));
    MOCK_METHOD4(ClientOnTimeSyncResult, int32_t(const char *, const void *, uint32_t, int32_t));
    MOCK_METHOD3(ClientOnPublishLNNResult, int32_t(const char *, int32_t, int32_t));
    MOCK_METHOD3(ClientOnRefreshLNNResult, int32_t(const char *, int32_t, int32_t));
    MOCK_METHOD3(ClientOnRefreshDeviceFound, int32_t(const char *, const void *, uint32_t));
    MOCK_METHOD1(LnnServerJoin,int32_t(ConnectionAddr *));
};
} // namespace OHOS
#endif // AUTH_CONNECTION_MOCK_H
