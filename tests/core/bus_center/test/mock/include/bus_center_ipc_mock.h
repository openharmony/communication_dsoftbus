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

#include <gmock/gmock.h>
#include <mutex>

#include "bus_center_client_proxy.h"
#include "bus_center_manager.h"
#include "lnn_connection_addr_utils.h"
#include "lnn_heartbeat_utils_struct.h"
#include "lnn_local_net_ledger.h"
#include "lnn_ranging_manager_struct.h"

namespace OHOS {
class BusCenterIpcInterface {
public:
    BusCenterIpcInterface() {};
    virtual ~BusCenterIpcInterface() {};

    virtual bool LnnIsSameConnectionAddr(const ConnectionAddr *addr1, const ConnectionAddr *addr2, bool isShort) = 0;
    virtual int32_t LnnServerLeave(const char *networkId, const char *pkgName) = 0;
    virtual int32_t LnnGetAllOnlineNodeInfo(NodeBasicInfo **info, int32_t *infoNum) = 0;
    virtual bool LnnIsLSANode(const NodeBasicInfo *info) = 0;
    virtual int32_t LnnGetLocalDeviceInfo(NodeBasicInfo *info) = 0;
    virtual int32_t LnnGetNodeKeyInfo(const char *networkId, int32_t key, uint8_t *info, uint32_t infoLen) = 0;
    virtual int32_t LnnSetNodeKeyInfo(const char *networkId, int32_t key, uint8_t *info, uint32_t infoLen) = 0;
    virtual int32_t LnnSetNodeDataChangeFlag(const char *networkId, uint16_t dataChangeFlag) = 0;
    virtual int32_t LnnStartTimeSync(const char *pkgName, int32_t callingPid, const char *targetNetworkId,
        TimeSyncAccuracy accuracy, TimeSyncPeriod period) = 0;
    virtual int32_t LnnStopTimeSync(const char *pkgName, const char *targetNetworkId, int32_t callingPid) = 0;
    virtual int32_t LnnPublishService(
        const char *pkgName, const PublishInfo *info, bool isInnerRequest, int32_t callingPid) = 0;
    virtual int32_t LnnUnPublishService(
        const char *pkgName, int32_t publishId, bool isInnerRequest, int32_t callingPid) = 0;
    virtual int32_t LnnStartDiscDevice(const char *pkgName, const SubscribeInfo *info, const InnerCallback *cb,
        bool isInnerRequest, int32_t callingPid) = 0;
    virtual int32_t LnnStopDiscDevice(
        const char *pkgName, int32_t subscribeId, bool isInnerRequest, int32_t callingPid) = 0;
    virtual int32_t LnnActiveMetaNode(const MetaNodeConfigInfo *info, char *metaNodeId) = 0;
    virtual int32_t LnnDeactiveMetaNode(const char *metaNodeId) = 0;
    virtual int32_t LnnGetAllMetaNodeInfo(MetaNodeInfo *infos, int32_t *infoNum) = 0;
    virtual int32_t LnnShiftLNNGear(
        const char *pkgName, const char *callerId, const char *targetNetworkId, const GearMode *mode) = 0;
    virtual int32_t ClientOnJoinLNNResult(
        PkgNameAndPidInfo *info, void *addr, uint32_t addrTypeLen, const char *networkId, int32_t retCode) = 0;
    virtual int32_t ClientOnLeaveLNNResult(
        const char *pkgName, int32_t pid, const char *networkId, int32_t retCode) = 0;
    virtual int32_t ClinetOnNodeOnlineStateChanged(bool isOnline, void *info, uint32_t infoTypeLen) = 0;
    virtual int32_t ClinetOnNodeBasicInfoChanged(void *info, uint32_t infoTypeLen, int32_t type) = 0;
    virtual int32_t ClientOnTimeSyncResult(
        const char *pkgName, int32_t pid, const void *info, uint32_t infoTypeLen, int32_t retCode) = 0;
    virtual int32_t ClientOnPublishLNNResult(const char *pkgName, int32_t pid, int32_t publishId, int32_t reason) = 0;
    virtual int32_t ClientOnRefreshLNNResult(const char *pkgName, int32_t pid, int32_t refreshId, int32_t reason) = 0;
    virtual int32_t ClientOnRefreshDeviceFound(
        const char *pkgName, int32_t pid, const void *device, uint32_t deviceLen) = 0;
    virtual int32_t LnnServerJoin(ConnectionAddr *addr, const char *pkgName, bool isForceJoin) = 0;
    virtual void SleRangeDeathCallbackPacked(void) = 0;
    virtual void LnnRegBleRangeCb(const IBleRangeInnerCallback *callback) = 0;
    virtual void LnnRegSleRangeCbPacked(const ISleRangeInnerCallback *callback) = 0;
    virtual void LnnUnregBleRangeCb(void) = 0;
    virtual void LnnUnregSleRangeCbPacked(void) = 0;
    virtual int32_t ClientOnRangeResult(const char *pkgName, int32_t pid, const RangeResultInnerInfo *rangeInfo) = 0;
    virtual void SdMgrDeathCallbackPacked(const char *pkgName);
};
class BusCenterIpcInterfaceMock : public BusCenterIpcInterface {
public:
    BusCenterIpcInterfaceMock();
    ~BusCenterIpcInterfaceMock() override;

    MOCK_METHOD3(LnnIsSameConnectionAddr, bool(const ConnectionAddr *, const ConnectionAddr *, bool));
    MOCK_METHOD2(LnnServerLeave, int32_t(const char *, const char *));
    MOCK_METHOD2(LnnGetAllOnlineNodeInfo, int32_t(NodeBasicInfo **, int32_t *));
    MOCK_METHOD1(LnnIsLSANode, bool(const NodeBasicInfo *));
    MOCK_METHOD1(LnnGetLocalDeviceInfo, int32_t(NodeBasicInfo *));
    MOCK_METHOD4(LnnGetNodeKeyInfo, int32_t(const char *, int, uint8_t *, uint32_t));
    MOCK_METHOD4(LnnSetNodeKeyInfo, int32_t(const char *, int, uint8_t *, uint32_t));
    MOCK_METHOD2(LnnSetNodeDataChangeFlag, int32_t(const char *, uint16_t));
    MOCK_METHOD5(LnnStartTimeSync, int32_t(const char *, int32_t, const char *, TimeSyncAccuracy, TimeSyncPeriod));
    MOCK_METHOD3(LnnStopTimeSync, int32_t(const char *, const char *, int32_t));
    MOCK_METHOD4(LnnPublishService, int32_t(const char *, const PublishInfo *, bool, int32_t));
    MOCK_METHOD4(LnnUnPublishService, int32_t(const char *, int32_t, bool, int32_t));
    MOCK_METHOD5(
        LnnStartDiscDevice, int32_t(const char *, const SubscribeInfo *, const InnerCallback *, bool, int32_t));
    MOCK_METHOD4(LnnStopDiscDevice, int32_t(const char *, int32_t, bool, int32_t));
    MOCK_METHOD2(LnnActiveMetaNode, int32_t(const MetaNodeConfigInfo *, char *));
    MOCK_METHOD1(LnnDeactiveMetaNode, int32_t(const char *));
    MOCK_METHOD2(LnnGetAllMetaNodeInfo, int32_t(MetaNodeInfo *, int32_t *));
    MOCK_METHOD4(LnnShiftLNNGear, int32_t(const char *, const char *, const char *, const GearMode *));
    MOCK_METHOD5(ClientOnJoinLNNResult, int32_t(PkgNameAndPidInfo *, void *, uint32_t, const char *, int32_t));
    MOCK_METHOD4(ClientOnLeaveLNNResult, int32_t(const char *, int32_t, const char *, int32_t));
    MOCK_METHOD3(ClinetOnNodeOnlineStateChanged, int32_t(bool, void *, uint32_t));
    MOCK_METHOD3(ClinetOnNodeBasicInfoChanged, int32_t(void *, uint32_t, int32_t));
    MOCK_METHOD5(ClientOnTimeSyncResult, int32_t(const char *, int32_t, const void *, uint32_t, int32_t));
    MOCK_METHOD4(ClientOnPublishLNNResult, int32_t(const char *, int32_t, int32_t, int32_t));
    MOCK_METHOD4(ClientOnRefreshLNNResult, int32_t(const char *, int32_t, int32_t, int32_t));
    MOCK_METHOD4(ClientOnRefreshDeviceFound, int32_t(const char *, int32_t, const void *, uint32_t));
    MOCK_METHOD3(LnnServerJoin, int32_t(ConnectionAddr *, const char *, bool));
    MOCK_METHOD0(SleRangeDeathCallbackPacked, void(void));
    MOCK_METHOD1(LnnRegBleRangeCb, void(const IBleRangeInnerCallback *callback));
    MOCK_METHOD1(LnnRegSleRangeCbPacked, void(const ISleRangeInnerCallback *callback));
    MOCK_METHOD0(LnnUnregBleRangeCb, void(void));
    MOCK_METHOD0(LnnUnregSleRangeCbPacked, void(void));
    MOCK_METHOD3(ClientOnRangeResult, int32_t(const char *pkgName, int32_t pid, const RangeResultInnerInfo *rangeInfo));
    MOCK_METHOD1(SdMgrDeathCallbackPacked, void(const char *pkgName));
};
} // namespace OHOS
#endif // AUTH_CONNECTION_MOCK_H
