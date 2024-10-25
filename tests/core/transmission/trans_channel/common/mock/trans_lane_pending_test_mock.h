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

#ifndef TRANS_LANE_PENDING_TEST_MOCK_H
#define TRANS_LANE_PENDING_TEST_MOCK_H

#include <gmock/gmock.h>
#include "lnn_distributed_net_ledger.h"
#include "lnn_lane_interface.h"
#include "lnn_node_info.h"
#include "softbus_app_info.h"
#include "softbus_config_type.h"
#include "softbus_trans_def.h"
#include "softbus_utils.h"

namespace OHOS {
class TransLanePendingTestInterface {
public:
    TransLanePendingTestInterface() {};
    virtual ~TransLanePendingTestInterface() {};
    virtual SoftBusList *CreateSoftBusList(void) = 0;
    virtual LaneTransType TransGetLaneTransTypeBySession(const SessionParam *param) = 0;
    virtual int32_t LnnGetRemoteNodeInfoById(const char *id, IdCategory type, NodeInfo *info) = 0;
    virtual int32_t TransGetUidAndPid(const char *sessionName, int32_t *uid, int32_t *pid) = 0;
    virtual bool LnnHasDiscoveryType(const NodeInfo *info, DiscoveryType type) = 0;
    virtual LnnLaneManager* GetLaneManager(void) = 0;
    virtual int32_t LnnRequestLane(uint32_t laneReqId, const LaneRequestOption *request,
        const ILaneListener *listener) = 0;
    virtual int32_t TransSoftBusCondWait(SoftBusCond *cond, SoftBusMutex *mutex, uint32_t timeMillis) = 0;
    virtual int32_t TransWaitingRequestCallback(uint32_t laneHandle) = 0;
    virtual int32_t SoftBusCondWait(SoftBusCond *cond, SoftBusMutex *mutex, SoftBusSysTime *time) = 0;
    virtual int32_t TransOpenChannelProc(ChannelType type, AppInfo *appInfo,
        const ConnectOption *connOpt, int32_t *channelId) = 0;
    virtual int32_t ClientIpcSetChannelInfo(const char *pkgName, const char *sessionName, int32_t sessionId,
    const TransInfo *transInfo, int32_t pid) = 0;
    virtual int32_t TransLaneMgrAddLane(const TransInfo *transInfo, const LaneConnInfo *connInfo,
        uint32_t laneHandle, bool isQosLane, AppInfoData *myData) = 0;
    virtual int32_t LnnGetLocalStrInfo(InfoKey key, char *info, uint32_t len) = 0;
    virtual int32_t TransGetPkgNameBySessionName(const char *sessionName, char *pkgName, uint16_t len) = 0;
    virtual int32_t LnnGetRemoteStrInfo(const char *networkId, InfoKey key, char *info, uint32_t len) = 0;
    virtual int32_t LnnGetDLAuthCapacity(const char *networkId, uint32_t *authCapacity) = 0;
};

class TransLanePendingTestInterfaceMock : public TransLanePendingTestInterface {
public:
    TransLanePendingTestInterfaceMock();
    ~TransLanePendingTestInterfaceMock() override;
    MOCK_METHOD0(CreateSoftBusList, SoftBusList * ());
    MOCK_METHOD1(TransGetLaneTransTypeBySession, LaneTransType (const SessionParam *param));
    MOCK_METHOD3(LnnGetRemoteNodeInfoById, int32_t (const char *id, IdCategory type, NodeInfo *info));
    MOCK_METHOD3(TransGetUidAndPid, int32_t (const char *sessionName, int32_t *uid, int32_t *pid));
    MOCK_METHOD2(LnnHasDiscoveryType, bool (const NodeInfo *info, DiscoveryType type));
    MOCK_METHOD0(GetLaneManager, LnnLaneManager * ());
    MOCK_METHOD3(LnnRequestLane, int32_t (uint32_t laneReqId, const LaneRequestOption *request,
        const ILaneListener *listener));
    MOCK_METHOD3(TransSoftBusCondWait, int32_t (SoftBusCond *cond, SoftBusMutex *mutex, uint32_t timeMillis));
    MOCK_METHOD3(SoftBusCondWait, int32_t (SoftBusCond *cond, SoftBusMutex *mutex, SoftBusSysTime *time));
    MOCK_METHOD1(TransWaitingRequestCallback, int32_t (uint32_t laneHandle));
    MOCK_METHOD4(TransOpenChannelProc, int32_t
        (ChannelType type, AppInfo *appInfo, const ConnectOption *connOpt, int32_t *channelId));
    MOCK_METHOD5(ClientIpcSetChannelInfo, int32_t (const char *pkgName, const char *sessionName, int32_t sessionId,
        const TransInfo *transInfo, int32_t pid));
    MOCK_METHOD5(TransLaneMgrAddLane, int32_t (const TransInfo *transInfo, const LaneConnInfo *connInfo,
        uint32_t laneHandle, bool isQosLane, AppInfoData *myData));
    MOCK_METHOD3(LnnGetLocalStrInfo, int32_t (InfoKey key, char *info, uint32_t len));
    MOCK_METHOD3(TransGetPkgNameBySessionName, int32_t (const char *sessionName, char *pkgName, uint16_t len));
    MOCK_METHOD4(LnnGetRemoteStrInfo, int32_t (const char *networkId, InfoKey key, char *info, uint32_t len));
    MOCK_METHOD2(LnnGetDLAuthCapacity, int32_t (const char *networkId, uint32_t *authCapacity));
};
} // namespace OHOS
#endif // TRANS_LANE_COMMON_TEST_MOCK_H
