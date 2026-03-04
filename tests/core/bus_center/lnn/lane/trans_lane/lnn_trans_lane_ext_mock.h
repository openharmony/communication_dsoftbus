/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#ifndef LNN_TRANS_LANE_EXT_MOCK_H
#define LNN_TRANS_LANE_EXT_MOCK_H

#include <gmock/gmock.h>

#include "lnn_distributed_net_ledger_struct.h"
#include "lnn_lane_interface_struct.h"
#include "lnn_lane_link_struct.h"
#include "lnn_trans_lane_struct.h"

namespace OHOS {
class TransLaneExtInterface {
public:
    TransLaneExtInterface() {};
    virtual ~TransLaneExtInterface() {};

    virtual uint64_t SoftBusGetSysTimeMs(void) = 0;
    virtual int32_t GetTransReqInfoByLaneReqId(uint32_t laneReqId, TransReqInfo *reqInfo) = 0;
    virtual int32_t FindLaneResourceByLaneId(uint64_t laneId, LaneResource *resource) = 0;
    virtual int32_t LnnGetRemoteNumInfo(const char *networkId, InfoKey key, int32_t *info) = 0;
    virtual int32_t LnnConvertDlId(
        const char *srcId, IdCategory srcIdType, IdCategory dstIdType, char *dstIdBuf, uint32_t dstIdBufLen) = 0;
    virtual bool HaveConcurrencyPreLinkNodeByLaneReqIdPacked(uint32_t laneReqId, bool isCheckPreLink) = 0;
    virtual int32_t CheckLinkConflictByReleaseLink(LaneLinkType releaseLink) = 0;
    virtual bool CheckVirtualLinkByLaneReqId(uint32_t laneReqId) = 0;
    virtual int32_t PostDelayDestroyMessage(uint32_t laneReqId, uint64_t laneId, uint64_t delayMillis) = 0;
    virtual int32_t UpdateAndGetReqInfoByFree(uint32_t laneReqId, TransReqInfo *reqInfo) = 0;
    virtual int32_t LnnGetNetworkIdByUdid(const char *udid, char *buf, uint32_t len) = 0;
    virtual int32_t DestroyLink(const char *networkId, uint32_t laneReqId, LaneLinkType type) = 0;
};

class TransLaneExtInterfaceMock : public TransLaneExtInterface {
public:
    TransLaneExtInterfaceMock();
    ~TransLaneExtInterfaceMock() override;

    MOCK_METHOD0(SoftBusGetSysTimeMs, uint64_t ());
    MOCK_METHOD2(GetTransReqInfoByLaneReqId, int32_t (uint32_t, TransReqInfo *));
    MOCK_METHOD2(FindLaneResourceByLaneId, int32_t (uint64_t, LaneResource *));
    MOCK_METHOD3(LnnGetRemoteNumInfo, int32_t (const char *, InfoKey, int32_t *));
    MOCK_METHOD5(LnnConvertDlId, int32_t (const char *, IdCategory, IdCategory, char *, uint32_t));
    MOCK_METHOD2(HaveConcurrencyPreLinkNodeByLaneReqIdPacked, bool (uint32_t, bool));
    MOCK_METHOD1(CheckLinkConflictByReleaseLink, int32_t (LaneLinkType));
    MOCK_METHOD1(CheckVirtualLinkByLaneReqId, bool (uint32_t));
    MOCK_METHOD3(PostDelayDestroyMessage, int32_t (uint32_t, uint64_t, uint64_t));
    MOCK_METHOD2(UpdateAndGetReqInfoByFree, int32_t (uint32_t, TransReqInfo *reqInfo));
    MOCK_METHOD3(LnnGetNetworkIdByUdid, int32_t (const char *, char *, uint32_t));
    MOCK_METHOD3(DestroyLink, int32_t (const char *, uint32_t, LaneLinkType));
};
} // namespace OHOS
#endif // LNN_TRANS_LANE_EXT_MOCK_H