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

#ifndef LNN_TRANS_LANE_DEPS_MOCK_H
#define LNN_TRANS_LANE_DEPS_MOCK_H

#include <gmock/gmock.h>

#include "lnn_lane_common.h"
#include "lnn_lane_link.h"
#include "lnn_lane_model.h"
#include "lnn_lane_select.h"

namespace OHOS {
class TransLaneDepsInterface {
public:
    TransLaneDepsInterface() {};
    virtual ~TransLaneDepsInterface() {};

    virtual int32_t SelectLane(const char *networkId, const LaneSelectParam *request,
        LaneLinkType **linkList, uint32_t *listNum);
    virtual int32_t BuildLink(const LinkRequest *reqInfo, uint32_t reqId, const LaneLinkCb *cb) = 0;
    virtual void DestroyLink(uint32_t reqId, LaneLinkType type, int32_t pid,
        const char *mac, const char *networkId) = 0;
    virtual uint32_t GenerateLaneProfileId(const LaneGenerateParam *param) = 0;
    virtual void UnbindLaneIdFromProfile(uint32_t laneId, uint32_t profileId) = 0;
    virtual int32_t BindLaneIdToProfile(uint32_t laneId, LaneProfile *profile) = 0;
};

class TransLaneDepsInterfaceMock : public TransLaneDepsInterface {
public:
    TransLaneDepsInterfaceMock();
    ~TransLaneDepsInterfaceMock() override;
    MOCK_METHOD4(SelectLane, int32_t (const char*, const LaneSelectParam *, LaneLinkType **, uint32_t *));
    MOCK_METHOD3(BuildLink, int32_t (const LinkRequest *, uint32_t, const LaneLinkCb *));
    MOCK_METHOD5(DestroyLink, void (uint32_t, LaneLinkType, int32_t, const char *, const char *));
    MOCK_METHOD1(GenerateLaneProfileId, uint32_t (const LaneGenerateParam *));
    MOCK_METHOD2(UnbindLaneIdFromProfile, void (uint32_t, uint32_t));
    MOCK_METHOD2(BindLaneIdToProfile, int32_t (uint32_t, LaneProfile *));
};
} // namespace OHOS
#endif // LNN_TRANS_LANE_DEPS_MOCK_H