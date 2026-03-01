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
 * See the License for the specific language  governing permissions and
 * limitations under the License.
 */

#include "transauthlanependingctl2_fuzzer.h"

#include <cstring>
#include <fuzzer/FuzzedDataProvider.h>
#include <securec.h>
#include <vector>

#include "fuzz_data_generator.h"
#include "softbus_proxychannel_manager.h"
#include "trans_auth_lane_pending_ctl.c"

namespace OHOS {
static constexpr uint32_t MAX_SESSION_NAME_LEN = 256;
static constexpr uint32_t MIN_LANE_REQ_ID = 1;
static constexpr uint32_t MAX_LANE_REQ_ID = 1000;
static constexpr int32_t MIN_CHANNEL_ID = -10;
static constexpr int32_t MAX_CHANNEL_ID = 10;

class TransAuthLanePendingCtl2 {
public:
    TransAuthLanePendingCtl2()
    {
        isInited_ = false;
        (void)TransProxyManagerInit(TransServerGetChannelCb());
        (void)TransAuthWithParaReqLanePendingInit();
        TransAuthWithParaReqLanePendingDeinit();
        isInited_ = true;
    }

    ~TransAuthLanePendingCtl2()
    {
        isInited_ = false;
        TransProxyManagerDeinit();
    }

    bool IsInited(void)
    {
        return isInited_;
    }

private:
    volatile bool isInited_;
};

void TestAddAndDelLaneReq(FuzzedDataProvider &provider)
{
    uint32_t laneReqId = provider.ConsumeIntegralInRange<uint32_t>(MIN_LANE_REQ_ID, MAX_LANE_REQ_ID);
    std::string sessionName = provider.ConsumeRandomLengthString(MAX_SESSION_NAME_LEN);
    bool accountInfo = provider.ConsumeBool();
    int32_t channelId = provider.ConsumeIntegralInRange<int32_t>(MIN_CHANNEL_ID, MAX_CHANNEL_ID);

    (void)TransAuthWithParaAddLaneReqToList(laneReqId, nullptr, accountInfo, channelId);
    (void)TransAuthWithParaAddLaneReqToList(laneReqId, sessionName.c_str(), accountInfo, channelId);
    (void)TransAuthWithParaDelLaneReqById(laneReqId);
    (void)TransAuthWithParaDelLaneReqById(laneReqId + 1);
}

void TestUpdateAndGetLaneReq(FuzzedDataProvider &provider)
{
    uint32_t laneReqId = provider.ConsumeIntegralInRange<uint32_t>(MIN_LANE_REQ_ID, MAX_LANE_REQ_ID);
    std::string sessionName = provider.ConsumeRandomLengthString(MAX_SESSION_NAME_LEN);
    bool accountInfo = provider.ConsumeBool();
    int32_t channelId = provider.ConsumeIntegralInRange<int32_t>(MIN_CHANNEL_ID, MAX_CHANNEL_ID);
    bool bSucc = provider.ConsumeBool();
    int32_t errCode = provider.ConsumeIntegral<int32_t>();
    LaneConnInfo connInfo;
    (void)memset_s(&connInfo, sizeof(LaneConnInfo), 0, sizeof(LaneConnInfo));

    (void)TransAuthWithParaAddLaneReqToList(laneReqId, sessionName.c_str(), accountInfo, channelId);
    (void)TransUpdateAuthWithParaLaneConnInfo(laneReqId, bSucc, nullptr, errCode);
    (void)TransUpdateAuthWithParaLaneConnInfo(laneReqId, bSucc, &connInfo, errCode);
    (void)TransUpdateAuthWithParaLaneConnInfo(laneReqId + 1, bSucc, &connInfo, errCode);

    TransAuthWithParaNode paraNode;
    (void)memset_s(&paraNode, sizeof(TransAuthWithParaNode), 0, sizeof(TransAuthWithParaNode));
    (void)TransAuthWithParaGetLaneReqByLaneReqId(laneReqId, nullptr);
    (void)TransAuthWithParaGetLaneReqByLaneReqId(laneReqId, &paraNode);
    (void)TransAuthWithParaGetLaneReqByLaneReqId(laneReqId + 1, &paraNode);
}

void TestMultiLaneReqOps(FuzzedDataProvider &provider)
{
    uint32_t baseLaneReqId = provider.ConsumeIntegralInRange<uint32_t>(MIN_LANE_REQ_ID, MAX_LANE_REQ_ID);
    std::string sessionName1 = provider.ConsumeRandomLengthString(MAX_SESSION_NAME_LEN);
    std::string sessionName2 = provider.ConsumeRandomLengthString(MAX_SESSION_NAME_LEN);
    bool accountInfo = provider.ConsumeBool();
    int32_t channelId = provider.ConsumeIntegralInRange<int32_t>(MIN_CHANNEL_ID, MAX_CHANNEL_ID);
    LaneConnInfo connInfo;
    (void)memset_s(&connInfo, sizeof(LaneConnInfo), 0, sizeof(LaneConnInfo));

    (void)TransAuthWithParaAddLaneReqToList(baseLaneReqId, sessionName1.c_str(), accountInfo, channelId);
    (void)TransAuthWithParaAddLaneReqToList(baseLaneReqId + 1, sessionName2.c_str(), !accountInfo, channelId + 1);
    (void)TransUpdateAuthWithParaLaneConnInfo(baseLaneReqId, true, &connInfo, 0);
    (void)TransUpdateAuthWithParaLaneConnInfo(baseLaneReqId + 1, false, &connInfo, -1);

    TransAuthWithParaNode paraNode1;
    TransAuthWithParaNode paraNode2;
    (void)memset_s(&paraNode1, sizeof(TransAuthWithParaNode), 0, sizeof(TransAuthWithParaNode));
    (void)memset_s(&paraNode2, sizeof(TransAuthWithParaNode), 0, sizeof(TransAuthWithParaNode));
    (void)TransAuthWithParaGetLaneReqByLaneReqId(baseLaneReqId, &paraNode1);
    (void)TransAuthWithParaGetLaneReqByLaneReqId(baseLaneReqId + 1, &paraNode2);

    (void)TransAuthWithParaDelLaneReqById(baseLaneReqId);
    (void)TransAuthWithParaDelLaneReqById(baseLaneReqId + 1);
}
} // namespace OHOS

extern "C" int32_t LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    static OHOS::TransAuthLanePendingCtl2 testEvent;
    if (!testEvent.IsInited()) {
        return 0;
    }

    FuzzedDataProvider provider(data, size);
    OHOS::TestAddAndDelLaneReq(provider);
    OHOS::TestUpdateAndGetLaneReq(provider);
    OHOS::TestMultiLaneReqOps(provider);

    return 0;
}
