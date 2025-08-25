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

#include "transauthlanependingctl_fuzzer.h"

#include <cstring>
#include <fuzzer/FuzzedDataProvider.h>
#include <securec.h>
#include <vector>

#include "fuzz_data_generator.h"
#include "softbus_proxychannel_manager.h"
#include "trans_auth_lane_pending_ctl.c"

namespace OHOS {
class TransAuthLanePendingCtl {
public:
    TransAuthLanePendingCtl()
    {
        isInited_ = false;
        (void)TransProxyManagerInit(TransServerGetChannelCb());
        isInited_ = true;
    }

    ~TransAuthLanePendingCtl()
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

void TransAuthWithParaReqLanePendingInitTest(FuzzedDataProvider &provider)
{
    (void)provider;
    (void)TransAuthWithParaReqLanePendingInit();
}

void TransAuthWithParaReqLanePendingDeinitTest(FuzzedDataProvider &provider)
{
    (void)provider;
    TransAuthWithParaReqLanePendingDeinit();
}

void FillTransAuthWithParaNodeTest(FuzzedDataProvider &provider)
{
    TransAuthWithParaNode item;
    (void)memset_s(&item, sizeof(TransAuthWithParaNode), 0, sizeof(TransAuthWithParaNode));
    uint32_t laneReqId = provider.ConsumeIntegral<uint32_t>();
    std::string sessionName = provider.ConsumeRandomLengthString(SESSION_NAME_SIZE_MAX);
    bool accountInfo = provider.ConsumeBool();
    int32_t channelId = provider.ConsumeIntegral<int32_t>();

    (void)FillTransAuthWithParaNode(&item, laneReqId, sessionName.c_str(), accountInfo, channelId);
}

void TransAuthWithParaAddLaneReqToListTest(FuzzedDataProvider &provider)
{
    uint32_t laneReqId = provider.ConsumeIntegral<uint32_t>();
    std::string sessionName = provider.ConsumeRandomLengthString(SESSION_NAME_SIZE_MAX);
    bool accountInfo = provider.ConsumeBool();
    int32_t channelId = provider.ConsumeIntegral<int32_t>();

    (void)TransAuthWithParaAddLaneReqToList(laneReqId, nullptr, accountInfo, channelId);
    (void)TransAuthWithParaAddLaneReqToList(laneReqId, sessionName.c_str(), accountInfo, channelId);
}

void TransAuthWithParaDelLaneReqByIdTest(FuzzedDataProvider &provider)
{
    uint32_t laneReqId = provider.ConsumeIntegral<uint32_t>();

    (void)TransAuthWithParaDelLaneReqById(laneReqId);
}

void TransUpdateAuthWithParaLaneConnInfoTest(FuzzedDataProvider &provider)
{
    uint32_t laneHandle = provider.ConsumeIntegral<uint32_t>();
    bool bSucc = provider.ConsumeBool();
    int32_t errCode = provider.ConsumeIntegral<int32_t>();
    LaneConnInfo connInfo;
    (void)memset_s(&connInfo, sizeof(LaneConnInfo), 0, sizeof(LaneConnInfo));

    (void)TransUpdateAuthWithParaLaneConnInfo(laneHandle, bSucc, nullptr, errCode);
    (void)TransUpdateAuthWithParaLaneConnInfo(laneHandle, bSucc, &connInfo, errCode);
}

void TransAuthWithParaGetLaneReqByLaneReqIdTest(FuzzedDataProvider &provider)
{
    uint32_t laneReqId = provider.ConsumeIntegral<uint32_t>();
    TransAuthWithParaNode paraNode;
    (void)memset_s(&paraNode, sizeof(TransAuthWithParaNode), 0, sizeof(TransAuthWithParaNode));

    (void)TransAuthWithParaGetLaneReqByLaneReqId(laneReqId, nullptr);
    (void)TransAuthWithParaGetLaneReqByLaneReqId(laneReqId, &paraNode);
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int32_t LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    static OHOS::TransAuthLanePendingCtl testEvent;
    if (!testEvent.IsInited()) {
        return 0;
    }

    /* Run your code on data */
    FuzzedDataProvider provider(data, size);
    OHOS::TransAuthWithParaReqLanePendingInitTest(provider);
    OHOS::TransAuthWithParaReqLanePendingInitTest(provider);
    OHOS::TransUpdateAuthWithParaLaneConnInfoTest(provider);
    OHOS::TransAuthWithParaDelLaneReqByIdTest(provider);
    OHOS::TransAuthWithParaGetLaneReqByLaneReqIdTest(provider);
    OHOS::FillTransAuthWithParaNodeTest(provider);
    OHOS::TransAuthWithParaAddLaneReqToListTest(provider);
    OHOS::TransUpdateAuthWithParaLaneConnInfoTest(provider);
    OHOS::TransAuthWithParaGetLaneReqByLaneReqIdTest(provider);
    OHOS::TransAuthWithParaDelLaneReqByIdTest(provider);
    OHOS::TransAuthWithParaReqLanePendingDeinitTest(provider);
    OHOS::TransAuthWithParaReqLanePendingDeinitTest(provider);

    return 0;
}
