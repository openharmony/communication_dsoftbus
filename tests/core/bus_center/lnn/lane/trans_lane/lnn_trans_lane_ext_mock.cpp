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

#include "lnn_trans_lane_ext_mock.h"
#include "softbus_error_code.h"

using namespace testing::ext;
using namespace testing;

namespace OHOS {
void *g_transLaneExtIf;
TransLaneExtInterfaceMock::TransLaneExtInterfaceMock()
{
    g_transLaneExtIf = reinterpret_cast<void *>(this);
}

TransLaneExtInterfaceMock::~TransLaneExtInterfaceMock()
{
    g_transLaneExtIf = nullptr;
}

static TransLaneExtInterface *GetTransLaneExtIf()
{
    return reinterpret_cast<TransLaneExtInterface *>(g_transLaneExtIf);
}

extern "C" {
uint64_t SoftBusGetSysTimeMs(void)
{
    return GetTransLaneExtIf()->SoftBusGetSysTimeMs();
}

int32_t GetTransReqInfoByLaneReqId(uint32_t laneReqId, TransReqInfo *reqInfo)
{
    return GetTransLaneExtIf()->GetTransReqInfoByLaneReqId(laneReqId, reqInfo);
}

int32_t FindLaneResourceByLaneId(uint64_t laneId, LaneResource *resource)
{
    return GetTransLaneExtIf()->FindLaneResourceByLaneId(laneId, resource);
}

int32_t LnnGetRemoteNumInfo(const char *networkId, InfoKey key, int32_t *info)
{
    return GetTransLaneExtIf()->LnnGetRemoteNumInfo(networkId, key, info);
}

int32_t LnnConvertDlId(
    const char *srcId, IdCategory srcIdType, IdCategory dstIdType, char *dstIdBuf, uint32_t dstIdBufLen)
{
    return GetTransLaneExtIf()->LnnConvertDlId(srcId, srcIdType, dstIdType, dstIdBuf, dstIdBufLen);
}

bool HaveConcurrencyPreLinkNodeByLaneReqIdPacked(uint32_t laneReqId, bool isCheckPreLink)
{
    return GetTransLaneExtIf()->HaveConcurrencyPreLinkNodeByLaneReqIdPacked(laneReqId, isCheckPreLink);
}

int32_t CheckLinkConflictByReleaseLink(LaneLinkType releaseLink)
{
    return GetTransLaneExtIf()->CheckLinkConflictByReleaseLink(releaseLink);
}

bool CheckVirtualLinkByLaneReqId(uint32_t laneReqId)
{
    return GetTransLaneExtIf()->CheckVirtualLinkByLaneReqId(laneReqId);
}

int32_t PostDelayDestroyMessage(uint32_t laneReqId, uint64_t laneId, uint64_t delayMillis)
{
    return GetTransLaneExtIf()->PostDelayDestroyMessage(laneReqId, laneId, delayMillis);
}

int32_t LnnGetNetworkIdByUdid(const char *udid, char *buf, uint32_t len)
{
    return GetTransLaneExtIf()->LnnGetNetworkIdByUdid(udid, buf, len);
}

int32_t UpdateAndGetReqInfoByFree(uint32_t laneReqId, TransReqInfo *reqInfo)
{
    return GetTransLaneExtIf()->UpdateAndGetReqInfoByFree(laneReqId, reqInfo);
}

int32_t DestroyLink(const char *networkId, uint32_t laneReqId, LaneLinkType type)
{
    return GetTransLaneExtIf()->DestroyLink(networkId, laneReqId, type);
}
}
} // namespace OHOS