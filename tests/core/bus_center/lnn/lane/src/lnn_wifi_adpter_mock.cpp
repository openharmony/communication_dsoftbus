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

#include "lnn_wifi_adpter_mock.h"

#include <thread>
#include <securec.h>

#include "lnn_lane_link.h"
#include "softbus_error_code.h"

using namespace testing;
using namespace testing::ext;

constexpr uint32_t SLEEP_FOR_LOOP_COMPLETION_MS = 50;

namespace OHOS {
void *g_wifiAdpterInterface;
LnnWifiAdpterInterfaceMock::LnnWifiAdpterInterfaceMock()
{
    g_wifiAdpterInterface = reinterpret_cast<void *>(this);
}

LnnWifiAdpterInterfaceMock::~LnnWifiAdpterInterfaceMock()
{
    g_wifiAdpterInterface = nullptr;
}

static LnnWifiAdpterInterface *GetWifiAdpterInterface()
{
    return reinterpret_cast<LnnWifiAdpterInterface *>(g_wifiAdpterInterface);
}

void LnnWifiAdpterInterfaceMock::SetDefaultResult()
{
    EXPECT_CALL(*this, SoftBusGetLinkBand).WillRepeatedly(Return(BAND_UNKNOWN));
}

bool LnnWifiAdpterInterfaceMock::delayNotifyLinkSuccess = false;
int32_t LnnWifiAdpterInterfaceMock::ActionOfLnnConnectP2p(const LinkRequest *request, uint32_t laneLinkReqId,
    const LaneLinkCb *callback)
{
    GTEST_LOG_(INFO) << "ActionOfLnnConnectP2p enter";
    if (request == nullptr || callback == nullptr) {
        GTEST_LOG_(ERROR) << "invalid param";
        return SOFTBUS_INVALID_PARAM;
    }
    LaneLinkInfo linkInfo;
    if (memset_s(&linkInfo, sizeof(LaneLinkInfo), 0, sizeof(LaneLinkInfo)) != EOK) {
        return SOFTBUS_MEM_ERR;
    }
    linkInfo.type = request->linkType;
    if (delayNotifyLinkSuccess) {
        GTEST_LOG_(INFO) << "delay notify laneLinkSuccess after 50ms";
        std::this_thread::sleep_for(std::chrono::milliseconds(SLEEP_FOR_LOOP_COMPLETION_MS));
    }
    callback->OnLaneLinkSuccess(laneLinkReqId, &linkInfo);
    return SOFTBUS_OK;
}

extern "C" {
int32_t SoftBusGetLinkedInfo(SoftBusWifiLinkedInfo *info)
{
    return GetWifiAdpterInterface()->SoftBusGetLinkedInfo(info);
}

SoftBusBand SoftBusGetLinkBand(void)
{
    return GetWifiAdpterInterface()->SoftBusGetLinkBand();
}

void LnnDisconnectP2p(const char *networkId, int32_t pid, uint32_t laneLinkReqId)
{
    return GetWifiAdpterInterface()->LnnDisconnectP2p(networkId, pid, laneLinkReqId);
}

void LnnDestroyP2p(void)
{
    return GetWifiAdpterInterface()->LnnDestroyP2p();
}

int32_t LnnConnectP2p(const LinkRequest *request, uint32_t laneLinkReqId, const LaneLinkCb *callback)
{
    return GetWifiAdpterInterface()->LnnConnectP2p(request, laneLinkReqId, callback);
}
int32_t UpdateP2pLinkedInfo(uint32_t laneReqId, uint64_t laneId)
{
    return GetWifiAdpterInterface()->UpdateP2pLinkedInfo(laneReqId, laneId);
}
}
}