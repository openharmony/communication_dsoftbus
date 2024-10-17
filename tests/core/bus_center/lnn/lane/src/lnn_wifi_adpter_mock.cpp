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
#include "wifi_direct_error_code.h"

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
    char peerIp[] = "127.1.1.1";
    char peerUdid[] = "222222222222222222";
    if (strncpy_s(linkInfo.linkInfo.p2p.connInfo.peerIp, IP_LEN, peerIp, strlen(peerIp)) != EOK) {
        return SOFTBUS_STRCPY_ERR;
    }
    if (strncpy_s(linkInfo.peerUdid, UDID_BUF_LEN, peerUdid, strlen(peerUdid)) != EOK) {
        return SOFTBUS_STRCPY_ERR;
    }
    if (delayNotifyLinkSuccess) {
        GTEST_LOG_(INFO) << "delay notify laneLinkSuccess after 50ms";
        std::this_thread::sleep_for(std::chrono::milliseconds(SLEEP_FOR_LOOP_COMPLETION_MS));
    }
    callback->onLaneLinkSuccess(laneLinkReqId, request->linkType, &linkInfo);
    return SOFTBUS_OK;
}

int32_t LnnWifiAdpterInterfaceMock::ActionOfOnConnectP2pFail(const LinkRequest *request, uint32_t laneLinkReqId,
    const LaneLinkCb *callback)
{
    GTEST_LOG_(INFO) << "ActionOfOnConnectP2pFail enter";
    callback->onLaneLinkFail(laneLinkReqId, ERROR_WIFI_OFF, request->linkType);
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

int32_t LnnDisconnectP2p(const char *networkId, uint32_t laneReqId)
{
    return GetWifiAdpterInterface()->LnnDisconnectP2p(networkId, laneReqId);
}

void LnnDestroyP2p(void)
{
    GetWifiAdpterInterface()->LnnDestroyP2p();
}

int32_t LnnConnectP2p(const LinkRequest *request, uint32_t laneReqId, const LaneLinkCb *callback)
{
    return GetWifiAdpterInterface()->LnnConnectP2p(request, laneReqId, callback);
}

int32_t UpdateP2pLinkedInfo(uint32_t laneReqId, uint64_t laneId)
{
    return GetWifiAdpterInterface()->UpdateP2pLinkedInfo(laneReqId, laneId);
}

void LnnCancelWifiDirect(uint32_t laneReqId)
{
    return GetWifiAdpterInterface()->LnnCancelWifiDirect(laneReqId);
}

void LnnDisconnectP2pWithoutLnn(uint32_t laneReqId)
{
    return GetWifiAdpterInterface()->LnnDisconnectP2pWithoutLnn(laneReqId);
}

SoftBusWifiDetailState SoftBusGetWifiState(void)
{
    return GetWifiAdpterInterface()->SoftBusGetWifiState();
}

int32_t SoftBusRegWlanChannelInfoCb(WlanChannelInfoCb *cb)
{
    return GetWifiAdpterInterface()->SoftBusRegWlanChannelInfoCb(cb);
}

int32_t SoftBusRegisterWifiEvent(ISoftBusScanResult *cb)
{
    return GetWifiAdpterInterface()->SoftBusRegisterWifiEvent(cb);
}

int32_t SoftBusUnRegisterWifiEvent(ISoftBusScanResult *cb)
{
    return GetWifiAdpterInterface()->SoftBusUnRegisterWifiEvent(cb);
}

int32_t SoftBusRequestWlanChannelInfo(int32_t *channelId, uint32_t num)
{
    return GetWifiAdpterInterface()->SoftBusRequestWlanChannelInfo(channelId, num);
}

int32_t SoftBusGetChannelListFor5G(int32_t *channelList, int32_t num)
{
    return GetWifiAdpterInterface()->SoftBusGetChannelListFor5G(channelList, num);
}

bool SoftBusIsWifiActive(void)
{
    return GetWifiAdpterInterface()->SoftBusIsWifiActive();
}

int32_t RemoveAuthSessionServer(const char *peerIp)
{
    return GetWifiAdpterInterface()->RemoveAuthSessionServer(peerIp);
}
}
}