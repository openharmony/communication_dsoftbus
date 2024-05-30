/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "lnn_ctrl_lane.h"

#include <securec.h>

#include "auth_interface.h"
#include "lnn_lane_interface.h"
#include "lnn_log.h"
#include "lnn_trans_lane.h"
#include "softbus_adapter_mem.h"
#include "softbus_errcode.h"
#include "wifi_direct_manager.h"

static LaneInterface g_ctrlLaneObject = {
    .allocLaneByQos = CtrlAlloc,
    .freeLane = CtrlFree,
};

LaneInterface *CtrlLaneGetInstance(void)
{
    return &g_ctrlLaneObject;
}

int32_t ConvertAuthLinkToLaneLink(AuthLinkTypeList *authLinkType, LanePreferredLinkList *laneLinkType)
{
    if (authLinkType == NULL || laneLinkType == NULL) {
        LNN_LOGE(LNN_LANE, "param invalid");
        return SOFTBUS_INVALID_PARAM;
    }
    laneLinkType->linkTypeNum = 0;
    for (uint32_t i = 0; i < authLinkType->linkTypeNum; ++i) {
        switch (authLinkType->linkType[i]) {
            case AUTH_LINK_TYPE_WIFI:
                laneLinkType->linkType[laneLinkType->linkTypeNum++] = LANE_WLAN_2P4G;
                laneLinkType->linkType[laneLinkType->linkTypeNum++] = LANE_WLAN_5G;
                break;
            case AUTH_LINK_TYPE_BR:
                laneLinkType->linkType[laneLinkType->linkTypeNum++] = LANE_BR;
                break;
            case AUTH_LINK_TYPE_BLE:
                laneLinkType->linkType[laneLinkType->linkTypeNum++] = LANE_BLE;
                break;
            case AUTH_LINK_TYPE_P2P:
                laneLinkType->linkType[laneLinkType->linkTypeNum++] = LANE_P2P;
                break;
            case AUTH_LINK_TYPE_ENHANCED_P2P:
                laneLinkType->linkType[laneLinkType->linkTypeNum++] = LANE_HML;
                break;
            default:
                break;
        }
    }
    return SOFTBUS_OK;
}

bool IsAuthReuseP2p(const char *networkId, const char *udid, AuthLinkType authType)
{
    LaneResource resoureItem;
    if (memset_s(&resoureItem, sizeof(LaneResource), 0, sizeof(LaneResource)) != EOK) {
        LNN_LOGE(LNN_LANE, "memset_s LaneResource fail");
        return false;
    }
    if (authType == AUTH_LINK_TYPE_ENHANCED_P2P &&
        FindLaneResourceByLinkType(udid, LANE_HML, &resoureItem) == SOFTBUS_OK &&
        !GetWifiDirectManager()->isNegotiateChannelNeeded(networkId, WIFI_DIRECT_LINK_TYPE_HML)) {
        LNN_LOGI(LNN_LANE, "can use HML");
        return true;
    } else if (authType == AUTH_LINK_TYPE_P2P &&
        FindLaneResourceByLinkType(udid, LANE_P2P, &resoureItem) == SOFTBUS_OK &&
        !GetWifiDirectManager()->isNegotiateChannelNeeded(networkId, WIFI_DIRECT_LINK_TYPE_P2P)) {
        LNN_LOGI(LNN_LANE, "can use P2P");
        return true;
    } else {
        return false;
    }
}