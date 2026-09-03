/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "lnn_lane_common.h"

#include <securec.h>

#include "lnn_log.h"

typedef int32_t (*LinkInfoProc)(const LaneLinkInfo *, LaneConnInfo *);

static int32_t Wlan2P4GInfoProc(const LaneLinkInfo *linkInfo, LaneConnInfo *connInfo)
{
    connInfo->type = LANE_WLAN_2P4G;
    if (memcpy_s(&connInfo->connInfo.wlan, sizeof(WlanConnInfo),
        &linkInfo->linkInfo.wlan.connInfo, sizeof(WlanConnInfo)) != EOK) {
        LNN_LOGE(LNN_LANE, "memcpy WlanConnInfo fail");
        return SOFTBUS_MEM_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t Wlan5GInfoProc(const LaneLinkInfo *linkInfo, LaneConnInfo *connInfo)
{
    connInfo->type = LANE_WLAN_5G;
    if (memcpy_s(&connInfo->connInfo.wlan, sizeof(WlanConnInfo),
        &linkInfo->linkInfo.wlan.connInfo, sizeof(WlanConnInfo)) != EOK) {
        LNN_LOGE(LNN_LANE, "memcpy WlanConnInfo fail");
        return SOFTBUS_MEM_ERR;
    }
    return SOFTBUS_OK;
}

static LinkInfoProc g_funcList[LANE_LINK_TYPE_BUTT] = {
    [LANE_WLAN_2P4G] = Wlan2P4GInfoProc,
    [LANE_WLAN_5G] = Wlan5GInfoProc,
};

int32_t LaneInfoProcess(const LaneLinkInfo *linkInfo, LaneConnInfo *connInfo, LaneProfile *profile)
{
    (void)profile;
    if ((linkInfo == NULL) || (connInfo == NULL)) {
        LNN_LOGE(LNN_LANE, "laneInfoProcess param invalid");
        return SOFTBUS_INVALID_PARAM;
    }
    if ((linkInfo->type >= LANE_LINK_TYPE_BUTT) || (g_funcList[linkInfo->type] == NULL)) {
        LNN_LOGE(LNN_LANE, "unsupport linkType=%{public}d", linkInfo->type);
        return SOFTBUS_INVALID_PARAM;
    }
    return g_funcList[linkInfo->type](linkInfo, connInfo);
}
