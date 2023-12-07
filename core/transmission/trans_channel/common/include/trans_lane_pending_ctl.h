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

#ifndef TRANS_LANE_PENDING_CTL_H
#define TRANS_LANE_PENDING_CTL_H

#include <stdint.h>

#include "lnn_lane_interface.h"
#include "session.h"
#include "softbus_conn_interface.h"
#include "softbus_trans_def.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

int32_t TransReqLanePendingInit(void);
void TransReqLanePendingDeinit(void);

LaneTransType TransGetLaneTransTypeBySession(const SessionParam *param);
int32_t TransGetConnectOptByConnInfo(const LaneConnInfo *info, ConnectOption *connOpt);
int32_t TransGetLaneInfo(const SessionParam *param, LaneConnInfo *connInfo, uint32_t *laneId);
int32_t TransGetLaneInfoByOption(bool isQosLane, const LaneRequestOption *requestOption, LaneConnInfo *connInfo,
    uint32_t *laneId);
bool TransGetAuthTypeByNetWorkId(const char *peerNetWorkId);

#ifdef __cplusplus
}
#endif /* __cplusplus */
#endif

