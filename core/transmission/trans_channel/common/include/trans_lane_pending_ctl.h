/*
 * Copyright (c) 2022-2025 Huawei Device Co., Ltd.
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

#include "lnn_lane_interface.h"
#include "softbus_app_info.h"
#include "softbus_conn_interface.h"
#include "softbus_trans_def.h"
#include "trans_lane_pending_ctl_struct.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

int32_t TransReqLanePendingInit(void);
void TransReqLanePendingDeinit(void);
int32_t TransAsyncReqLanePendingInit(void);
void TransAsyncReqLanePendingDeinit(void);
int32_t TransFreeLanePendingInit(void);
void TransFreeLanePendingDeinit(void);

int32_t TransGetConnectOptByConnInfo(const LaneConnInfo *info, ConnectOption *connOpt);
int32_t TransGetLaneInfo(const SessionParam *param, LaneConnInfo *connInfo, uint32_t *laneHandle);
int32_t TransAsyncGetLaneInfo(const SessionParam *param, uint32_t *laneHandle, const AppInfo *appInfo);
int32_t TransGetLaneInfoByOption(const LaneRequestOption *requestOption, LaneConnInfo *connInfo,
    uint32_t *laneHandle, NetWorkingChannelInfo *info);
bool TransGetAuthTypeByNetWorkId(const char *peerNetWorkId);
int32_t TransDeleteLaneReqItemByLaneHandle(uint32_t laneHandle, bool isAsync);

int32_t TransFreeLaneByLaneHandle(uint32_t laneHandle, bool isAsync);

int32_t TransAsyncGetReserveLaneInfoByQos(const SessionParam *param, const LaneAllocInfo *allocInfo,
    uint32_t *laneHandle, uint64_t laneId, const AppInfo *info);

int32_t TransAsyncGetLaneReserveInfo(
    const SessionParam *param, uint32_t *laneHandle, uint64_t laneId, const AppInfo *info);

void ClearSessionParamMemory(SessionParam *param);
#ifdef __cplusplus
}
#endif /* __cplusplus */
#endif
