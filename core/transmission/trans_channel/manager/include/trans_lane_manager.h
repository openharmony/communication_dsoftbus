/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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

#ifndef TRANS_LANE_MANAGER_H
#define TRANS_LANE_MANAGER_H

#include <stdint.h>
#include "lnn_lane_interface.h"
#include "softbus_app_info.h"
#include "softbus_conn_interface.h"
#include "softbus_trans_def.h"
#include "trans_lane_manager_struct.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

int32_t TransLaneMgrInit(void);

int32_t TransSocketLaneMgrInit(void);

void TransLaneMgrDeinit(void);

void TransSocketLaneMgrDeinit(void);

int32_t TransLaneMgrAddLane(
    const TransInfo *transInfo, const LaneConnInfo *connInfo, uint32_t laneHandle, bool isQosLane, AppInfoData *myData);

int32_t TransLaneMgrDelLane(int32_t channelId, int32_t channelType, bool isAsync);

void TransLaneMgrDeathCallback(const char *pkgName, int32_t pid);

int32_t TransGetLaneHandleByChannelId(int32_t channelId, uint32_t *laneHandle);

int32_t TransGetLaneIdByChannelId(int32_t channelId, uint64_t *laneId);

int32_t TransGetChannelInfoByLaneHandle(uint32_t laneHandle, int32_t *channelId, int32_t *channelType);

int32_t TransAddSocketChannelInfo(
    const char *sessionName, int32_t sessionId, int32_t channelId, int32_t channelType, CoreSessionState state);

int32_t TransAddSocketChannelInfoMultipath(
    const char *sessionName, int32_t sessionId, int32_t channelId, int32_t channelType, CoreSessionState state);

int32_t TransUpdateSocketChannelInfo(
    const char *sessionName, int32_t sessionId, bool isUserReserve);

int32_t TransUpdateSocketChannelInfoBySession(
    const char *sessionName, int32_t sessionId, int32_t channelId, int32_t channelType);

int32_t TransUpdateSocketChannelLaneInfoBySession(
    const char *sessionName, int32_t sessionId, uint32_t laneHandle, bool isQosLane, bool isAsync);

int32_t TransDeleteSocketChannelInfoBySession(const char *sessionName, int32_t sessionId);

int32_t TransDeleteSocketChannelInfoByChannel(int32_t channelId, int32_t channelType);

int32_t TransDeleteSocketChannelInfoByPid(int32_t pid);

int32_t TransSetSocketChannelStateBySession(const char *sessionName, int32_t sessionId, CoreSessionState state);

int32_t TransSetSocketChannelStateByChannel(int32_t channelId, int32_t channelType, CoreSessionState state);

int32_t TransGetSocketChannelStateBySession(const char *sessionName, int32_t sessionId, CoreSessionState *state);

int32_t TransGetSocketChannelStateByChannel(int32_t channelId, int32_t channelType, CoreSessionState *state);

int32_t TransGetSocketChannelLaneInfoBySession(
    const char *sessionName, int32_t sessionId, uint32_t *laneHandle, bool *isQosLane, bool *isAsync);

int32_t TransGetPidFromSocketChannelInfoBySession(const char *sessionName, int32_t sessionId, int32_t *pid);

int32_t TransGetConnectTypeByChannelId(int32_t channelId, ConnectType *connectType);

int32_t TransGetTransLaneInfoByLaneHandle(uint32_t laneHandle, TransLaneInfo *laneInfo);

void TransGetMultipathReallocList(ListNode *multipathReallocList);

int32_t TransGetSocketChannelStateReserveBySession(const char *sessionName, int32_t sessionId, CoreSessionState *state);

int32_t TransSetSocketChannelStateReserveBySession(const char *sessionName, int32_t sessionId, CoreSessionState state);

bool CheckNeedReallocSecondLane(int32_t channelId);

int32_t TransAddSessionParamBySessionId(const char *sessionName, int32_t sessionId, const SessionParam *param);

int32_t TransGetSessionParamByChannelId(int32_t channelId, SessionParam *param);

int32_t TransClearSocketChannelInfoReserveBySession(const char *sessionName, int32_t sessionId);

int32_t CopySessionParam(const SessionParam *source, SessionParam *target);

int32_t CopySessionParamExtension(const SessionParam *source, SessionParam *target);

#ifdef __cplusplus
}
#endif /* __cplusplus */
#endif
