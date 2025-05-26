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

#ifndef LNN_HEARTBEAT_MEDIUM_MGR_H
#define LNN_HEARTBEAT_MEDIUM_MGR_H

#include "lnn_heartbeat_medium_mgr_struct.h"

#ifdef __cplusplus
extern "C" {
#endif

int32_t LnnHbMediumMgrSetParam(void *param);
int32_t LnnHbMediumMgrSendBegin(LnnHeartbeatSendBeginData *custData);
int32_t LnnHbMediumMgrSendEnd(LnnHeartbeatSendEndData *custData);
int32_t LnnHbMediumMgrStop(LnnHeartbeatType *type);
int32_t LnnHbMediumMgrUpdateSendInfo(LnnHeartbeatUpdateInfoType type);
void LnnHbClearRecvList(void);

int32_t LnnHbMediumMgrInit(void);
void LnnHbMediumMgrDeinit(void);

int32_t LnnRegistHeartbeatMediumMgr(LnnHeartbeatMediumMgr *mgr);
int32_t LnnUnRegistHeartbeatMediumMgr(LnnHeartbeatMediumMgr *mgr);

void LnnDumpHbMgrRecvList(void);
void LnnDumpHbOnlineNodeList(void);

#ifdef __cplusplus
}
#endif
#endif /* LNN_HEARTBEAT_MEDIUM_MGR_H */
