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

#ifndef LNN_CONNECTION_FSM_PROCESS_H
#define LNN_CONNECTION_FSM_PROCESS_H

#include <stdint.h>

#include "lnn_connection_fsm.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

bool CheckInterfaceCommonArgs(const LnnConnectionFsm *connFsm, bool needCheckDead);
void NotifyJoinResult(LnnConnectionFsm *connFsm, const char *networkId, int32_t retCode);
void FreeUnhandledMessage(int32_t msgType, void *para);
void ReportDeviceOnlineEvt(const char *udid, NodeBasicInfo *peerDevInfo);

#ifdef __cplusplus
#if __cplusplus
}
#endif /* __cplusplus */
#endif /* __cplusplus */

#endif /* LNN_CONNECTION_FSM_PROCESS_H */