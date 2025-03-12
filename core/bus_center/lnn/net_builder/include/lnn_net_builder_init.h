/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#ifndef LNN_NET_BUILDER_INIT_H
#define LNN_NET_BUILDER_INIT_H

#include <stdint.h>

#include "auth_interface.h"
#include "lnn_event.h"
#include "lnn_sync_info_manager.h"
#include "softbus_bus_center.h"

#ifdef __cplusplus
extern "C" {
#endif

void InitiateNewNetworkOnline(ConnectionAddrType addrType, const char *networkId);
void TryElectAsMasterState(const char *networkId, bool isOnline);
bool IsSupportMasterNodeElect(SoftBusVersion version);
int32_t TryElectMasterNodeOnline(const LnnConnectionFsm *connFsm);
int32_t TryElectMasterNodeOffline(const LnnConnectionFsm *connFsm);
int32_t PostJoinRequestToConnFsm(LnnConnectionFsm *connFsm, const JoinLnnMsgPara *para, bool needReportFailure);
void SetBeginJoinLnnTime(LnnConnectionFsm *connFsm);
LnnConnectionFsm *FindConnectionFsmByConnFsmId(uint16_t connFsmId);
void TryInitiateNewNetworkOnline(const LnnConnectionFsm *connFsm);
void TryNotifyAllTypeOffline(const LnnConnectionFsm *connFsm);
void TryDisconnectAllConnection(const LnnConnectionFsm *connFsm);
void NotifyStateForSession(const ConnectionAddr *para);

#ifdef __cplusplus
}
#endif

#endif