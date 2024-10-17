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

#ifndef LNN_NET_BUILDER_PROCESS_H
#define LNN_NET_BUILDER_PROCESS_H

#include <stdint.h>

#include "auth_interface.h"
#include "lnn_event.h"
#include "lnn_sync_info_manager.h"
#include "softbus_bus_center.h"
#include "lnn_connection_fsm.h"


#ifdef __cplusplus
extern "C" {
#endif

LnnConnectionFsm *FindConnectionFsmByRequestId(uint32_t requestId);
int32_t FindRequestIdByAddr(ConnectionAddr *connetionAddr, uint32_t *requestId);
void NetBuilderMessageHandler(SoftBusMessage *msg);
LnnConnectionFsm *FindConnectionFsmByAddr(const ConnectionAddr *addr, bool isShort);
LnnConnectionFsm *StartNewConnectionFsm(const ConnectionAddr *addr, const char *pkgName, bool isNeedConnect);
void StopConnectionFsm(LnnConnectionFsm *connFsm);

#ifdef __cplusplus
}
#endif

#endif