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

#ifndef LNN_NETWORK_MANAGER_H
#define LNN_NETWORK_MANAGER_H

#include "bus_center_info_key.h"
#include "common_list.h"
#include "lnn_network_manager_struct.h"
#include "softbus_bus_center.h"
#include "softbus_conn_interface.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

int32_t LnnRegistProtocol(LnnProtocolManager *impl);

int32_t LnnInitNetworkManager(void);
int32_t LnnInitNetworkManagerDelay(void);
void LnnDeinitNetworkManager(void);

int32_t LnnGetNetIfTypeByName(const char *ifName, LnnNetIfType *type);
int32_t LnnGetAddrTypeByIfName(const char *ifName, ConnectionAddrType *type);

ListenerModule LnnGetProtocolListenerModule(ProtocolType protocol, ListenerMode mode);

void RestartCoapDiscovery(void);
bool LnnIsAutoNetWorkingEnabled(void);

bool LnnVisitNetif(VisitNetifCallback callback, void *data);
bool LnnVisitProtocol(VisitProtocolCallback callback, void *data);
int32_t RegistIPProtocolManager(void);
int32_t RegistUsbProtocolManager(void);
void LnnSetUnlockState(void);
void LnnGetDataShareInitResult(bool *isDataShareInit);

#ifdef __cplusplus
#if __cplusplus
}
#endif /* __cplusplus */
#endif /* __cplusplus */

#endif /* LNN_NETWORK_MANAGER_H */
