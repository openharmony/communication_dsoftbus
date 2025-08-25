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

#ifndef SOFTBUS_ADAPTER_BT_COMMON_H
#define SOFTBUS_ADAPTER_BT_COMMON_H

#include "softbus_adapter_thread.h"
#include "softbus_adapter_bt_common_struct.h"

#ifdef __cplusplus
extern "C" {
#endif

int SoftBusEnableBt(void);

int SoftBusDisableBt(void);

int SoftBusGetBtState(void);

int SoftBusGetBrState(void);

int SoftBusGetBtMacAddr(SoftBusBtAddr *mac);

int SoftBusGetBtName(unsigned char *name, unsigned int *len);

int SoftBusSetBtName(const char *name);

int SoftBusAddBtStateListener(const SoftBusBtStateListener *listener, int *listenerId);

int SoftBusRemoveBtStateListener(int listenerId);

void SoftBusComputeWaitBleSendDataTime(uint32_t waitMillis, SoftBusSysTime *outtime);

int SoftBusGetRandomAddress(const char *addr, char *out, int tokenId);

int SoftBusBtInit(void);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* SOFTBUS_ADAPTER_BT_COMMON_H */