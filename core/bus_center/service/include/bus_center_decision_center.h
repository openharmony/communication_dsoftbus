/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef BUS_CENTER_DECISION_CENTER_H
#define BUS_CENTER_DECISION_CENTER_H

#include <stdint.h>
#include "bus_center_event.h"
#include "softbus_conn_interface.h"

#ifdef __cplusplus
extern "C" {
#endif

int32_t InitDecisionCenter(void);
void DeinitDecisionCenter(void);
void LnnDCReportConnectException(const ConnectOption *option, int32_t errorCode);
void LnnDCClearConnectException(const ConnectOption *option);
void LnnDCProcessOnlineState(bool isOnline, const NodeBasicInfo *info);

#ifdef __cplusplus
}
#endif
#endif //BUS_CENTER_DECISION_CENTER_H