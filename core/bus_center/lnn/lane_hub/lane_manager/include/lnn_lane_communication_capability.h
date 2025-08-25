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

#ifndef LNN_LANE_COMMUNICATION_CAPABILITY_H
#define LNN_LANE_COMMUNICATION_CAPABILITY_H

#include "lnn_lane_interface.h"
#include "softbus_bus_center.h"
#include "softbus_common.h"

#ifdef __cplusplus
extern "C" {
#endif

int32_t CheckStaticNetCap(const char *networkId, LaneLinkType linkType);
int32_t CheckDynamicNetCap(const char *networkId, LaneLinkType linkType);
void SetRemoteDynamicNetCap(const char *peerUdid, LaneLinkType linkType);

#ifdef __cplusplus
}
#endif
#endif // LNN_LANE_COMMUNICATION_CAPABILITY_H