/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef LNN_LANE_POWER_CONTROL_H
#define LNN_LANE_POWER_CONTROL_H

#include <stdint.h>
#include "lnn_lane_interface.h"

#ifdef __cplusplus
extern "C" {
#endif

#define LNN_MAC_LEN 18

typedef struct {
    LaneLinkType linkType;
    char wifiDirectMac[LNN_MAC_LEN];
    uint32_t bandWidth;
} WifiDirectLinkInfo;

int32_t EnablePowerControl(const WifiDirectLinkInfo *wifiDirectInfo);
void DisablePowerControl(const WifiDirectLinkInfo *wifiDirectInfo);

#ifdef __cplusplus
}
#endif
#endif // LNN_LANE_POWER_CONTROL_H