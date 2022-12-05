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

#ifndef LNN_LANE_LINK_H
#define LNN_LANE_LINK_H

#include <stdint.h>
#include "lnn_lane_info.h"

#ifdef __cplusplus
extern "C" {
#endif
int32_t LnnLanePendingInit(void);
void LnnLanePendingDeinit(void);
int32_t LnnConnectP2p(const char *networkId, int32_t pid, LnnLaneP2pInfo *p2pInfo);
int32_t LnnDisconnectP2p(const char *networkId, int32_t pid, const char *mac);

#ifdef __cplusplus
}
#endif
#endif /* LNN_LANE_LINK_H */