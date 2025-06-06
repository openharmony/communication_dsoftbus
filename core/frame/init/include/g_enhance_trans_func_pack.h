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
#ifndef G_ENHANCE_TRANS_FUNC_PACK_H
#define G_ENHANCE_TRANS_FUNC_PACK_H

#include <stdint.h>

#include "lnn_lane_interface_struct.h"
#include "softbus_trans_def.h"
#include "softbus_def.h"

#ifdef __cplusplus
extern "C" {
#endif

int32_t SetDefaultQdiscPacked(void);
int32_t InitQosPacked(void);
void NotifyQosChannelClosedPacked(int32_t channelId, int32_t channelType);
void GetExtQosInfoPacked(const SessionParam *param, QosInfo *qosInfo, uint32_t index, AllocExtendInfo *extendInfo);
int32_t NotifyQosChannelOpenedPacked(const ChannelInfo *chanInfo);

#ifdef __cplusplus
}
#endif

#endif