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

#ifndef LNN_LANE_INFO_H
#define LNN_LANE_INFO_H

#include <stdint.h>
#include "softbus_bus_center.h"

#ifdef __cplusplus
extern "C" {
#endif

#define LNN_REQUEST_MAX_LANE_NUM 1
/* Link type */
typedef enum {
    LNN_LINK_TYPE_WLAN_5G = 0x0,
    LNN_LINK_TYPE_WLAN_2P4G,
    LNN_LINK_TYPE_BR,
    LNN_LINK_TYPE_BUTT,
} LnnLaneLinkType;

typedef struct {
    bool isProxy;
    ConnectionAddr conOption;
} LnnLaneInfo;

typedef enum {
    LNN_MESSAGE_LANE = 1,
    LNN_BYTES_LANE,
    LNN_FILE_LANE,
    LNN_STREAM_LANE,
    LNN_LANE_PROPERTY_BUTT,
} LnnLaneProperty;

ConnectionAddrType LnnGetLaneType(int32_t laneId);
void LnnReleaseLane(int32_t laneId);
const LnnLaneInfo *LnnGetConnection(int32_t laneId);
bool LnnUpdateLaneRemoteInfo(const char *netWorkId, LnnLaneLinkType type, bool mode);
void LnnLanesInit(void);

#ifdef __cplusplus
}
#endif
#endif /* LNN_LANE_INFO_H */