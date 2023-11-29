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

#ifndef LNN_TRANS_LANE_H
#define LNN_TRANS_LANE_H

#include "lnn_lane_assign.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    MSG_TYPE_LANE_TRIGGER_LINK = 0,
    MSG_TYPE_LANE_LINK_SUCCESS,
    MSG_TYPE_LANE_LINK_FAIL,
    MSG_TYPE_LANE_LINK_EXCEPTION,
    MSG_TYPE_DELAY_DESTROY_LINK,
} LaneMsgType;

LaneInterface *TransLaneGetInstance(void);
int32_t GetQosInfoByLaneId(uint32_t laneId, QosInfo *qosOpt);
int32_t LnnLanePostMsgToHandler(int32_t msgType, uint64_t param1, uint64_t param2,
    void *obj, uint64_t delayMillis);

#ifdef __cplusplus
}
#endif
#endif
