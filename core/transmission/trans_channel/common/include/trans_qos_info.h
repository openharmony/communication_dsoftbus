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

#ifndef TRANS_QOS_INFO_H
#define TRANS_QOS_INFO_H

#include "softbus_trans_def.h"
#include "lnn_lane_interface.h"

#ifdef __cplusplus
extern "C"{
#endif /* __cplusplus */

void GetExtQosInfo(const SessionParam *param, QosInfo *qosInfo, uint32_t index, AllocExtendInfo *extendInfo);
#ifdef __cplusplus
}
#endif /* __cplusplus */
#endif // TRANS_QOS_INFO_H