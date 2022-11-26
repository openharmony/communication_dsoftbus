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

#ifndef SOFTBUS_QOS_H
#define SOFTBUS_QOS_H

#include "softbus_def.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

int32_t NotifyQosChannelOpened(const ChannelInfo *chanInfo);
void NotifyQosChannelClosed(int32_t channelId, int32_t channelType);
int32_t QosReportExecute(int channelId, int chanType, int appType, int quality);
int32_t SetDefaultQdisc(void);
int32_t InitQos(void);

#ifdef __cplusplus
}
#endif /* __cplusplus */
#endif