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

#ifndef LNN_EVENT_H
#define LNN_EVENT_H

#include "form/lnn_event_form.h"

#ifdef __cplusplus
extern "C" {
#endif

#define LNN_EVENT(scene, stage, extra) LnnEventInner(scene, stage, __FUNCTION__, __LINE__, &(extra))
#define LNN_ALARM(scene, type, extra) LnnAlarmInner(scene, type, __FUNCTION__, __LINE__, &(extra))
#define LNN_STATS(scene, extra) LnnStatsInner(scene, __FUNCTION__, __LINE__, &(extra))
#define LNN_AUDIT(scene, extra) LnnAuditInner(scene, __FUNCTION__, __LINE__, &(extra))

/* For inner use only */
void LnnEventInner(int32_t scene, int32_t stage, const char *func, int32_t line, LnnEventExtra *extra);
void LnnAlarmInner(int32_t scene, int32_t type, const char *func, int32_t line, LnnAlarmExtra *extra);
void LnnStatsInner(int32_t scene, const char *func, int32_t line, LnnStatsExtra *extra);
void LnnAuditInner(int32_t scene, const char *func, int32_t line, LnnAuditExtra *extra);

void LnnEventExtraInit(LnnEventExtra *extra);

#ifdef __cplusplus
}
#endif /* __cplusplus */
#endif // LNN_EVENT_H
