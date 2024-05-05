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

#ifndef DISC_EVENT_H
#define DISC_EVENT_H

#include "form/disc_event_form.h"

#ifdef __cplusplus
extern "C" {
#endif

#define DISC_EVENT(scene, stage, extra) DiscEventInner(scene, stage, __FUNCTION__, __LINE__, &(extra))
#define DISC_ALARM(scene, type, extra) DiscAlarmInner(scene, type, __FUNCTION__, __LINE__, &(extra))
#define DISC_STATS(scene, extra) DiscStatsInner(scene, __FUNCTION__, __LINE__, &(extra))
#define DISC_AUDIT(scene, extra) DiscAuditInner(scene, __FUNCTION__, __LINE__, &(extra))

/* For inner use only */
void DiscEventInner(int32_t scene, int32_t stage, const char *func, int32_t line, DiscEventExtra *extra);
void DiscAlarmInner(int32_t scene, int32_t type, const char *func, int32_t line, DiscAlarmExtra *extra);
void DiscStatsInner(int32_t scene, const char *func, int32_t line, DiscStatsExtra *extra);
void DiscAuditInner(int32_t scene, const char *func, int32_t line, DiscAuditExtra *extra);

void DiscEventExtraInit(DiscEventExtra *extra);

#ifdef __cplusplus
}
#endif /* __cplusplus */
#endif // DISC_EVENT_H
