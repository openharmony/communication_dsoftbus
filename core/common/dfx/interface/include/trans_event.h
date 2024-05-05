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

#ifndef TRANS_EVENT_H
#define TRANS_EVENT_H

#include "form/trans_event_form.h"

#ifdef __cplusplus
extern "C" {
#endif

#define TRANS_EVENT(scene, stage, extra) TransEventInner(scene, stage, __FUNCTION__, __LINE__, &(extra))
#define TRANS_ALARM(scene, type, extra) TransAlarmInner(scene, type, __FUNCTION__, __LINE__, &(extra))
#define TRANS_STATS(scene, extra) TransStatsInner(scene, __FUNCTION__, __LINE__, &(extra))
#define TRANS_AUDIT(scene, extra) TransAuditInner(scene, __FUNCTION__, __LINE__, &(extra))

/* For inner use only */
void TransEventInner(int32_t scene, int32_t stage, const char *func, int32_t line, TransEventExtra *extra);
void TransAlarmInner(int32_t scene, int32_t type, const char *func, int32_t line, TransAlarmExtra *extra);
void TransStatsInner(int32_t scene, const char *func, int32_t line, TransStatsExtra *extra);
void TransAuditInner(int32_t scene, const char *func, int32_t line, TransAuditExtra *extra);

#ifdef __cplusplus
}
#endif /* __cplusplus */
#endif // TRANS_EVENT_H
