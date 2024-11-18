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

#ifndef CONN_EVENT_H
#define CONN_EVENT_H

#include "form/conn_event_form.h"


#ifdef __cplusplus
extern "C" {
#endif

#define CONN_EVENT(scene, stage, extra) ConnEventInner(scene, stage, __FUNCTION__, __LINE__, &extra)
#define CONN_ALARM(scene, type, extra) ConnAlarmInner(scene, type, __FUNCTION__, __LINE__, &extra)
#define CONN_STATS(scene, extra) ConnStatsInner(scene, __FUNCTION__, __LINE__, &extra)
#define CONN_AUDIT(scene, extra) ConnAuditInner(scene, __FUNCTION__, __LINE__, &extra)

/* For inner use only */
void ConnEventInner(int32_t scene, int32_t stage, const char *func, int32_t line, ConnEventExtra *extra);
void ConnAlarmInner(int32_t scene, int32_t type, const char *func, int32_t line, ConnAlarmExtra *extra);
void ConnStatsInner(int32_t scene, const char *func, int32_t line, ConnStatsExtra *extra);
void ConnAuditInner(int32_t scene, const char *func, int32_t line, ConnAuditExtra *extra);

#ifdef __cplusplus
}
#endif /* __cplusplus */
#endif // CONN_EVENT_H
