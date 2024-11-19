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

#ifndef STATS_EVENT_H
#define STATS_EVENT_H

#include "form/stats_event_form.h"

#ifdef __cplusplus
extern "C" {
#endif

#define DSOFTBUS_STATS(scene, extra) StatsEventInner(scene, __FUNCTION__, __LINE__, &(extra))

/* For inner use only */
void StatsEventInner(int32_t scene, const char *func, int32_t line, StatsEventExtra *extra);

#ifdef __cplusplus
}
#endif /* __cplusplus */
#endif // STATS_EVENT_H
