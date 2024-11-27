/*
 * Copyright (C) 2021-2023 Huawei Device Co., Ltd.
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

#ifndef NSTACKX_DFINDER_HIEVENT_H
#define NSTACKX_DFINDER_HIEVENT_H
#include "nstackx.h"

#ifdef __cplusplus
extern "C" {
#endif

int SetEventFunc(void *softobj, DFinderEventFunc func);
int SetEventFuncDirectly(void *softobj, DFinderEventFunc func);
void ResetEventFunc(void);
void NotifyStatisticsEvent(void);

#ifdef __cplusplus
}
#endif

#endif
