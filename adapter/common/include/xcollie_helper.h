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

#ifndef XCOLLIE_HELPER_H
#define XCOLLIE_HELPER_H
#include <stdint.h>
#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

int SetTimer(const char *name, unsigned int timeout, void(*func)(void*), void *args);
void CancelTimer(int id);
void RunOneShotTask(const char *name, void(*task)(void), uint64_t delay);
void RunPeriodicalTask(const char *name, void(*task)(void), uint64_t interval, uint64_t delay);

#ifdef __cplusplus
#if __cplusplus
}
#endif /* __cplusplus */
#endif /* __cplusplus */

#endif
