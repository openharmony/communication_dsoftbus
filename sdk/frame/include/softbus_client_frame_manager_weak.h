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

#ifndef SOFTBUS_CLIENT_FRAME_MANAGER_WEAK_H
#define SOFTBUS_CLIENT_FRAME_MANAGER_WEAK_H

#ifdef __cplusplus
extern "C" {
#endif

int __attribute__ ((weak)) EventClientInit(void);
void __attribute__ ((weak))EventClientDeinit(void);

int __attribute__ ((weak)) BusCenterClientInit(void);
void __attribute__ ((weak))BusCenterClientDeinit(void);

int __attribute__ ((weak)) DiscClientInit(void);
void __attribute__ ((weak)) DiscClientDeinit(void);

int __attribute__ ((weak)) TransClientInit(void);
void __attribute__ ((weak))TransClientDeinit(void);

#ifdef __cplusplus
}
#endif

#endif // SOFTBUS_CLIENT_FRAME_MANAGER_WEAK_H

