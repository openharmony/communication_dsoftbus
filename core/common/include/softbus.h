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

#ifndef SOFT_BUS_H
#define SOFT_BUS_H

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

enum SoftBusEvent {
    EVENT_SERVER_DEATH = 1,
    EVENT_SERVER_RECOVERY = 2,
    EVENT_BUTT
};

typedef int (*EventCallback)(void *arg, unsigned int argLen, void *userData);

int RegisterEventCallback(enum SoftBusEvent event, EventCallback cb, void *userData);

#ifdef __cplusplus
#if __cplusplus
}
#endif /* __cplusplus */
#endif /* __cplusplus */

#endif /* SOFT_BUS_H */
