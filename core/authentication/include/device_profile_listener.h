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
 * See the License for the specific language governing permission and
 * limitations under the License.
 */
 
#ifndef DEVICE_PROFILE_LISTENER_H
#define DEVICE_PROFILE_LISTENER_H

#include <stdint.h>

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif
typedef struct {
    void (*onDeviceProfileAdd)(const char *udid, const char *groupInfo);
    void (*onDeviceProfileDeleted)(const char *udid, int32_t localUserId);
} DeviceProfileChangeListener;

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif
#endif /* DEVICE_PROFILE_LISTENER_H */

