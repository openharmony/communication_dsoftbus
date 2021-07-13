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

#ifndef DISC_CLIENT_PROXY_H

#include <stdint.h>
#include "discovery_service.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

int32_t ClientIpcOnDeviceFound(const char *pkgName, const DeviceInfo *device);
int32_t ClientIpcOnDiscoverFailed(const char *pkgName, int subscribeId, int failReason);
int32_t ClientIpcDiscoverySuccess(const char *pkgName, int subscribeId);
int32_t ClientIpcOnPublishSuccess(const char *pkgName, int publishId);
int32_t ClientIpcOnPublishFail(const char *pkgName, int publishId, int reason);

#ifdef __cplusplus
#if __cplusplus
}
#endif /* __cplusplus */
#endif /* __cplusplus */

#endif // !DISC_CLIENT_PROXY_H
