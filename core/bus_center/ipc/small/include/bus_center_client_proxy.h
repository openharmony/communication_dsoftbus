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

#ifndef BUS_CENTER_CLIENT_PROXY_H
#define BUS_CENTER_CLIENT_PROXY_H

#include <stdbool.h>
#include <stdint.h>
#include "softbus_bus_center.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

int32_t ClientOnJoinLNNResult(const char *pkgName, void *addr, uint32_t addrTypeLen,
    const char *networkId, int32_t retCode);
int32_t ClientOnLeaveLNNResult(const char *pkgName, const char *networkId, int32_t retCode);
int32_t ClinetOnNodeOnlineStateChanged(bool isOnline, void *info, uint32_t infoTypeLen);
int32_t ClinetOnNodeBasicInfoChanged(void *info, uint32_t infoTypeLen, int32_t type);
int32_t ClientOnTimeSyncResult(
    const char *pkgName, int32_t pid, const void *info, uint32_t infoTypeLen, int32_t retCode);
int32_t ClientOnPublishLNNResult(const char *pkgName, int32_t pid, int32_t publishId, int32_t reason);
int32_t ClientOnRefreshLNNResult(const char *pkgName, int32_t pid, int32_t refreshId, int32_t reason);
int32_t ClientOnRefreshDeviceFound(const char *pkgName, int32_t pid, const void *device, uint32_t deviceLen);

#ifdef __cplusplus
#if __cplusplus
}
#endif /* __cplusplus */
#endif /* __cplusplus */

#endif
