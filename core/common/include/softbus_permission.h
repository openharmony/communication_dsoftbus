/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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

#ifndef SOFTBUS_PERMISSION_H
#define SOFTBUS_PERMISSION_H

#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

#define ACTION_CREATE 0x1
#define ACTION_OPEN 0x2

enum {
    SYSTEM_APP = 0,
    NATIVE_APP,
    SELF_APP,
    NORMAL_APP,
    GRANTED_APP,
};

int32_t TransPermissionInit(void);
void TransPermissionDeinit(void);
int32_t CheckTransPermission(pid_t callingUid, pid_t callingPid,
    const char *pkgName, const char *sessionName, uint32_t actions);
int32_t CheckTransSecLevel(const char *mySessionName, const char *peerSessionName);
bool CheckDiscPermission(pid_t callingUid, const char *pkgName);
bool CheckBusCenterPermission(pid_t callingUid, const char *pkgName);
int32_t GrantTransPermission(int32_t callingUid, int32_t callingPid, const char *sessionName);
int32_t RemoveTransPermission(const char *sessionName);

#ifdef __cplusplus
#if __cplusplus
}
#endif /* __cplusplus */
#endif /* __cplusplus */

#endif /* SOFTBUS_PERMISSION_H */
