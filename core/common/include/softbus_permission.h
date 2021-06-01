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

#ifndef SOFTBUS_PERMISSION_H
#define SOFTBUS_PERMISSION_H

#include <stdint.h>

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

#define PERMISSION_JSON_FILE "/system/etc/communication/softbus/permission.json"

#define ACTION_CREATE 0x1
#define ACTION_OPEN 0x2

enum {
    SYSTEM_APP = 0,
    NATIVE_APP,
    SELF_APP,
    NORMAL_APP,
    GRANTED_APP,
};

int32_t TransPermissionInit(const char *fileName);
void TransPermissionDeinit(void);
int32_t CheckTransPermission(const char *pkgName, const char *SessionName, uint32_t action);
bool CheckDiscPermission(const char *pkgName);
bool CheckBusCenterPermission(const char *pkgName);

#ifdef __cplusplus
#if __cplusplus
}
#endif /* __cplusplus */
#endif /* __cplusplus */

#endif /* SOFTBUS_PERMISSION_H */
