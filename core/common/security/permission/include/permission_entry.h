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

#ifndef PERMISSION_ENTRY_H
#define PERMISSION_ENTRY_H

#include "softbus_def.h"
#include "softbus_permission.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

#define UNKNOWN_VALUE (-1)

typedef enum {
    UDID = 0,
    UUID,
    NETWORKID,
} DevId;

typedef enum {
    LEVEL_PRIVATE = 0,
    LEVEL_PUBLIC,
} SecurityLevel;

typedef struct {
    int32_t permType;
    int32_t uid;
    int32_t pid;
    char *pkgName;
    uint32_t actions;
} SoftBusPermissionItem;

typedef struct {
    ListNode node;
    int32_t type;
    char pkgName[PKG_NAME_SIZE_MAX];
    uint32_t actions;
    int32_t uid;
    int32_t pid;
} SoftBusAppInfo;

typedef struct {
    ListNode node;
    char sessionName[SESSION_NAME_SIZE_MAX];
    int32_t devId;
    bool regexp;
    int32_t secLevel;
    ListNode appInfo;
} SoftBusPermissionEntry;

int32_t LoadPermissionJson(const char *fileName);
void DeinitPermissionJson(void);
int32_t CheckPermissionEntry(const char *sessionName, const SoftBusPermissionItem *pItem);
int32_t IsValidPkgName(int32_t uid, const char *pkgName);
SoftBusPermissionItem *CreatePermissionItem(int32_t permType, int32_t uid, int32_t pid,
    const char *pkgName, uint32_t actions);
bool PermIsSecLevelPublic(const char *sessionName);
int32_t InitDynamicPermission(void);
int32_t AddDynamicPermission(int32_t callingUid, int32_t callingPid, const char *sessionName);
int32_t DeleteDynamicPermission(const char *sessionName);
int32_t CompareString(const char *src, const char *dest, bool regexp);
bool CheckDBinder(const char *sessionName);

#ifdef __cplusplus
#if __cplusplus
}
#endif /* __cplusplus */
#endif /* __cplusplus */

#endif /* PERMISSION_ENTRY_H */
