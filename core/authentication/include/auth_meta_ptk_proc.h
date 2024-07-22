/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef AUTH_META_PTK_PROC_H
#define AUTH_META_PTK_PROC_H

#include "auth_interface.h"
#include "lnn_node_info.h"
#include "softbus_common.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

int32_t AuthGetPtkSyncInfoByAuthId(int64_t authId, bool *syncDone, int32_t *reason);
int32_t AuthAddPtkSyncInfoForPendingList(AuthHandle authHandle, const NodeInfo *nodeInfo);
int32_t AuthDelPtkSyncInfoFromPendingList(int64_t authId);
int32_t AuthWaitingRequestCallback(int64_t authId);
int32_t AuthNotifyResultByUuid(const char *uuid, int32_t reason, int64_t *authId);
int32_t UpdateAuthSyncPtkInfoStatus(int64_t authId);
int64_t GetAuthIdFromAuthSyncPtkInfo(const char *uuid);
int32_t AuthMetaInitPtkProc(void);
void AuthMetaDeinitPtkProc(void);

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif
#endif /* AUTH_META_PTK_PROC_H */
