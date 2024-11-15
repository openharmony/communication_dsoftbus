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

#include "auth_meta_ptk_proc.h"

int32_t AuthGetPtkSyncInfoByAuthId(int64_t authId, bool *syncDone, int32_t *reason)
{
    (void)authId;
    (void)syncDone;
    (void)reason;
    return SOFTBUS_OK;
}

int32_t AuthAddPtkSyncInfoForPendingList(AuthHandle authHandle, const NodeInfo *nodeInfo)
{
    (void)authHandle;
    (void)nodeInfo;
    return SOFTBUS_OK;
}

int32_t AuthDelPtkSyncInfoFromPendingList(int64_t authId)
{
    (void)authId;
    return SOFTBUS_OK;
}

int32_t AuthWaitingRequestCallback(int64_t authId)
{
    (void)authId;
    return SOFTBUS_OK;
}

int32_t AuthNotifyResultByUuid(const char *uuid, int32_t reason, int64_t *authId)
{
    (void)uuid;
    (void)reason;
    (void)authId;
    return SOFTBUS_OK;
}

int32_t UpdateAuthSyncPtkInfoStatus(int64_t authId)
{
    (void)authId;
    return SOFTBUS_OK;
}

int32_t AuthMetaInitPtkProc(void)
{
    return SOFTBUS_OK;
}

void AuthMetaDeinitPtkProc(void)
{
    return;
}
