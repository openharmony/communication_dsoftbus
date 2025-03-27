/*
 * Copyright (c) 2024-2025 Huawei Device Co., Ltd.
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

#include "trans_session_account_adapter.h"

#include "ipc_skeleton.h"
#include "os_account_manager.h"
#include "trans_log.h"
#include "trans_session_manager.h"

using namespace OHOS;

int32_t TransGetUserIdFromUid(int32_t uid)
{
    int32_t userId = INVALID_USER_ID;
    int32_t ret = AccountSA::OsAccountManager::GetOsAccountLocalIdFromUid(uid, userId);
    if (ret != 0) {
        TRANS_LOGE(TRANS_CTRL, "GetOsAccountLocalIdFromUid failed ret=%{public}d.", ret);
    }
    return userId;
}

int32_t TransGetUserIdFromSessionName(const char *sessionName)
{
    int32_t uid;
    int32_t pid;
    int32_t localId = INVALID_USER_ID;
    int32_t ret = TransGetUidAndPid(sessionName, &uid, &pid);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "TransGetUid failed ret=%{public}d.", ret);
        return localId;
    }

    ret = AccountSA::OsAccountManager::GetOsAccountLocalIdFromUid(uid, localId);
    if (ret != 0) {
        TRANS_LOGE(TRANS_CTRL, "GetOsAccountLocalIdFromUid failed ret=%{public}d.", ret);
    }
    return localId;
}
 