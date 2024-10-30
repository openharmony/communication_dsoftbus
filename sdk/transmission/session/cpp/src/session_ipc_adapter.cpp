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

#include "session_ipc_adapter.h"

#include <string>

#include "accesstoken_kit.h"
#include "ipc_skeleton.h"
#include "tokenid_kit.h"
#include "trans_log.h"

bool CheckIsSystemService(void)
{
    uint32_t tokenId = OHOS::IPCSkeleton::GetSelfTokenID();
    auto type = OHOS::Security::AccessToken::AccessTokenKit::GetTokenTypeFlag(tokenId);
    TRANS_LOGD(TRANS_SDK, "access token type=%{public}d", type);
    if (type == OHOS::Security::AccessToken::TOKEN_NATIVE) {
        return true;
    }
    return false;
}

bool CheckIsNormalApp(const char *sessionName)
{
    #define DBINDER_BUS_NAME_PREFIX "DBinder"
    //The authorization of dbind is granted through Samgr, and there is no control here
    if (strncmp(sessionName, DBINDER_BUS_NAME_PREFIX, strlen(DBINDER_BUS_NAME_PREFIX)) == 0) {
        return false;
    }
    uint64_t selfToken = OHOS::IPCSkeleton::GetSelfTokenID();
    auto tokenType = OHOS::Security::AccessToken::AccessTokenKit::GetTokenTypeFlag(static_cast<uint32_t>(selfToken));
    if (tokenType == OHOS::Security::AccessToken::ATokenTypeEnum::TOKEN_NATIVE) {
        return false;
    } else if (tokenType == OHOS::Security::AccessToken::ATokenTypeEnum::TOKEN_HAP) {
        bool isSystemApp = OHOS::Security::AccessToken::TokenIdKit::IsSystemAppByFullTokenID(selfToken);
        if (isSystemApp) {
            return false;
        }
    }
    TRANS_LOGI(TRANS_SDK, "is normal app");
    return true;
}