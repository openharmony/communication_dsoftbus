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

#include "softbus_access_token_test.h"
#include "accesstoken_kit.h"
#include "nativetoken_kit.h"
#include "softbus_common.h"
#include "token_setproc.h"

void SetAccessTokenPermission(const char *processName)
{
    uint64_t tokenId;
    const char **perms = new const char *[2];
    perms[0] = OHOS_PERMISSION_DISTRIBUTED_DATASYNC;
    perms[1] = OHOS_PERMISSION_DISTRIBUTED_SOFTBUS_CENTER;
    NativeTokenInfoParams infoInstance = {
        .dcapsNum = 0,
        .permsNum = 2,
        .aclsNum = 0,
        .dcaps = nullptr,
        .perms = perms,
        .acls = nullptr,
        .processName = processName,
        .aplStr = "system_basic",
    };
    tokenId = GetAccessTokenId(&infoInstance);
    SetSelfTokenID(tokenId);
    OHOS::Security::AccessToken::AccessTokenKit::ReloadNativeTokenInfo();
}
