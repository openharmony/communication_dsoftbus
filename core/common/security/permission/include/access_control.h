/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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

#ifndef ACCESS_CONTROL_H
#define ACCESS_CONTROL_H

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

// if the upstream module does not set the first caller tokenID, the value is 0
#define TOKENID_NOT_SET 0

enum FirstTokenType {
    FOREGROUND_APP_TYPE = 1,
    BACKGROUND_APP_TYPE = 2,
    TOKEN_HAP_TYPE = 3,
    SYSTEM_SA_TYPE = 4,
    TOKEN_SHELL_TYPE = 5,
};

int32_t TransCheckClientAccessControl(const char *peerNetworkId);
int32_t CheckSecLevelPublic(const char *mySessionName, const char *peerSessionName);
int32_t TransCheckServerAccessControl(uint64_t callingTokenId);
uint64_t TransACLGetFirstTokenID(void);
uint64_t TransACLGetCallingTokenID(void);
void TransGetTokenInfo(uint64_t callingId, char *tokenName, int32_t nameLen, int32_t *tokenType);

#ifdef __cplusplus
#if __cplusplus
}
#endif /* __cplusplus */
#endif /* __cplusplus */

#endif /* ACCESS_CONTROL_H */
