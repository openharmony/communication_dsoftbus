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

#include "stdint.h"

#include "access_control.h"
#include "softbus_error_code.h"

int32_t TransCheckClientAccessControl(const char *peerNetworkId)
{
    (void)peerNetworkId;
    return SOFTBUS_OK;
}

int32_t CheckSecLevelPublic(const char *mySessionName, const char *peerSessionName)
{
    (void)mySessionName;
    (void)peerSessionName;
    return SOFTBUS_OK;
}

int32_t TransCheckServerAccessControl(uint64_t firstCallingId)
{
    (void)firstCallingId;
    return SOFTBUS_OK;
}
uint64_t TransACLGetFirstTokenID(void)
{
    return TOKENID_NOT_SET;
}

uint64_t TransACLGetCallingTokenID(void)
{
    return TOKENID_NOT_SET;
}

void TransGetTokenInfo(uint64_t callingId, char *tokenName, int32_t nameLen, int32_t *tokenType)
{
    (void)callingId;
    (void)tokenName;
    (void)nameLen;
    (void)tokenType;
}
