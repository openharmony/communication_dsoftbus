/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "auth_pre_link.h"

#include "auth_log.h"
#include "softbus_error_code.h"

int32_t InitAuthPreLinkList(void)
{
    return SOFTBUS_OK;
}

bool IsAuthPreLinkNodeExist(uint32_t requestId)
{
    (void)requestId;
    return false;
}

int32_t AddToAuthPreLinkList(uint32_t requestId, int32_t fd, ConnectionAddr *connAddr)
{
    (void)requestId;
    (void)fd;
    (void)connAddr;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t FindAuthPreLinkNodeById(uint32_t requestId, AuthPreLinkNode *reuseNode)
{
    (void)requestId;
    (void)reuseNode;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t FindAuthPreLinkNodeByUuid(const char *uuid, AuthPreLinkNode *reuseNode)
{
    (void)uuid;
    (void)reuseNode;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t UpdateAuthPreLinkUuidById(uint32_t requestId, const char *uuid)
{
    (void)requestId;
    (void)uuid;
    return SOFTBUS_NOT_IMPLEMENT;
}

void DelAuthPreLinkById(uint32_t requestId)
{
    (void)requestId;
}

void DelAuthPreLinkByUuid(const char *uuid)
{
    (void)uuid;
}

void DeinitAuthPreLinkList(void)
{
}

int32_t InitAuthGenCertParallelList(void)
{
    return SOFTBUS_OK;
}

int32_t AddAuthGenCertParaNode(int32_t requestId)
{
    (void)requestId;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t UpdateAuthGenCertParaNode(int32_t requestId, bool isValid, SoftbusCertChain *softbusCertChain)
{
    (void)requestId;
    (void)isValid;
    (void)softbusCertChain;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t FindAndWaitAuthGenCertParaNodeById(int32_t requestId, AuthGenCertNode **genCertParaNode)
{
    (void)requestId;
    (void)genCertParaNode;
    return SOFTBUS_NOT_IMPLEMENT;
}

void DelAuthGenCertParaNodeById(int32_t requestId)
{
    (void)requestId;
}

void DeinitAuthGenCertParallelList(void)
{
}
