/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef AUTH_PRE_LINK_H
#define AUTH_PRE_LINK_H

#include <stdbool.h>
#include <stdint.h>
#include <stdatomic.h>
#include "common_list.h"
#include "softbus_common.h"
#include "auth_attest_interface.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    char uuid[UUID_BUF_LEN];
    ConnectionAddr connAddr;
    int32_t fd;
    uint32_t requestId;
    ListNode node;
} AuthPreLinkNode;

typedef struct {
    bool isValid;
    _Atomic int isParallelGen;
    int32_t requestId;
    SoftbusCertChain *softbusCertChain;
    ListNode node;
} AuthGenCertNode;

int32_t InitAuthPreLinkList(void);
bool IsAuthPreLinkNodeExist(uint32_t requestId);
int32_t AddToAuthPreLinkList(uint32_t requestId, int32_t fd, ConnectionAddr *connAddr);
int32_t FindAuthPreLinkNodeById(uint32_t requestId, AuthPreLinkNode *reuseNode);
int32_t FindAuthPreLinkNodeByUuid(const char *uuid, AuthPreLinkNode *reuseNode);
int32_t UpdateAuthPreLinkUuidById(uint32_t requestId, char *uuid);
void DelAuthPreLinkById(uint32_t requestId);
void DelAuthPreLinkByUuid(char *uuid);
void DeinitAuthPreLinkList(void);

int32_t InitAuthGenCertParallelList(void);
int32_t AddAuthGenCertParaNode(int32_t requestId);
int32_t UpdateAuthGenCertParaNode(int32_t requestId, bool isParallelGen, bool isValid,
    SoftbusCertChain *softbusCertChain);
int32_t FindAndWaitAuthGenCertParaNodeById(int32_t requestId, AuthGenCertNode **genCertParaNode);
void DelAuthGenCertParaNodeById(int32_t requestId);
void DeinitAuthGenCertParallelList(void);

#ifdef __cplusplus
}
#endif
#endif /* AUTH_PRE_LINK_H */