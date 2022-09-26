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

#ifndef P2PLINK_COMMON_H
#define P2PLINK_COMMON_H

#include <stdbool.h>
#include "p2plink_type.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

P2pLinkRole P2pLinkGetRole(void);
void P2pLinkSetRole(P2pLinkRole role);

void P2pLinkCommonInit(void);
void P2pLinkCommonClean(void);

void P2pLinkSetMyMacExpired(bool isExpired);
void P2pLinkSetMyIp(const char *ip);
char* P2pLinkGetMyIp(void);
char* P2pLinkGetMyMac(void);

void P2pLinkSetGoIp(const char *ip);
void P2pLinkSetGoMac(const char *mac);
void P2pLinkSetGoPort(int32_t port);
char* P2pLinkGetGoIp(void);
char* P2pLinkGetGoMac(void);
int32_t P2pLinkGetGoPort(void);
void P2pLinkSetGcPort(int32_t port);
int32_t P2pLinkGetGcPort(void);

void P2pLinkSetState(bool state);
bool P2pLinkIsEnable(void);

void P2pLinkSetDhcpState(bool isNeedDhcp);
bool P2pLinkGetDhcpState(void);

bool P2pLinkIsDisconnectState(void);
void P2pLinkSetDisconnectState(bool state);

#ifdef __cplusplus
#if __cplusplus
}
#endif /* __cplusplus */
#endif /* __cplusplus */

#endif
