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

#ifndef P2PLINK_REFERENCE_H
#define P2PLINK_REFERENCE_H

#include "stdint.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

void P2pLinkInitRef(void);

int32_t P2pLinkGetMyP2pRef(void);
void P2pLinkDelMyP2pRef(void);
void P2pLinkAddMyP2pRef(void);

void P2pLinkAddPidMacRef(int32_t pid, const char *mac);
void P2pLinkDelPidMacRef(int32_t pid, const char *mac);

void P2pLinkRefClean(void);
void DisConnectByPid(int32_t pid);

int32_t P2pLinGetMacRefCnt(int32_t pid, const char *mac);
void P2pLinkDumpRef(void);
void P2pLinkMyP2pRefClean(void);

#ifdef __cplusplus
#if __cplusplus
}
#endif /* __cplusplus */
#endif /* __cplusplus */
#endif /* P2PLINK_REFERENCE_H */