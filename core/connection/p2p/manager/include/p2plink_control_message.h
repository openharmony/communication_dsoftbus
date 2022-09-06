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

#ifndef P2PLINK_CONTROL_MESSAGE_H
#define P2PLINK_CONTROL_MESSAGE_H

#include <stdio.h>
#include "cJSON.h"
#include "p2plink_device.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

void P2pLinkControlMsgProc(int64_t authId, int64_t seq, P2pLinkCmdType type, const cJSON *root);
int32_t P2pLinkSendHandshake(P2pLinkAuthId *chan, char *myMac, char *myIp);
int32_t P2pLinkSendDisConnect(const P2pLinkAuthId *chan, const char *myMac);
int32_t P2pLinkSendReuse(P2pLinkAuthId *chan, char *myMac);
void P2pLinkonAuthChannelClose(int64_t authId);
#ifdef __cplusplus
#if __cplusplus
}
#endif /* __cplusplus */
#endif /* __cplusplus */
#endif /* P2PLINK_CONTROL_MESSAGE_H */
