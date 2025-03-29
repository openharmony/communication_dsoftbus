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

#ifndef CLIENT_TRANS_TCP_DIRECT_MESSAGE_H
#define CLIENT_TRANS_TCP_DIRECT_MESSAGE_H

#include "softbus_def.h"

#ifdef __cplusplus
extern "C" {
#endif

int32_t TransTdcRecvData(int32_t channelId);

int32_t TransDataListInit(void);
void TransDataListDeinit(void);
int32_t TransDelDataBufNode(int32_t channelId);
int32_t TransAddDataBufNode(int32_t channelId, int32_t fd);
int32_t TransTdcSendBytes(int32_t channelId, const char *data, uint32_t len, bool needAck);
int32_t TransTdcAsyncSendBytes(int32_t channelId, const char *data, uint32_t len, uint32_t dataSeq);
int32_t TransTdcSendMessage(int32_t channelId, const char *data, uint32_t len);

#ifdef __cplusplus
}
#endif
#endif // CLIENT_TRANS_TCP_DIRECT_MESSAGE_H