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

#ifndef CLIENT_TRANS_FILE_H
#define CLIENT_TRANS_FILE_H

#include "client_trans_udp_manager.h"
#include "softbus_def.h"

#ifdef __cplusplus
extern "C" {
#endif

void RegisterFileCb(const UdpChannelMgrCb *fileCb);

int32_t TransOnFileChannelOpened(const ChannelInfo *channel, int32_t *filePort);

void TransCloseFileChannel(int32_t dfileId);

int32_t TransSendFile(int32_t channelId, const char *sFileList[], const char *dFileList[], uint32_t fileCnt);
#ifdef __cplusplus
}
#endif
#endif // CLIENT_TRANS_FILE_H