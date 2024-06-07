/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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

#ifndef CLIENT_TRANS_PROXY_FILE_HELPER_H
#define CLIENT_TRANS_PROXY_FILE_HELPER_H

#include <stdint.h>

#include "client_trans_file_listener.h"
#include "client_trans_proxy_file_common.h"
#include "client_trans_proxy_file_manager.h"

#ifdef __cplusplus
extern "C" {
#endif

int32_t ProxyChannelSendFileStream(int32_t channelId, const char *data, uint32_t len, int32_t type);

int32_t SendFileTransResult(int32_t channelId, uint32_t seq, int32_t result, uint32_t side);

int32_t UnpackFileTransResultFrame(
    const uint8_t *data, uint32_t len, uint32_t *seq, int32_t *result, uint32_t *side);

int32_t SendFileAckReqAndResData(int32_t channelId, uint32_t startSeq, uint32_t value, int32_t type);

int32_t UnpackAckReqAndResData(FileFrame *frame, uint32_t *startSeq, uint32_t *value);

int64_t PackReadFileData(FileFrame *fileFrame, uint64_t readLength, uint64_t fileOffset, SendListenerInfo *info);

int32_t UnpackFileDataFrame(FileRecipientInfo *info, FileFrame *fileFrame, uint32_t *fileDataLen);

int32_t AckResponseDataHandle(const SendListenerInfo *info, const char *data, uint32_t len);

char *GetFullRecvPath(const char *filePath, const char *recvRootDir);

int32_t CreateDirAndGetAbsPath(const char *filePath, char *recvAbsPath, int32_t pathSize);

#ifdef __cplusplus
}
#endif
#endif // CLIENT_TRANS_PROXY_FILE_HELPER_H
