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

#ifndef CLIENT_TRANS_FILE_LISTENER_H
#define CLIENT_TRANS_FILE_LISTENER_H

#include "session.h"
#include "softbus_def.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef void (*SocketFileCallbackFunc)(int32_t socket, FileEvent *event);

typedef struct {
    ListNode node;
    char mySessionName[SESSION_NAME_SIZE_MAX];
    IFileSendListener sendListener;
    IFileReceiveListener recvListener;
    char rootDir[FILE_RECV_ROOT_DIR_SIZE_MAX];
    SocketFileCallbackFunc socketSendCallback;
    SocketFileCallbackFunc socketRecvCallback;
} FileListener;

int TransFileInit(void);

void TransFileDeinit(void);

int32_t TransSetFileReceiveListener(const char *sessionName,
    const IFileReceiveListener *recvListener, const char *rootDir);

int32_t TransSetFileSendListener(const char *sessionName, const IFileSendListener *sendListener);

int32_t TransGetFileListener(const char *sessionName, FileListener *fileListener);

void TransDeleteFileListener(const char *sessionName);

int32_t TransSetSocketFileListener(const char *sessionName, SocketFileCallbackFunc fileCallback, bool isReceiver);
#ifdef __cplusplus
}
#endif
#endif // CLIENT_TRANS_FILE_LISTENER_H