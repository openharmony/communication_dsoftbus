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

#ifndef CLIENT_TRANS_PROXY_CHANNEL_H
#define CLIENT_TRANS_PROXY_CHANNEL_H

#include "client_trans_file_listener.h"
#include "client_trans_session_callback.h"
#include "softbus_def.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifdef __linux__
#define MAX_FILE_NUM 1
#else
#define MAX_FILE_NUM 1
#endif
#define MAX_FILE_PATH_NAME_LEN (256)
#define MAX_REMOTE_PATH_LEN (512)

#define FRAME_DATA_SEQ_OFFSET (4)
#define PROXY_MAX_PACKET_SIZE (1 * 1024)
#define MAX_FILE_SIZE (0x500000) /* 5M */

#define PATH_SEPARATOR '/'
#define DEFAULT_NEW_PATH_AUTHORITY (0750)

#define INVALID_NODE_INDEX (-1)
#define INVALID_FD (-1)

typedef struct {
    uint32_t seqCount;
    SoftBusMutex lock;
    uint32_t seqLockInitFlag;
}SendFileInfo;

typedef struct {
    uint8_t *buffer;
    uint32_t bufferSize;
}FileListBuffer;

typedef struct {
    int32_t frameType;
    int32_t frameLength;
    uint8_t *data;
} FileFrame;

typedef enum {
    NODE_IDLE,
    NODE_BUSY,
    NODE_ERR,
} RecvFileNodeStatus;

typedef struct {
    int32_t index;
    uint32_t seq;
    int32_t fileFd;
    int32_t fileStatus; /* 0: idle 1:busy */
    uint64_t fileOffset;
    int32_t timeOut;
    char filePath[MAX_REMOTE_PATH_LEN];
}SingleFileInfo;

typedef struct {
    SoftBusMutex lock;
    int32_t curIndex;
    int32_t sessionId;
    FileListener fileListener;
    SingleFileInfo recvFileInfo[MAX_FILE_NUM];
}RecvFileInfo;

int32_t ClinetTransProxyInit(const IClientSessionCallBack *cb);

int32_t ClientTransProxyOnChannelOpened(const char *sessionName, const ChannelInfo *channel);

int32_t ClientTransProxyOnChannelClosed(int32_t channelId);

int32_t ClientTransProxyOnChannelOpenFailed(int32_t channelId);

int32_t ClientTransProxyOnDataReceived(int32_t channelId,
    const void *data, uint32_t len, SessionPktType type);

void ClientTransProxyCloseChannel(int32_t channelId);

int32_t TransProxyChannelSendBytes(int32_t channelId, const void *data, uint32_t len);

int32_t TransProxyChannelSendMessage(int32_t channelId, const void *data, uint32_t len);

int32_t TransProxyChannelSendFile(int32_t channelId, const char *sFileList[], const char *dFileList[],
    uint32_t fileCnt);

int32_t ProcessFileFrameData(int32_t        sessionId, FileListener fileListener, const char *data, int32_t len,
    int32_t type);

int32_t ProcessFileListData(int32_t        sessionId, FileListener fileListener, const char *data, int32_t len);

#ifdef __cplusplus
}
#endif
#endif
