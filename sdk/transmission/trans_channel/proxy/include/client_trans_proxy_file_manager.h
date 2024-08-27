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

#ifndef CLIENT_TRANS_PROXY_FILE_MANAGER_H
#define CLIENT_TRANS_PROXY_FILE_MANAGER_H

#include <stdint.h>

#include "client_trans_file_listener.h"
#include "client_trans_proxy_file_common.h"

#ifdef __linux__
#define MAX_SEND_FILE_NUM 10
#else
#define MAX_SEND_FILE_NUM 1
#endif
#define MAX_FILE_SIZE (0x500000) /* 5M */

#define DEFAULT_NEW_PATH_AUTHORITY (0750)

#define INVALID_NODE_INDEX (-1)

#define FILE_MAGIC_NUMBER 0xBABEFACE

#define PROXY_BR_MAX_PACKET_SIZE (4096 - 48)
#define PROXY_BLE_MAX_PACKET_SIZE (1024 - 48)

#define FRAME_MAGIC_OFFSET 4
#define FRAME_LEN_OFFSET 8
#define FRAME_HEAD_LEN (FRAME_MAGIC_OFFSET + FRAME_LEN_OFFSET)
#define FRAME_DATA_SEQ_OFFSET 4
#define FRAME_CRC_LEN 2
#define FRAME_CRC_CHECK_NUM_LEN 8

#define IS_SEND_RESULT 1
#define IS_RECV_RESULT 0

#define FILE_SEND_ACK_RESULT_SUCCESS 0xFFFFFFFF
#define FILE_SEND_ACK_INTERVAL 32
#define WAIT_START_ACK_TIME 20000
#define WAIT_ACK_TIME 200
#define WAIT_ACK_LAST_TIME 5000
#define WAIT_FRAME_ACK_TIMEOUT_COUNT 24

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    TRANS_FILE_RECV_IDLE_STATE = 0,
    TRANS_FILE_RECV_START_STATE,
    TRANS_FILE_RECV_PROCESS_STATE,
    TRANS_FILE_RECV_ERR_STATE,
} FileRecvState;

typedef enum {
    NODE_IDLE,
    NODE_BUSY,
    NODE_ERR,
} RecvFileNodeStatus;

typedef struct {
    uint32_t magic;
    int32_t frameType;
    uint32_t frameLength;
    uint32_t seq;
    uint16_t crc;
    uint8_t *data;
    uint8_t *fileData;
} FileFrame;

typedef struct {
    SoftBusMutex lock;
    _Atomic uint32_t lockInitFlag;
} TransFileInfoLock;

typedef struct {
    ListNode node;
    int32_t channelId;
    uint32_t count;
    SoftBusMutex sendLock;
} ProxyFileMutexLock;

typedef struct {
    uint32_t startSeq;
    uint32_t seqResult;
} AckResponseData;

typedef struct {
    const char **files;
    uint32_t fileCnt;
    uint64_t bytesProcessed;
    uint64_t bytesTotal;
} FilesInfo;

typedef struct {
    uint32_t seq;
    int32_t fileFd;
    int32_t fileStatus; /* 0: idle 1:busy */
    uint64_t fileOffset;
    uint64_t oneFrameLen;
    uint32_t startSeq;
    uint64_t seqResult;
    uint32_t preStartSeq;
    uint32_t preSeqResult;
    uint64_t fileSize;
    int32_t timeOut;
    uint64_t checkSumCRC;
    char filePath[MAX_FILE_PATH_NAME_LEN];
} SingleFileInfo;

typedef struct {
    ListNode node;
    int32_t sessionId;
    int32_t channelId;
    int32_t osType;
    int32_t fileEncrypt;
    int32_t algorithm;
    int32_t crc;
    int32_t result;
    FileListener fileListener;
    int32_t objRefCount;
    int32_t recvState;
    SingleFileInfo recvFileInfo;
} FileRecipientInfo;

typedef struct {
    ListNode node;
    int32_t channelId;
    int32_t sessionId;
    int32_t fd;
    uint64_t fileSize;
    uint64_t frameNum;
    int32_t fileEncrypt;
    int32_t algorithm;
    int32_t crc;
    uint32_t seq;
    int32_t waitSeq;
    int32_t waitTimeoutCount;
    int32_t result;
    uint64_t checkSumCRC;
    FileListener fileListener;
    FilesInfo totalInfo;
    uint32_t packetSize;
    int32_t osType;
} SendListenerInfo;

int32_t ClinetTransProxyFileManagerInit(void);
void ClinetTransProxyFileManagerDeinit(void);
void ClientDeleteRecvFileList(int32_t sessionId);

int32_t ProxyChannelSendFile(int32_t channelId, const char *sFileList[], const char *dFileList[], uint32_t fileCnt);
int32_t ProcessRecvFileFrameData(int32_t sessionId, int32_t channelId, const FileFrame *oneFrame);
#ifdef __cplusplus
}
#endif
#endif // CLIENT_TRANS_PROXY_FILE_MANAGER_H
