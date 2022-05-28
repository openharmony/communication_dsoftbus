/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include "client_trans_proxy_file_manager.h"

#include "client_trans_pending.h"
#include "client_trans_proxy_file_common.h"
#include "client_trans_session_manager.h"
#include "client_trans_tcp_direct_message.h"
#include "securec.h"
#include "softbus_adapter_errcode.h"
#include "softbus_adapter_file.h"
#include "softbus_adapter_mem.h"
#include "softbus_adapter_timer.h"
#include "softbus_app_info.h"
#include "softbus_conn_interface.h"
#include "softbus_def.h"
#include "softbus_errcode.h"
#include "softbus_log.h"
#include "softbus_type_def.h"
#include "softbus_utils.h"
#include "trans_server_proxy.h"

// FILE_SEND_ACK_INTERVAL max 32
#define FILE_SEND_ACK_RESULT_SUCCESS 0xFFFFFFFF
#define FILE_SEND_ACK_INTERVAL 32
#define WAIT_START_ACK_TIME 2000
#define WAIT_ACK_TIME 100
#define WAIT_ACK_LAST_TIME 500
// WAIT_FRAME_ACK_TIMEOUT_COUNT < FILE_SEND_ACK_INTERVAL
#define WAIT_FRAME_ACK_TIMEOUT_COUNT 10

typedef struct {
    int32_t index;
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
    int32_t fileEncrypt;
    int32_t algorithm;
    int32_t crc;
    int32_t result;
    FileListener fileListener;
    int32_t curRecvIndex;
    SingleFileInfo recvFileInfo[MAX_RECV_FILE_NUM]; // 接收超时时使用下一个
} FileRecipientInfo;

typedef struct {
    ListNode node;
    int32_t channelId;
    int32_t sessionId;
    int32_t fd;
    uint64_t fileSize;
    int32_t fileEncrypt;
    int32_t algorithm;
    int32_t crc;
    uint32_t seq;
    int32_t waitSeq;
    int32_t waitTimeoutCount;
    int32_t result;
    uint64_t checkSumCRC;
    FileListener fileListener;
} SendListenerInfo;

typedef struct {
    ListNode node;
    int32_t channelId;
    uint32_t count;
    SoftBusMutex sendLock;
} ProxyFileMutexLock;

static TransFileInfoLock g_sendFileInfoLock = {
    .lock = 0,
    .lockInitFlag = false,
};

static TransFileInfoLock g_recvFileInfoLock = {
    .lock = 0,
    .lockInitFlag = false,
};

static LIST_HEAD(g_sessionFileLockList);
static LIST_HEAD(g_sendListenerInfoList);
static LIST_HEAD(g_recvRecipientInfoList);

static int32_t ProxyChannelSendFileStream(int32_t channelId, const char *data, uint32_t len, int32_t type)
{
    int32_t ret = ServerIpcSendMessage(channelId, CHANNEL_TYPE_PROXY, data, len, type);
    if (ret == SOFTBUS_CONNECTION_ERR_SENDQUEUE_FULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_WARN, "send queue full %d", ret);
    }
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_DBG, "send msg(%d): type=%d, ret=%d", channelId, type, ret);
    return ret;
}

static int32_t SendFileTransResult(int32_t channelId, uint32_t seq, int32_t result, uint32_t side)
{
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "send file result seq %u side %u result %d", seq, side, result);
    uint32_t len = FRAME_HEAD_LEN + FRAME_DATA_SEQ_OFFSET + sizeof(uint32_t) + sizeof(int32_t);
    char *data = (char *)SoftBusCalloc(len);
    if (data == NULL) {
        return SOFTBUS_MALLOC_ERR;
    }
    *(uint32_t *)data = FILE_MAGIC_NUMBER;
    *(uint64_t *)(data + FRAME_MAGIC_OFFSET) = (FRAME_DATA_SEQ_OFFSET + sizeof(uint32_t) + sizeof(int32_t));
    *(uint32_t *)(data + FRAME_HEAD_LEN) = seq;
    *(uint32_t *)(data + FRAME_HEAD_LEN + FRAME_DATA_SEQ_OFFSET) = side;
    *(int32_t *)(data + FRAME_HEAD_LEN + FRAME_DATA_SEQ_OFFSET + sizeof(uint32_t)) = result;

    int32_t ret = ProxyChannelSendFileStream(channelId, data, len, TRANS_SESSION_FILE_RESULT_FRAME);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "conn send trans result fail %d", ret);
        SoftBusFree(data);
        return ret;
    }
    SoftBusFree(data);
    return SOFTBUS_OK;
}

static int32_t UnpackFileTransResultFrame(const uint8_t *data, uint32_t len, uint32_t *seq,
    int32_t *result, uint32_t *side)
{
    if (seq == NULL || result == NULL || side == NULL) {
        return SOFTBUS_ERR;
    }
    if (data == NULL || len < FRAME_HEAD_LEN + FRAME_DATA_SEQ_OFFSET + FRAME_DATA_SEQ_OFFSET) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "recv ack response len: %u fail", len);
        return SOFTBUS_TRANS_INVALID_DATA_LENGTH;
    }
    uint32_t magic = *(uint32_t *)data;
    uint64_t dataLen = *(uint64_t *)(data + FRAME_MAGIC_OFFSET);
    if (magic != FILE_MAGIC_NUMBER || dataLen != (FRAME_DATA_SEQ_OFFSET + sizeof(uint32_t) + sizeof(int32_t))) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "recv ack response head fail: %u %" PRIu64, magic, dataLen);
        return SOFTBUS_INVALID_DATA_HEAD;
    }
    (*seq) = (*(uint32_t *)(data + FRAME_HEAD_LEN));
    (*side) = (*(uint32_t *)(data + FRAME_HEAD_LEN + FRAME_DATA_SEQ_OFFSET));
    (*result) = (*(int32_t *)(data + FRAME_HEAD_LEN + FRAME_DATA_SEQ_OFFSET + sizeof(uint32_t)));
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "seq %u side %u result %d", *seq, *side, *result);
    return SOFTBUS_OK;
}

static void ProxyFileTransTimerProc(void)
{
#define FILE_TRANS_TIMEOUT 10
    if (SoftBusMutexLock(&g_recvFileInfoLock.lock) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "lock file timer failed");
        return;
    }
    FileRecipientInfo *info = NULL;
    FileRecipientInfo *next = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(info, next, &g_recvRecipientInfoList, FileRecipientInfo, node) {
        for (int32_t i = 0; i < MAX_RECV_FILE_NUM; i++) {
            if (info->recvFileInfo[i].fileStatus != NODE_BUSY) {
                continue;
            }
            if (info->recvFileInfo[i].timeOut >= FILE_TRANS_TIMEOUT) {
                SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "file %s recv timeout",
                    info->recvFileInfo[i].filePath);
                info->recvFileInfo[i].fileStatus = NODE_ERR;
                info->recvFileInfo[i].timeOut = 0;
                (void)FileUnLock(info->recvFileInfo[i].fileFd);
                SoftBusCloseFile(info->recvFileInfo[i].fileFd);
                SoftBusRemoveFile(info->recvFileInfo[i].filePath);
                (void)SendFileTransResult(info->channelId, info->recvFileInfo[i].seq, SOFTBUS_TIMOUT, IS_RECV_RESULT);
                if (info->fileListener.recvListener.OnFileTransError != NULL) {
                    info->fileListener.recvListener.OnFileTransError(info->sessionId);
                }
                ListDelete(&info->node);
                SoftBusFree(info);
            } else {
                info->recvFileInfo[i].timeOut++;
            }
        }
    }
    (void)SoftBusMutexUnlock(&g_recvFileInfoLock.lock);
}

int32_t ClinetTransProxyFileManagerInit(void)
{
    if (g_sendFileInfoLock.lockInitFlag == false) {
        if (SoftBusMutexInit(&g_sendFileInfoLock.lock, NULL) != SOFTBUS_OK) {
            SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "sendfile mutex init fail!");
            return SOFTBUS_ERR;
        }
        g_sendFileInfoLock.lockInitFlag = true;
    }
    if (g_recvFileInfoLock.lockInitFlag == false) {
        if (SoftBusMutexInit(&g_recvFileInfoLock.lock, NULL) != SOFTBUS_OK) {
            SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "sendfile mutex init fail!");
            return SOFTBUS_ERR;
        }
        g_recvFileInfoLock.lockInitFlag = true;
    }
    if (InitPendingPacket() != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "InitPendingPacket fail!");
        return SOFTBUS_ERR;
    }
    if (RegisterTimeoutCallback(SOFTBUS_PROXY_SENDFILE_TIMER_FUN, ProxyFileTransTimerProc) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "register sendfile timer fail");
    }
    return SOFTBUS_OK;
}

void ClinetTransProxyFileManagerDeinit(void)
{
    (void)RegisterTimeoutCallback(SOFTBUS_PROXY_SENDFILE_TIMER_FUN, NULL);
    if (SoftBusMutexDestroy(&g_sendFileInfoLock.lock) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "destroy send file lock fail");
    }
    g_sendFileInfoLock.lockInitFlag = false;
    if (SoftBusMutexDestroy(&g_recvFileInfoLock.lock) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "destroy recv file lock fail");
    }
    g_recvFileInfoLock.lockInitFlag = false;
}

static int32_t SendFileAckReqAndResData(int32_t channelId, uint32_t startSeq, uint32_t value, int32_t type)
{
    uint32_t len = FRAME_HEAD_LEN + FRAME_DATA_SEQ_OFFSET + FRAME_DATA_SEQ_OFFSET;
    char *data = (char *)SoftBusCalloc(len);
    if (data == NULL) {
        return SOFTBUS_MALLOC_ERR;
    }
    *(uint32_t *)data = FILE_MAGIC_NUMBER;
    *(int64_t *)(data + FRAME_MAGIC_OFFSET) = (FRAME_DATA_SEQ_OFFSET + FRAME_DATA_SEQ_OFFSET);
    *(uint32_t *)(data + FRAME_HEAD_LEN) = startSeq;
    *(uint32_t *)(data + FRAME_HEAD_LEN + FRAME_DATA_SEQ_OFFSET) = value;
    int32_t ret = ProxyChannelSendFileStream(channelId, data, len, type);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "conn send ack buf fail %d", ret);
        SoftBusFree(data);
        return ret;
    }
    SoftBusFree(data);
    return SOFTBUS_OK;
}

static int32_t UnpackAckReqAndResData(FileFrame *frame, uint32_t *startSeq, uint32_t *value)
{
    if (frame == NULL || startSeq == NULL || value == NULL) {
        return SOFTBUS_ERR;
    }
    if (frame->frameLength < FRAME_HEAD_LEN + FRAME_DATA_SEQ_OFFSET + FRAME_DATA_SEQ_OFFSET) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "unpack ack data len %d fail", frame->frameLength);
        return SOFTBUS_TRANS_INVALID_DATA_LENGTH;
    }
    frame->magic = (*(uint32_t *)(frame->data));
    uint64_t dataLen = (*(uint64_t *)(frame->data + FRAME_MAGIC_OFFSET));
    if (frame->magic != FILE_MAGIC_NUMBER || dataLen < FRAME_DATA_SEQ_OFFSET + FRAME_DATA_SEQ_OFFSET) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "unpack ack head fail. magic %u, len: %" PRIu64,
            frame->magic, dataLen);
        return SOFTBUS_INVALID_DATA_HEAD;
    }
    frame->fileData = frame->data + FRAME_HEAD_LEN;
    (*startSeq) = (*(uint64_t *)(frame->fileData));
    (*value) = (*(uint64_t *)(frame->fileData + FRAME_DATA_SEQ_OFFSET));
    return SOFTBUS_OK;
}

static int64_t PackReadFileData(FileFrame *fileFrame, int32_t fd, uint64_t readLength, uint64_t fileOffset,
    SendListenerInfo *info)
{
    int64_t len = SoftBusPreadFile(fd, fileFrame->fileData + FRAME_DATA_SEQ_OFFSET, readLength, fileOffset);
    if (len <= 0) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "pread src file failed. ret: %d", len);
        return len;
    }
    if (info->crc == APP_INFO_SUPPORT) {
        uint64_t dataLen = len + FRAME_DATA_SEQ_OFFSET;
        fileFrame->frameLength = FRAME_HEAD_LEN + dataLen + FRAME_CRC_LEN;
        if (fileFrame->frameLength > PROXY_MAX_PACKET_SIZE) {
            return SOFTBUS_ERR;
        }
        uint16_t crc = RTU_CRC(fileFrame->fileData + FRAME_DATA_SEQ_OFFSET, len);
        (*(uint32_t *)(fileFrame->data)) = fileFrame->magic;
        (*(uint64_t *)(fileFrame->data + FRAME_MAGIC_OFFSET)) = dataLen;
        info->seq++;
        (*(uint32_t *)(fileFrame->fileData)) = info->seq;
        (*(uint16_t *)(fileFrame->fileData + dataLen)) = crc;
        info->checkSumCRC += crc;
    } else {
        fileFrame->frameLength = FRAME_DATA_SEQ_OFFSET + len;
        if (fileFrame->frameLength > PROXY_MAX_PACKET_SIZE) {
            return SOFTBUS_ERR;
        }
        (*(int32_t *)(fileFrame->fileData)) = info->channelId;
    }

    return len;
}

static int32_t UnpackFileDataFrame(FileRecipientInfo *info, FileFrame *fileFrame, uint32_t *fileDataLen)
{
    if (info->crc == APP_INFO_SUPPORT) {
        if (fileFrame->frameLength <= FRAME_HEAD_LEN + FRAME_DATA_SEQ_OFFSET + FRAME_CRC_LEN) {
            return SOFTBUS_TRANS_INVALID_DATA_LENGTH;
        }
        fileFrame->magic = (*(uint32_t *)(fileFrame->data));
        uint64_t dataLen = (*(uint64_t *)(fileFrame->data + FRAME_MAGIC_OFFSET));
        if (fileFrame->magic != FILE_MAGIC_NUMBER ||
            (dataLen + FRAME_HEAD_LEN + FRAME_CRC_LEN) != fileFrame->frameLength) {
            SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "unpack data frame failed. magic: %u, dataLen: %" PRIu64,
                fileFrame->magic, dataLen);
            return SOFTBUS_INVALID_DATA_HEAD;
        }
        fileFrame->fileData = fileFrame->data + FRAME_HEAD_LEN;
        fileFrame->seq = (*(uint32_t *)(fileFrame->fileData));
        uint16_t recvCRC = (*(uint16_t *)(fileFrame->fileData + dataLen));
        uint16_t crc = RTU_CRC(fileFrame->fileData + FRAME_DATA_SEQ_OFFSET, dataLen - FRAME_DATA_SEQ_OFFSET);
        if (crc != recvCRC) {
            SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "crc check fail recv crc: %u, crc: %u",
                (uint32_t)recvCRC, (uint32_t)crc);
            return SOFTBUS_ERR;
        }
        info->recvFileInfo[info->curRecvIndex].checkSumCRC += crc;
        *fileDataLen = dataLen;
    } else {
        fileFrame->fileData = fileFrame->data;
        fileFrame->seq = (*(uint32_t *)(fileFrame->fileData));
        if (fileFrame->frameLength <= FRAME_DATA_SEQ_OFFSET) {
            return SOFTBUS_TRANS_INVALID_DATA_LENGTH;
        }
        *fileDataLen = fileFrame->frameLength;
    }

    return SOFTBUS_OK;
}

static int32_t RetransFileFrameBySeq(const SendListenerInfo *info, int32_t seq)
{
    if (info->crc != APP_INFO_SUPPORT) {
        return SOFTBUS_OK;
    }
    if (seq <= 0) {
        return SOFTBUS_ERR;
    }
    FileFrame fileFrame = {0};
    fileFrame.data = (uint8_t *)SoftBusCalloc(PROXY_MAX_PACKET_SIZE);
    if (fileFrame.data == NULL) {
        return SOFTBUS_MALLOC_ERR;
    }
    fileFrame.magic = FILE_MAGIC_NUMBER;
    fileFrame.fileData = fileFrame.data + FRAME_HEAD_LEN;
    uint64_t frameDataSize = PROXY_MAX_PACKET_SIZE - FRAME_HEAD_LEN - FRAME_DATA_SEQ_OFFSET - FRAME_CRC_LEN;
    uint64_t fileOffset = frameDataSize * ((uint32_t)seq - 1);
    if (fileOffset >= info->fileSize) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "retrans file frame failed, seq: %d", seq);
        SoftBusFree(fileFrame.data);
        return SOFTBUS_INVALID_PARAM;
    }
    uint64_t remainedSize = info->fileSize - fileOffset;
    uint64_t readLength = (remainedSize < frameDataSize) ? remainedSize : frameDataSize;
    int64_t len = PackReadFileData(&fileFrame, info->fd, readLength, fileOffset, (SendListenerInfo *)info);
    if (len <= 0) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "retrans file frame failed");
        SoftBusFree(fileFrame.data);
        return SOFTBUS_ERR;
    }
    SoftBusFree(fileFrame.data);
    return SOFTBUS_OK;
}

static int32_t AckResponseDataHandle(const SendListenerInfo *info, const char *data, uint32_t len)
{
    if (data == NULL || len < FRAME_HEAD_LEN + FRAME_DATA_SEQ_OFFSET + FRAME_DATA_SEQ_OFFSET) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "recv ack response len: %u fail", len);
        return SOFTBUS_TRANS_INVALID_DATA_LENGTH;
    }
    uint32_t magic = *(uint32_t *)data;
    uint64_t dataLen = *(uint64_t *)(data + FRAME_MAGIC_OFFSET);
    if (magic != FILE_MAGIC_NUMBER || dataLen != (FRAME_DATA_SEQ_OFFSET + FRAME_DATA_SEQ_OFFSET)) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "recv ack response fail head: %u %" PRIu64, magic, dataLen);
        return SOFTBUS_INVALID_DATA_HEAD;
    }
    uint32_t startSeq = *(uint32_t *)(data + FRAME_HEAD_LEN);
    uint32_t seqResult = *(uint32_t *)(data + FRAME_HEAD_LEN + FRAME_DATA_SEQ_OFFSET);
    if (seqResult != FILE_SEND_ACK_RESULT_SUCCESS) {
        uint32_t failSeq;
        for (int32_t i = 0; i < FILE_SEND_ACK_INTERVAL; i++) {
            if (((seqResult >> i) & 0x01) == 0x01) {
                continue;
            }
            failSeq = startSeq + i;
            if (RetransFileFrameBySeq(info, failSeq) != SOFTBUS_OK) {
                return SOFTBUS_ERR;
            }
        }
    }
    return SOFTBUS_OK;
}

static int32_t GetAndCheckRealPath(const char *filePath, char *absPath)
{
    if ((filePath == NULL) || (absPath == NULL)) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "input invalid");
        return SOFTBUS_ERR;
    }

    if (SoftBusRealPath(filePath, absPath) == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "softbus realpath failed");
        return SOFTBUS_ERR;
    }

    int32_t pathLength = strlen(absPath);
    if (pathLength > (MAX_FILE_PATH_NAME_LEN - 1)) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "pathLength[%d] is too large", pathLength);
        return SOFTBUS_ERR;
    }

    return SOFTBUS_OK;
}

static bool IsPathValid(char *filePath)
{
    if (filePath == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "filePath is null");
        return false;
    }
    if ((strlen(filePath) == 0) || (strlen(filePath) > (MAX_FILE_PATH_NAME_LEN - 1))) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "filePath size[%d] is wrong", (int32_t)strlen(filePath));
        return false;
    }

    if (filePath[strlen(filePath) - 1] == PATH_SEPARATOR) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "filePath is end with '/' ");
        return false;
    }
    return true;
}

static bool CheckDestFilePathValid(const char *destFile)
{
    if (destFile == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "destFile is null");
        return false;
    }
    int32_t len = strlen(destFile);
    if ((len == 0) || (len > MAX_FILE_PATH_NAME_LEN) || (destFile[0] == PATH_SEPARATOR)) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "destFile first char is '/'");
        return false;
    }

    if (strstr(destFile, "..") != NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "dest path is not canonical form");
        return false;
    }
    return true;
}

static char *GetFullRecvPath(const char *filePath, const char *recvRootDir)
{
    if ((filePath == NULL) || (recvRootDir == NULL)) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "filePath or rootDir is null");
        return NULL;
    }

    int32_t rootDirLength = strlen(recvRootDir);
    int32_t filePathLength = strlen(filePath);
    bool isNeedAddSep = true;
    if (((filePathLength > 0) && (filePath[0] == PATH_SEPARATOR)) ||
        ((rootDirLength > 0) && (recvRootDir[rootDirLength - 1] == PATH_SEPARATOR))) {
        isNeedAddSep = false;
    }

    int32_t destFullPathLength = (isNeedAddSep) ? (rootDirLength + sizeof('/') + filePathLength) :
        (rootDirLength + filePathLength);
    char *recvFullPath = (char *)SoftBusCalloc(destFullPathLength + 1);
    if (recvFullPath == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "recvFullPath is null");
        return NULL;
    }

    int32_t ret;
    if (isNeedAddSep) {
        ret = sprintf_s(recvFullPath, destFullPathLength + 1, "%s%c%s", recvRootDir, PATH_SEPARATOR, filePath);
    } else {
        ret = sprintf_s(recvFullPath, destFullPathLength + 1, "%s%s", recvRootDir, filePath);
    }
    if (ret < 0) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "create fullPath fail");
        SoftBusFree(recvFullPath);
        return NULL;
    }
    return recvFullPath;
}

static int32_t GetDirPath(const char *fullPath, char *dirPath, int32_t dirPathLen)
{
    if ((fullPath == NULL) || (strlen(fullPath) < 1) || (fullPath[strlen(fullPath) - 1] == PATH_SEPARATOR)) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "invalid input param");
        return SOFTBUS_ERR;
    }
    int32_t i = 0;
    int32_t dirFullLen = (int32_t)strlen(fullPath);
    for (i = dirFullLen - 1; i >= 0; i--) {
        if (fullPath[i] == PATH_SEPARATOR) {
            i++;
            break;
        }
        if (i == 0) {
            break;
        }
    }
    int32_t dirLen = i;
    if (dirLen >= dirPathLen) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "dirLen[%d] >= dirPathLen[%d]", dirLen, dirPathLen);
        return SOFTBUS_ERR;
    }

    if (strncpy_s(dirPath, dirPathLen, fullPath, dirLen) != EOK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "strcpy_s dir path error, dirLen[%d]", dirLen);
        return SOFTBUS_ERR;
    }

    return SOFTBUS_OK;
}

static int32_t GetFileName(const char *fullPath, char *fileName, int32_t fileNameLen)
{
    if ((fullPath == NULL) || (strlen(fullPath) < 1) || (fullPath[strlen(fullPath) - 1] == PATH_SEPARATOR)) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "invalid input param");
        return SOFTBUS_ERR;
    }
    int32_t i;
    int32_t dirFullLen = (int32_t)strlen(fullPath);
    for (i = dirFullLen - 1; i >= 0; i--) {
        if (fullPath[i] == PATH_SEPARATOR) {
            i++;
            break;
        }
        if (i == 0) {
            break;
        }
    }

    if (strcpy_s(fileName, fileNameLen, fullPath + i) != EOK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "strcpy_s filename error, fileNameLen[%d]", fileNameLen);
        return SOFTBUS_ERR;
    }

    return SOFTBUS_OK;
}

static int32_t GetAbsFullPath(const char *fullPath, char *recvAbsPath, int32_t pathSize)
{
    char *dirPath = (char *)SoftBusCalloc(MAX_FILE_PATH_NAME_LEN);
    if (dirPath == NULL) {
        return SOFTBUS_MALLOC_ERR;
    }
    if (GetDirPath(fullPath, dirPath, MAX_FILE_PATH_NAME_LEN) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "get dir path failed");
        SoftBusFree(dirPath);
        return SOFTBUS_ERR;
    }
    char *absFullDir = (char *)SoftBusCalloc(PATH_MAX + 1);
    if (absFullDir == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "calloc absFullDir failed");
        SoftBusFree(dirPath);
        return SOFTBUS_MALLOC_ERR;
    }
    if (GetAndCheckRealPath(dirPath, absFullDir) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "get full abs file failed");
        goto EXIT_ERR;
    }
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "dirPath[%s], realFullDir[%s]", dirPath, absFullDir);
    char *fileName = dirPath;
    memset_s(fileName, MAX_FILE_PATH_NAME_LEN, 0, MAX_FILE_PATH_NAME_LEN);
    if (GetFileName(fullPath, fileName, MAX_FILE_PATH_NAME_LEN) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "get file name failed");
        goto EXIT_ERR;
    }
    int32_t fileNameLength = strlen(fileName);
    int32_t dirPathLength = strlen(absFullDir);
    if (pathSize < (fileNameLength + dirPathLength + 1)) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "copy name is too large, dirLen:%d, fileNameLen:%d",
            dirPathLength, fileNameLength);
        goto EXIT_ERR;
    }
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "fileName[%s][%d]", fileName, fileNameLength);
    if (sprintf_s(recvAbsPath, pathSize, "%s/%s", absFullDir, fileName) < 0) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "memcpy filename error");
        goto EXIT_ERR;
    }
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "recvAbsPath[%s]", recvAbsPath);
    SoftBusFree(absFullDir);
    SoftBusFree(dirPath);
    return SOFTBUS_OK;
EXIT_ERR:
    SoftBusFree(dirPath);
    SoftBusFree(absFullDir);
    return SOFTBUS_ERR;
}

static int32_t CreateDirAndGetAbsPath(const char *filePath, char *recvAbsPath, int32_t pathSize)
{
    if ((filePath == NULL) || (recvAbsPath == NULL)) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "invalid input");
        return SOFTBUS_ERR;
    }
    uint32_t len = (uint32_t)strlen(filePath);
    int32_t ret;
    char *tempPath = (char *)SoftBusCalloc(len + 1);
    if (tempPath == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "calloc tempPath failed");
        return SOFTBUS_ERR;
    }
    for (uint32_t i = 0; i < len; i++) {
        tempPath[i] = filePath[i];
        if (tempPath[i] != PATH_SEPARATOR) {
            continue;
        }
        if (SoftBusAccessFile(tempPath, SOFTBUS_F_OK) != SOFTBUS_OK) {
            ret = SoftBusMakeDir(tempPath, DEFAULT_NEW_PATH_AUTHORITY);
            if (ret == SOFTBUS_ADAPTER_ERR) {
                SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "mkdir failed(%d)", errno);
                SoftBusFree(tempPath);
                return SOFTBUS_ERR;
            }
        }
    }

    SoftBusFree(tempPath);
    if (GetAbsFullPath(filePath, recvAbsPath, pathSize) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "dest dir is invalid");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t FrameIndexToType(uint64_t index, uint64_t frameNumber)
{
#define FRAME_NUM_0 0
#define FRAME_NUM_1 1
#define FRAME_NUM_2 2
    if (index == FRAME_NUM_0) {
        return TRANS_SESSION_FILE_FIRST_FRAME;
    }

    if ((index == FRAME_NUM_1) && (frameNumber == FRAME_NUM_2)) {
        return TRANS_SESSION_FILE_ONLYONE_FRAME;
    }

    if (index == (frameNumber - 1)) {
        return TRANS_SESSION_FILE_LAST_FRAME;
    }

    return TRANS_SESSION_FILE_ONGOINE_FRAME;
}

static ProxyFileMutexLock *GetSessionFileLock(int32_t channelId)
{
    if (SoftBusMutexLock(&g_sendFileInfoLock.lock) != 0) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "lock mutex failed");
        return NULL;
    }
    ProxyFileMutexLock *item = NULL;
    ProxyFileMutexLock *sessionLock = NULL;
    LIST_FOR_EACH_ENTRY(item, &g_sessionFileLockList, ProxyFileMutexLock, node) {
        if (item->channelId == channelId) {
            sessionLock = item;
            break;
        }
    }
    if (sessionLock != NULL) {
        sessionLock->count++;
        (void)SoftBusMutexUnlock(&g_sendFileInfoLock.lock);
        return sessionLock;
    }
    sessionLock = (ProxyFileMutexLock *)SoftBusCalloc(sizeof(ProxyFileMutexLock));
    if (sessionLock == NULL) {
        (void)SoftBusMutexUnlock(&g_sendFileInfoLock.lock);
        return NULL;
    }
    if (SoftBusMutexInit(&sessionLock->sendLock, NULL) != SOFTBUS_OK) {
        (void)SoftBusMutexUnlock(&g_sendFileInfoLock.lock);
        SoftBusFree(sessionLock);
        return NULL;
    }
    ListInit(&sessionLock->node);
    sessionLock->count = 1;
    sessionLock->channelId = channelId;
    ListAdd(&g_sessionFileLockList, &sessionLock->node);
    (void)SoftBusMutexUnlock(&g_sendFileInfoLock.lock);
    return sessionLock;
}

static void DelSessionFileLock(int32_t channelId)
{
    if (SoftBusMutexLock(&g_sendFileInfoLock.lock) != 0) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "lock mutex failed");
        return;
    }
    ProxyFileMutexLock *item = NULL;
    ProxyFileMutexLock *sessionLock = NULL;
    LIST_FOR_EACH_ENTRY(item, &g_sessionFileLockList, ProxyFileMutexLock, node) {
        if (item->channelId == channelId) {
            sessionLock = item;
            break;
        }
    }
    if (sessionLock == NULL) {
        (void)SoftBusMutexUnlock(&g_sendFileInfoLock.lock);
        return;
    }
    sessionLock->count--;
    if (sessionLock->count <= 0) {
        ListDelete(&sessionLock->node);
        (void)SoftBusMutexDestroy(&sessionLock->sendLock);
        SoftBusFree(sessionLock);
    }
    (void)SoftBusMutexUnlock(&g_sendFileInfoLock.lock);
}

static int32_t AddSendListenerInfo(SendListenerInfo *info)
{
    if (SoftBusMutexLock(&g_sendFileInfoLock.lock) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "proxy add send info SoftBusMutexLock failed");
        return SOFTBUS_LOCK_ERR;
    }
    SendListenerInfo *item = NULL;
    LIST_FOR_EACH_ENTRY(item, &g_sendListenerInfoList, SendListenerInfo, node) {
        if (item->sessionId == info->sessionId) {
            SoftBusMutexUnlock(&g_sendFileInfoLock.lock);
            return SOFTBUS_ALREADY_EXISTED;
        }
    }
    ListTailInsert(&g_sendListenerInfoList, &info->node);
    (void)SoftBusMutexUnlock(&g_sendFileInfoLock.lock);
    return SOFTBUS_OK;
}

static void DelSendListenerInfo(SendListenerInfo *info)
{
    (void)SoftBusMutexLock(&g_sendFileInfoLock.lock);
    ListDelete(&info->node);
    (void)SoftBusMutexUnlock(&g_sendFileInfoLock.lock);
}

static int32_t PackFileTransStartInfo(FileFrame *fileFrame, const char *destFile, uint64_t fileSize,
    const SendListenerInfo *info)
{
    int32_t len = strlen(destFile);
    if (info->crc == APP_INFO_SUPPORT) {
        uint64_t dataLen = len + FRAME_DATA_SEQ_OFFSET + sizeof(uint64_t);
        fileFrame->frameLength = FRAME_HEAD_LEN + dataLen + sizeof(uint64_t);
        if (fileFrame->frameLength > PROXY_MAX_PACKET_SIZE) {
            return SOFTBUS_ERR;
        }
        // magic(4 byte) + dataLen(8 byte) + oneFrameLen(4 byte) + fileSize + fileName
        (*(uint32_t *)(fileFrame->data)) = fileFrame->magic;
        (*(uint64_t *)(fileFrame->data + FRAME_MAGIC_OFFSET)) = dataLen;
        (*(uint32_t *)(fileFrame->fileData)) =
            PROXY_MAX_PACKET_SIZE - FRAME_HEAD_LEN - FRAME_DATA_SEQ_OFFSET - FRAME_CRC_LEN;
        (*(uint64_t *)(fileFrame->fileData + FRAME_DATA_SEQ_OFFSET)) = fileSize;
        if (memcpy_s(fileFrame->fileData + FRAME_DATA_SEQ_OFFSET + sizeof(uint64_t), len, destFile, len) != EOK) {
            return SOFTBUS_MEM_ERR;
        }
    } else {
        fileFrame->frameLength = FRAME_DATA_SEQ_OFFSET + len;
        if (fileFrame->frameLength > PROXY_MAX_PACKET_SIZE) {
            return SOFTBUS_ERR;
        }
        (*(int32_t *)(fileFrame->fileData)) = info->channelId;
        if (memcpy_s(fileFrame->fileData + FRAME_DATA_SEQ_OFFSET, len, destFile, len) != EOK) {
            return SOFTBUS_MEM_ERR;
        }
    }
    return SOFTBUS_OK;
}

static int32_t UnpackFileTransStartInfo(FileFrame *fileFrame, const FileRecipientInfo *info, SingleFileInfo *file)
{
    uint8_t *fileNameData = NULL;
    uint64_t fileNameLen = 0;
    if (info->crc == APP_INFO_SUPPORT) {
        if (fileFrame->frameLength < FRAME_HEAD_LEN + FRAME_DATA_SEQ_OFFSET) {
            return SOFTBUS_INVALID_PARAM;
        }
        // magic(4 byte) + dataLen(8 byte) + oneFrameLen(4 byte) + fileSize(8 byte) + fileName
        fileFrame->magic = (*(uint32_t *)(fileFrame->data));
        uint64_t dataLen = (*(uint64_t *)(fileFrame->data + FRAME_MAGIC_OFFSET));
        if (fileFrame->magic != FILE_MAGIC_NUMBER || dataLen < (FRAME_DATA_SEQ_OFFSET + sizeof(uint64_t))) {
            SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "start info fail magic 0X%X dataLen %" PRIu64,
                fileFrame->magic, dataLen);
            return SOFTBUS_ERR;
        }
        fileFrame->fileData = fileFrame->data + FRAME_HEAD_LEN;
        file->oneFrameLen = (*(uint32_t *)(fileFrame->fileData));
        file->fileSize = (*(uint64_t *)(fileFrame->fileData + FRAME_DATA_SEQ_OFFSET));
        fileNameLen = dataLen - FRAME_DATA_SEQ_OFFSET - sizeof(uint64_t);
        if (fileNameLen > 0) {
            fileNameData = fileFrame->fileData + FRAME_DATA_SEQ_OFFSET + sizeof(uint64_t);
        }
        file->startSeq = file->preStartSeq = 1;
        file->seqResult = file->preSeqResult = 0;
    } else {
        if (fileFrame->frameLength < FRAME_DATA_SEQ_OFFSET) {
            return SOFTBUS_ERR;
        }
        fileFrame->fileData = fileFrame->data;
        fileNameLen = fileFrame->frameLength - FRAME_DATA_SEQ_OFFSET;
        file->seq = (*(uint32_t *)(fileFrame->fileData));
        if (fileNameLen > 0) {
            fileNameData = fileFrame->fileData + FRAME_DATA_SEQ_OFFSET + sizeof(uint64_t);
        }
    }
    if (fileNameLen > MAX_FILE_PATH_NAME_LEN) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "start info fail file name len %" PRIu64, fileNameLen);
        return SOFTBUS_INVALID_PARAM;
    }
    if (fileNameData != NULL)  {
        if (memcpy_s(file->filePath, MAX_FILE_PATH_NAME_LEN, fileNameData, fileNameLen) != EOK) {
            return SOFTBUS_MEM_ERR;
        }
    }
    return SOFTBUS_OK;
}

static int32_t GetAndCheckFileSize(const char *sourceFile, uint64_t *fileSize, uint64_t *frameNum, int32_t crc)
{
    if ((sourceFile == NULL) || (fileSize == NULL) || (frameNum == NULL)) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "get file size num params invalid");
        return SOFTBUS_INVALID_PARAM;
    }

    if (SoftBusGetFileSize(sourceFile, fileSize) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "get file size fail");
        return SOFTBUS_FILE_ERR;
    }

    if (*fileSize > MAX_FILE_SIZE) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "file is too large, filesize : %" PRIu64, *fileSize);
        return SOFTBUS_FILE_ERR;
    }

    if (PROXY_MAX_PACKET_SIZE <= FRAME_DATA_SEQ_OFFSET) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "size error");
        return SOFTBUS_ERR;
    }
    uint64_t oneFrameSize = PROXY_MAX_PACKET_SIZE - FRAME_DATA_SEQ_OFFSET;
    if (crc == APP_INFO_SUPPORT) {
        oneFrameSize -= (FRAME_HEAD_LEN + FRAME_CRC_LEN);
    }
    uint64_t frameNumTemp = (*fileSize) / oneFrameSize;
    if (((*fileSize) % oneFrameSize) != 0) {
        frameNumTemp++;
    }

    /* add 1 means reserve frame to send destFile string */
    frameNumTemp++;
    *frameNum = frameNumTemp;

    return SOFTBUS_OK;
}

static int32_t SendOneFrameFront(SendListenerInfo *info, int32_t frameType)
{
    if (info->crc != APP_INFO_SUPPORT) {
        return SOFTBUS_OK;
    }
    if (frameType == TRANS_SESSION_FILE_FIRST_FRAME) {
        if (CreatePendingPacket(info->sessionId, 0) != SOFTBUS_OK) {
            return SOFTBUS_ERR;
        }
        info->waitSeq = 0;
        info->waitTimeoutCount = 0;
    }
    return SOFTBUS_OK;
}

static int32_t SendOneFrameMiddle(SendListenerInfo *info, int32_t frameType)
{
    if (info->crc != APP_INFO_SUPPORT) {
        return SOFTBUS_OK;
    }
    if (frameType == TRANS_SESSION_FILE_ONGOINE_FRAME) {
        if ((uint32_t)info->seq % FILE_SEND_ACK_INTERVAL != 0) {
            return SOFTBUS_OK;
        }
        if (CreatePendingPacket((uint32_t)info->sessionId, (uint64_t)info->seq) != SOFTBUS_OK) {
            return SOFTBUS_ERR;
        }
        info->waitSeq = info->seq;
        info->waitTimeoutCount = 0;
        if (SendFileAckReqAndResData(info->channelId, info->seq, info->seq,
            TRANS_SESSION_FILE_ACK_REQUEST_SENT) != SOFTBUS_OK) {
            DeletePendingPacket((uint32_t)info->sessionId, (uint64_t)info->seq);
            info->waitSeq = 0;
            return SOFTBUS_ERR;
        }
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "send ack request. id: %d, wait seq: %d",
            info->channelId, info->waitSeq);
    }
    return SOFTBUS_OK;
}

static int32_t SendOneFrameRear(SendListenerInfo *info, int32_t frameType)
{
    if (info->crc != APP_INFO_SUPPORT) {
        return SOFTBUS_OK;
    }
    if (frameType == TRANS_SESSION_FILE_ONLYONE_FRAME) {
        return SOFTBUS_OK;
    }
    int32_t ret;
    TransPendData pendData = {0};
    if (frameType == TRANS_SESSION_FILE_FIRST_FRAME) {
        ret = GetPendingPacketData(info->sessionId, 0, WAIT_START_ACK_TIME, true, &pendData);
        if (ret == SOFTBUS_ALREADY_TRIGGERED || ret == SOFTBUS_OK) {
            SoftBusFree(pendData.data);
            return SOFTBUS_OK;
        }
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "recv start frame respone timeout. id: %d, ret: %d",
            info->channelId, ret);
    } else {
        if ((uint32_t)info->waitSeq == 0) {
            return SOFTBUS_OK;
        }
        uint32_t time = (frameType == TRANS_SESSION_FILE_LAST_FRAME ? WAIT_ACK_LAST_TIME : WAIT_ACK_TIME);
        ret = GetPendingPacketData(info->sessionId, (uint64_t)info->waitSeq, time, false, &pendData);
        if (ret == SOFTBUS_ALREADY_TRIGGERED || ret == SOFTBUS_OK) {
            ret = AckResponseDataHandle(info, pendData.data, pendData.len);
            info->waitSeq = 0;
            info->waitTimeoutCount = 0;
            SoftBusFree(pendData.data);
            return ret;
        } else if (ret == SOFTBUS_TIMOUT) {
            info->waitTimeoutCount++;
            if (frameType != TRANS_SESSION_FILE_LAST_FRAME &&
                info->waitTimeoutCount <= WAIT_FRAME_ACK_TIMEOUT_COUNT) {
                return SOFTBUS_OK;
            }
            DeletePendingPacket(info->sessionId, (uint64_t)info->waitSeq);
        }
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "recv ack respone timeout. id: %d, wait seq: %d, ret: %d",
            info->channelId, info->waitSeq, ret);
        info->waitSeq = 0;
        info->waitTimeoutCount = 0;
    }
    return SOFTBUS_ERR;
}

static int32_t SendOneFrame(const SendListenerInfo *sendInfo, const FileFrame *fileFrame)
{
    if (fileFrame->data == NULL) {
        return SOFTBUS_ERR;
    }
    if (SendOneFrameFront((SendListenerInfo *)sendInfo, fileFrame->frameType) != SOFTBUS_OK) {
        return SOFTBUS_ERR;
    }
    int32_t ret = ProxyChannelSendFileStream(sendInfo->channelId, (char *)fileFrame->data,
        fileFrame->frameLength, fileFrame->frameType);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "conn send buf fail %d", ret);
        return ret;
    }
    if (SendOneFrameMiddle((SendListenerInfo *)sendInfo, fileFrame->frameType) != SOFTBUS_OK) {
        return SOFTBUS_ERR;
    }
    if (SendOneFrameRear((SendListenerInfo *)sendInfo, fileFrame->frameType) != SOFTBUS_OK) {
        return SOFTBUS_ERR;
    }
    if (sendInfo->result != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "peer receiving data error. channal id: %d, errcode: %d",
            sendInfo->channelId, sendInfo->result);
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t SendFileCrcCheckSum(const SendListenerInfo *info)
{
    if (info->crc != APP_INFO_SUPPORT) {
        return SOFTBUS_OK;
    }
    uint32_t len = FRAME_HEAD_LEN + FRAME_DATA_SEQ_OFFSET + sizeof(info->checkSumCRC);
    char *data = (char *)SoftBusCalloc(len);
    if (data == NULL) {
        return SOFTBUS_MALLOC_ERR;
    }
    uint32_t seq = info->seq + 1;
    (*(uint32_t *)data) = FILE_MAGIC_NUMBER;
    (*(uint64_t *)(data + FRAME_MAGIC_OFFSET)) = (FRAME_DATA_SEQ_OFFSET + sizeof(info->checkSumCRC));
    (*(uint32_t *)(data + FRAME_HEAD_LEN)) = seq;
    (*(uint64_t *)(data + FRAME_HEAD_LEN + FRAME_DATA_SEQ_OFFSET)) = info->checkSumCRC;
    if (CreatePendingPacket((uint32_t)info->sessionId, seq) != SOFTBUS_OK) {
        return SOFTBUS_ERR;
    }
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "send check sum. id: %d, seq: %d", info->channelId, seq);
    int32_t ret = ProxyChannelSendFileStream(info->channelId, data, len, TRANS_SESSION_FILE_CRC_CHECK_FRAME);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "conn send crc buf fail %d", ret);
        DeletePendingPacket((uint32_t)info->sessionId, seq);
        SoftBusFree(data);
        return ret;
    }
    SoftBusFree(data);
    TransPendData pendData = {0};
    ret = GetPendingPacketData(info->sessionId, seq, WAIT_START_ACK_TIME, true, &pendData);
    if (ret == SOFTBUS_ALREADY_TRIGGERED || ret == SOFTBUS_OK) {
        SoftBusFree(pendData.data);
        return SOFTBUS_OK;
    }
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "recv check sum result timeout. id: %d, seq: %d, ret: %d",
        info->channelId, seq, ret);
    return ret;
}

static int32_t UnpackFileCrcCheckSum(const FileRecipientInfo *info, FileFrame *fileFrame)
{
    if (info->crc == APP_INFO_SUPPORT) {
        SingleFileInfo *file = (SingleFileInfo *)(&(info->recvFileInfo[info->curRecvIndex]));
        if (fileFrame->frameLength != FRAME_HEAD_LEN + FRAME_DATA_SEQ_OFFSET + sizeof(file->checkSumCRC)) {
            return SOFTBUS_TRANS_INVALID_DATA_LENGTH;
        }
        fileFrame->magic = (*(uint32_t *)(fileFrame->data));
        uint64_t dataLen = (*(uint64_t *)(fileFrame->data + FRAME_MAGIC_OFFSET));
        if ((fileFrame->magic != FILE_MAGIC_NUMBER) ||
            (dataLen != FRAME_DATA_SEQ_OFFSET + sizeof(file->checkSumCRC))) {
            SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR,
                "unpack crc check frame failed. magic: %u, dataLen: %" PRIu64, fileFrame->magic, dataLen);
            return SOFTBUS_INVALID_DATA_HEAD;
        }
        fileFrame->fileData = fileFrame->data + FRAME_HEAD_LEN;
        fileFrame->seq = (*(uint32_t *)(fileFrame->fileData));
        uint64_t recvCheckSumCRC = (*(uint64_t *)(fileFrame->fileData + FRAME_DATA_SEQ_OFFSET));
        if (recvCheckSumCRC != file->checkSumCRC) {
            SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR,
                "crc check sum fail recv: %" PRIu64 ", cur: %" PRIu64, recvCheckSumCRC, file->checkSumCRC);
            return SOFTBUS_ERR;
        }
    }
    return SOFTBUS_OK;
}

static int32_t FileToFrame(SendListenerInfo *sendInfo, uint64_t frameNum,
    const char *destFile, uint64_t fileSize)
{
    FileFrame fileFrame = {0};
    fileFrame.data = (uint8_t *)SoftBusCalloc(PROXY_MAX_PACKET_SIZE);
    if (fileFrame.data == NULL) {
        return SOFTBUS_ERR;
    }
    fileFrame.magic = FILE_MAGIC_NUMBER;
    fileFrame.fileData = fileFrame.data;
    uint64_t fileOffset = 0;
    uint64_t remainedSendSize = fileSize;
    uint64_t frameDataSize = PROXY_MAX_PACKET_SIZE - FRAME_DATA_SEQ_OFFSET;
    if (sendInfo->crc == APP_INFO_SUPPORT) {
        // magic + dataLen + seq + data + crc
        fileFrame.fileData = fileFrame.data + FRAME_HEAD_LEN;
        frameDataSize -= (FRAME_HEAD_LEN + FRAME_CRC_LEN);
    }
    for (uint64_t index = 0; index < frameNum; index++) {
        fileFrame.frameType = FrameIndexToType(index, frameNum);
        if (index == 0) {
            if (PackFileTransStartInfo(&fileFrame, destFile, fileSize, sendInfo) != SOFTBUS_OK) {
                goto EXIT_ERR;
            }
        } else {
            uint64_t readLength = (remainedSendSize < frameDataSize) ? remainedSendSize : frameDataSize;
            int64_t len = PackReadFileData(&fileFrame, sendInfo->fd, readLength, fileOffset, sendInfo);
            if (len <= 0) {
                SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "read file src file failed");
                goto EXIT_ERR;
            }
            fileOffset += len;
            remainedSendSize -= len;
        }
        if (SendOneFrame(sendInfo, &fileFrame) != SOFTBUS_OK) {
            SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "send one frame failed");
            goto EXIT_ERR;
        }
        if (sendInfo->fileListener.sendListener.OnSendFileProcess != NULL) {
            sendInfo->fileListener.sendListener.OnSendFileProcess(sendInfo->channelId, fileOffset, fileSize);
        }
        (void)memset_s(fileFrame.data, PROXY_MAX_PACKET_SIZE, 0, PROXY_MAX_PACKET_SIZE);
    }
    if (SendFileCrcCheckSum(sendInfo) != SOFTBUS_OK) {
        goto EXIT_ERR;
    }
    SoftBusFree(fileFrame.data);
    return SOFTBUS_OK;
EXIT_ERR:
    SoftBusFree(fileFrame.data);
    return SOFTBUS_ERR;
}

static int32_t FileToFrameAndSendFile(SendListenerInfo *sendInfo, const char *sourceFile, const char *destFile)
{
#define RETRY_READ_LOCK_TIMES 2
    if (CheckDestFilePathValid(destFile) == false) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "chanId:%d, dest path is wrong", sendInfo->channelId);
        return SOFTBUS_ERR;
    }
    char *absSrcPath = (char *)SoftBusCalloc(PATH_MAX + 1);
    if (absSrcPath == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "calloc absFullDir fail");
        return SOFTBUS_ERR;
    }
    if (GetAndCheckRealPath(sourceFile, absSrcPath) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "chanId:%d, get src abs file fail", sendInfo->channelId);
        SoftBusFree(absSrcPath);
        return SOFTBUS_ERR;
    }
    uint64_t fileSize = 0;
    uint64_t frameNum = 0;
    if (GetAndCheckFileSize(absSrcPath, &fileSize, &frameNum, sendInfo->crc) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "chanId:%d, %s size err", sendInfo->channelId, absSrcPath);
        SoftBusFree(absSrcPath);
        return SOFTBUS_ERR;
    }
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO,
        "chanId:%d, srcPath:%s, srcAbsPath:%s, destPath:%s, fileSize:%" PRIu64 ", frameNum:%" PRIu64,
        sendInfo->channelId, sourceFile, absSrcPath, destFile, fileSize, frameNum);
    int32_t fd = SoftBusOpenFile(absSrcPath, SOFTBUS_O_RDONLY);
    if (fd < 0) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "chanId:%d, open file fail", sendInfo->channelId);
        SoftBusFree(absSrcPath);
        return SOFTBUS_ERR;
    }
    if (TryFileLock(fd, SOFTBUS_F_RDLCK, RETRY_READ_LOCK_TIMES) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "file is writing");
        SoftBusCloseFile(fd);
        SoftBusFree(absSrcPath);
        return SOFTBUS_FILE_ERR;
    }
    sendInfo->fd = fd;
    sendInfo->fileSize = fileSize;
    int32_t ret = FileToFrame(sendInfo, frameNum, destFile, fileSize);
    (void)FileUnLock(fd);
    SoftBusCloseFile(fd);
    sendInfo->fd = INVALID_FD;
    SoftBusFree(absSrcPath);
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "chanId: %d send file ret: %d", sendInfo->channelId, ret);
    return ret;
}

static int32_t SendSingleFile(const SendListenerInfo *sendInfo, const char *sourceFile, const char *destFile)
{
    if ((sourceFile == NULL) || (destFile == NULL)) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "sourfile or dstfile is null");
        return SOFTBUS_ERR;
    }
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "chanId:%d send file %s begin, dest is:%s",
        sendInfo->channelId, sourceFile, destFile);

    int32_t ret = FileToFrameAndSendFile((SendListenerInfo *)sendInfo, sourceFile, destFile);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "FileToFrameAndSendFile failed");
        return SOFTBUS_ERR;
    }

    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "chanId:%d send file %s success", sendInfo->channelId, sourceFile);
    return SOFTBUS_OK;
}

static int32_t SendFileList(int32_t channelId, const char **destFile, uint32_t fileCnt)
{
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "send file list begin");
    FileListBuffer bufferInfo = {0};
    int32_t ret = FileListToBuffer(destFile, fileCnt, &bufferInfo);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "file list to buffer fail");
        return SOFTBUS_ERR;
    }

    ret = ProxyChannelSendFileStream(channelId, (char *)bufferInfo.buffer, bufferInfo.bufferSize,
        TRANS_SESSION_FILE_ALLFILE_SENT);
    SoftBusFree(bufferInfo.buffer);
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "send file list ret: %d", ret);
    return ret;
}

static bool IsValidFileString(const char *str[], uint32_t fileNum, uint32_t maxLen)
{
    if (str == NULL || fileNum == 0) {
        return false;
    }
    for (uint32_t i = 0; i < fileNum; i++) {
        if (str[i] == NULL) {
            return false;
        }
        uint32_t len = strlen(str[i]);
        if (len == 0 || len >= maxLen) {
            return false;
        }
    }
    return true;
}

static int32_t ProxyStartSendFile(const SendListenerInfo *sendInfo, const char *sFileList[],
    const char *dFileList[], uint32_t fileCnt)
{
    if ((fileCnt == 0) || (fileCnt > MAX_SEND_FILE_NUM)) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "sendfile arg filecnt[%d] error", fileCnt);
        return SOFTBUS_ERR;
    }
    if (!IsValidFileString(sFileList, fileCnt, MAX_FILE_PATH_NAME_LEN) ||
        !IsValidFileString(dFileList, fileCnt, MAX_FILE_PATH_NAME_LEN)) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "sendfile invalid arg input");
        return SOFTBUS_ERR;
    }
    int32_t ret;
    for (uint32_t index = 0; index < fileCnt; index++) {
        ret = SendSingleFile(sendInfo, sFileList[index], dFileList[index]);
        if (ret != SOFTBUS_OK) {
            SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "send file %s, failed", sFileList[index]);
            return SOFTBUS_ERR;
        }
    }
    ret = SendFileList(sendInfo->channelId, dFileList, fileCnt);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "SendFileList failed");
        return SOFTBUS_ERR;
    }
    if (sendInfo->result != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "send file recv side fail channal: %d, errCode: %d",
            sendInfo->channelId, sendInfo->result);
        return SOFTBUS_ERR;
    }
    if (sendInfo->fileListener.sendListener.OnSendFileFinished != NULL) {
        sendInfo->fileListener.sendListener.OnSendFileFinished(sendInfo->sessionId, dFileList[0]);
    }
    return SOFTBUS_OK;
}

static int32_t GetSendListenerInfoByChannelId(int32_t channelId, SendListenerInfo *info)
{
    int32_t sessionId;
    int32_t ret = ClientGetSessionIdByChannelId(channelId, CHANNEL_TYPE_PROXY, &sessionId);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "get sessionId failed, channelId [%d]", channelId);
        return SOFTBUS_ERR;
    }
    char sessionName[SESSION_NAME_SIZE_MAX] = {0};
    if (ClientGetSessionDataById(sessionId, sessionName, SESSION_NAME_SIZE_MAX, KEY_SESSION_NAME) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "get sessionId name failed");
        return SOFTBUS_ERR;
    }
    if (ClientGetFileConfigInfoById(sessionId, &info->fileEncrypt, &info->algorithm, &info->crc) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "get file config failed");
        return SOFTBUS_ERR;
    }
    if (TransGetFileListener(sessionName, &(info->fileListener)) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "get file listener failed");
        return SOFTBUS_ERR;
    }
    info->channelId = channelId;
    info->sessionId = sessionId;
    ListInit(&info->node);
    return SOFTBUS_OK;
}

int32_t ProxyChannelSendFile(int32_t channelId, const char *sFileList[], const char *dFileList[], uint32_t fileCnt)
{
    int32_t ret = SOFTBUS_ERR;
    ProxyFileMutexLock *sessionLock = GetSessionFileLock(channelId);
    if (sessionLock == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "proxy send file get file lock failed");
        return SOFTBUS_LOCK_ERR;
    }
    if (SoftBusMutexLock(&sessionLock->sendLock) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "proxy send file lock file mutex failed");
        return SOFTBUS_LOCK_ERR;
    }
    SendListenerInfo *sendInfo = (SendListenerInfo *)SoftBusCalloc(sizeof(SendListenerInfo));
    if (sendInfo == NULL) {
        (void)SoftBusMutexUnlock(&sessionLock->sendLock);
        return SOFTBUS_MALLOC_ERR;
    }
    if (GetSendListenerInfoByChannelId(channelId, sendInfo) != SOFTBUS_OK) {
        (void)SoftBusMutexUnlock(&sessionLock->sendLock);
        SoftBusFree(sendInfo);
        return SOFTBUS_INVALID_PARAM;
    }
    ret = AddSendListenerInfo(sendInfo);
    if (ret != SOFTBUS_OK) {
        (void)SoftBusMutexUnlock(&sessionLock->sendLock);
        goto EXIT_ERR;
    }
    if (ProxyStartSendFile(sendInfo, sFileList, dFileList, fileCnt) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "proxy send file failed");
        DeletePendingPacket(sendInfo->sessionId, sendInfo->waitSeq);
        (void)SoftBusMutexUnlock(&sessionLock->sendLock);
        ret = SOFTBUS_TRANS_PROXY_SENDMSG_ERR;
        goto EXIT_ERR;
    }
    (void)SoftBusMutexUnlock(&sessionLock->sendLock);
    DelSessionFileLock(channelId);
    DelSendListenerInfo(sendInfo);
    SoftBusFree(sendInfo);
    return SOFTBUS_OK;
EXIT_ERR:
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "send file trans error failed");
    DelSessionFileLock(channelId);
    DelSendListenerInfo(sendInfo);
    if (sendInfo->fileListener.sendListener.OnFileTransError != NULL) {
        sendInfo->fileListener.sendListener.OnFileTransError(sendInfo->sessionId);
    }
    SoftBusFree(sendInfo);
    return ret;
}

static int32_t PutToRecvFileList(FileRecipientInfo *recipient, const SingleFileInfo *file)
{
#define RETRY_WRITE_LOCK_TIMES 2
    if (recipient == NULL || file == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "file is null");
        return SOFTBUS_ERR;
    }
    // get idle index
    int32_t index = INVALID_NODE_INDEX;
    for (int32_t i = 0; i < MAX_RECV_FILE_NUM; i++) {
        if (recipient->recvFileInfo[i].fileStatus == NODE_IDLE) {
            index = i;
            break;
        }
    }
    if (index == INVALID_NODE_INDEX) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "not find idle index");
        return SOFTBUS_ERR;
    }
    if (memcpy_s(recipient->recvFileInfo + index, sizeof(SingleFileInfo), file, sizeof(SingleFileInfo)) != EOK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "memcpy file info fail");
        return SOFTBUS_MEM_ERR;
    }

    // open
    int32_t fd = SoftBusOpenFileWithPerms(file->filePath,
        SOFTBUS_O_WRONLY | SOFTBUS_O_CREATE | SOFTBUS_O_TRUNC, SOFTBUS_S_IRUSR | SOFTBUS_S_IWUSR);
    if (fd < 0) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "open destFile fail");
        return SOFTBUS_FILE_ERR;
    }
    if (TryFileLock(fd, SOFTBUS_F_WRLCK, RETRY_WRITE_LOCK_TIMES) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "file busy");
        SoftBusCloseFile(fd);
        return SOFTBUS_FILE_ERR;
    }
    recipient->recvFileInfo[index].index = index;
    recipient->recvFileInfo[index].fileStatus = NODE_BUSY;
    recipient->recvFileInfo[index].fileOffset = 0;
    recipient->recvFileInfo[index].timeOut = 0;
    recipient->recvFileInfo[index].fileFd = fd;
    recipient->curRecvIndex = index;
    return SOFTBUS_OK;
}

static bool CheckRecvFileExist(const char *absFullPath)
{
    if (absFullPath == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "absFullPath is null");
        return false;
    }

    FileRecipientInfo *info = NULL;
    LIST_FOR_EACH_ENTRY(info, &g_recvRecipientInfoList, FileRecipientInfo, node) {
        for (int32_t i = 0; i < MAX_RECV_FILE_NUM; i++) {
            if (info->recvFileInfo[i].fileStatus == NODE_IDLE) {
                continue;
            }
            if (strcmp(info->recvFileInfo[i].filePath, absFullPath) == 0) {
                return true;
            }
        }
    }
    return false;
}

static FileRecipientInfo *GetRecipientNoLock(int32_t sessionId)
{
    FileRecipientInfo *info = NULL;
    LIST_FOR_EACH_ENTRY(info, &g_recvRecipientInfoList, FileRecipientInfo, node) {
        if (info->sessionId == sessionId) {
            return info;
        }
    }
    return NULL;
}

static FileRecipientInfo *CreateNewRecipient(int32_t sessionId, int32_t channelId)
{
    FileRecipientInfo *info = NULL;
    LIST_FOR_EACH_ENTRY(info, &g_recvRecipientInfoList, FileRecipientInfo, node) {
        if (info->sessionId == sessionId) {
            SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "session id exists");
            return NULL;
        }
    }
    info = (FileRecipientInfo *)SoftBusCalloc(sizeof(FileRecipientInfo));
    if (info == NULL) {
        return NULL;
    }
    char sessionName[SESSION_NAME_SIZE_MAX] = {0};
    if (ClientGetSessionDataById(sessionId, sessionName, SESSION_NAME_SIZE_MAX, KEY_SESSION_NAME) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "get sessionId name failed");
        SoftBusFree(info);
        return NULL;
    }
    if (ClientGetFileConfigInfoById(sessionId, &info->fileEncrypt, &info->algorithm, &info->crc) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "get file config failed");
        SoftBusFree(info);
        return NULL;
    }
    info->channelId = channelId;
    info->sessionId = sessionId;
    if (TransGetFileListener(sessionName, &(info->fileListener)) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "get file listener failed");
        SoftBusFree(info);
        return NULL;
    }
    ListInit(&info->node);
    // add list
    ListTailInsert(&g_recvRecipientInfoList, &info->node);
    return info;
}

static int32_t GetFileInfoByStartFrame(const FileFrame *fileFrame, const FileRecipientInfo *info, SingleFileInfo *file)
{
    if (file == NULL || info == NULL || fileFrame == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    const char *rootDir = info->fileListener.rootDir;
    if (strstr(rootDir, "..") != NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "rootDir[%s] is not cannoical form", rootDir);
        return SOFTBUS_ERR;
    }
    if (UnpackFileTransStartInfo((FileFrame *)fileFrame, info, file) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "session[%s] unpack start info fail", info->sessionId);
        return SOFTBUS_ERR;
    }
    char *filePath = file->filePath;
    if (!CheckDestFilePathValid(filePath)) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "recv file path[%s] form is wrong", filePath);
        return SOFTBUS_ERR;
    }
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "destFilePath[%s], rootDir[%s]", filePath, rootDir);
    char *fullRecvPath = GetFullRecvPath(filePath, rootDir);
    if (!IsPathValid(fullRecvPath)) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "destFilePath is invalid");
        SoftBusFree(fullRecvPath);
        return SOFTBUS_ERR;
    }
    (void)memset_s(filePath, MAX_FILE_PATH_NAME_LEN, 0, MAX_FILE_PATH_NAME_LEN);
    if (CreateDirAndGetAbsPath(fullRecvPath, filePath, MAX_FILE_PATH_NAME_LEN) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "create dest dir failed");
        SoftBusFree(fullRecvPath);
        return SOFTBUS_ERR;
    }
    SoftBusFree(fullRecvPath);
    return SOFTBUS_OK;
}

static int32_t CreateFileFromFrame(int32_t sessionId, int32_t channelId, const FileFrame *fileFrame)
{
    if (SoftBusMutexLock(&g_recvFileInfoLock.lock) != SOFTBUS_OK) {
        return SOFTBUS_LOCK_ERR;
    }
    FileRecipientInfo *recipient = GetRecipientNoLock(sessionId);
    if (recipient == NULL) {
        recipient = CreateNewRecipient(sessionId, channelId);
        if (recipient == NULL) {
            SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "sessionId: %d create file recipient failed", sessionId);
            (void)SendFileTransResult(channelId, 0, SOFTBUS_ERR, IS_RECV_RESULT);
            (void)SoftBusMutexUnlock(&g_recvFileInfoLock.lock);
            return SOFTBUS_ERR;
        }
    }
    int32_t result = SOFTBUS_ERR;
    SingleFileInfo *file = (SingleFileInfo *)SoftBusCalloc(sizeof(SingleFileInfo));
    if (file == NULL) {
        goto EXIT_ERR;
    }
    if (GetFileInfoByStartFrame(fileFrame, recipient, file) != SOFTBUS_OK) {
        goto EXIT_ERR;
    }
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "fullRecvPath %s, seq:%u", file->filePath, file->seq);
    if (CheckRecvFileExist(file->filePath)) {
        goto EXIT_ERR;
    }
    if (PutToRecvFileList(recipient, file) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "put sessionId[%u] failed", recipient->sessionId);
        goto EXIT_ERR;
    }
    if (recipient->fileListener.recvListener.OnReceiveFileStarted != NULL) {
        recipient->fileListener.recvListener.OnReceiveFileStarted(sessionId, file->filePath, 1);
    }
    SoftBusFree(file);
    (void)SendFileTransResult(channelId, 0, SOFTBUS_OK, IS_RECV_RESULT);
    (void)SoftBusMutexUnlock(&g_recvFileInfoLock.lock);
    return SOFTBUS_OK;
EXIT_ERR:
    SoftBusFree(file);
    (void)SendFileTransResult(channelId, 0, result, IS_RECV_RESULT);
    if (recipient->fileListener.recvListener.OnFileTransError != NULL) {
        recipient->fileListener.recvListener.OnFileTransError(sessionId);
    }
    ListDelete(&recipient->node);
    SoftBusFree(recipient);
    (void)SoftBusMutexUnlock(&g_recvFileInfoLock.lock);
    return SOFTBUS_ERR;
}

static int32_t WriteEmptyFrame(SingleFileInfo *fileInfo, int32_t count)
{
    // 写空帧：文件留空白
    if (count > 0) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "write %d empty frame", count);
        char *emptyBuff = (char *)SoftBusCalloc(fileInfo->oneFrameLen);
        if (emptyBuff == NULL) {
            return SOFTBUS_MALLOC_ERR;
        }
        for (int32_t i = 0; i < count; ++i) {
            int64_t emptyLen = SoftBusPwriteFile(fileInfo->fileFd, emptyBuff,
                fileInfo->oneFrameLen, fileInfo->fileOffset);
            if (emptyLen < 0 || (uint64_t)emptyLen != fileInfo->oneFrameLen) {
                SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "pwrite empty frame fail");
                SoftBusFree(emptyBuff);
                return SOFTBUS_ERR;
            }
            fileInfo->fileOffset += (uint64_t)emptyLen;
        }
        SoftBusFree(emptyBuff);
    }
    return SOFTBUS_OK;
}

static int32_t ProcessOneFrameCRC(const FileFrame *frame, uint32_t dataLen, SingleFileInfo *fileInfo)
{
    uint32_t seq = frame->seq;
    // 到下一个32帧，startSeq还未更新，说明没有接收到ack请求，直接返回失败
    if (seq >= fileInfo->startSeq + FILE_SEND_ACK_INTERVAL) {
        return SOFTBUS_ERR;
    }
    uint64_t fileOffset = 0;
    uint32_t bit = seq % FILE_SEND_ACK_INTERVAL;
    bit = ((bit == 0) ? (FILE_SEND_ACK_INTERVAL - 1) : (bit - 1));
    if (seq >= fileInfo->startSeq) {
        // 写空帧：文件留空白
        int32_t seqDiff = seq - fileInfo->seq - 1;
        if (WriteEmptyFrame(fileInfo, seqDiff) != SOFTBUS_OK) {
            return SOFTBUS_ERR;
        }
        // 当前帧为最后一帧或者大于上一次32帧+timeout count, 去校验上一次32帧的接收结果，如果有不成功，代表丢帧
        if ((seq >= fileInfo->preStartSeq + FILE_SEND_ACK_INTERVAL + WAIT_FRAME_ACK_TIMEOUT_COUNT - 1) ||
            (frame->frameType == TRANS_SESSION_FILE_LAST_FRAME && seq > FILE_SEND_ACK_INTERVAL)) {
            if ((fileInfo->preSeqResult & FILE_SEND_ACK_RESULT_SUCCESS) != FILE_SEND_ACK_RESULT_SUCCESS) {
                SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "recv file fail. frame loss");
                return SOFTBUS_ERR;
            }
        }
        fileInfo->seq = seq;
        fileOffset = fileInfo->fileOffset;
        // 设置当前帧的接收成功
        fileInfo->seqResult |= 0x01 << bit;
    } else {
        // 计算当前重发送的帧，前面写了多少数据，计算偏移
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "recv retrans file frame");
        fileOffset = (seq - 1) * fileInfo->oneFrameLen;
        fileInfo->preSeqResult |= 0x01 << bit;
    }
    int64_t writeLength = SoftBusPwriteFile(fileInfo->fileFd, frame->fileData + FRAME_DATA_SEQ_OFFSET,
        dataLen - FRAME_DATA_SEQ_OFFSET, fileOffset);
    if (writeLength < 0 || (uint64_t)writeLength != dataLen - FRAME_DATA_SEQ_OFFSET) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "pwrite file failed");
        return SOFTBUS_ERR;
    }
    if (seq >= fileInfo->startSeq) {
        fileInfo->fileOffset += (uint64_t)writeLength;
        if (fileInfo->fileOffset > MAX_FILE_SIZE) {
            SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "file is too large, offset: %" PRIu64,
                fileInfo->fileOffset);
            return SOFTBUS_ERR;
        }
    }
    return SOFTBUS_OK;
}

static int32_t ProcessOneFrame(const FileFrame *fileFrame, uint32_t dataLen, int32_t crc, SingleFileInfo *fileInfo)
{
    if (fileInfo->fileStatus == NODE_ERR) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "fileStatus is error");
        return SOFTBUS_ERR;
    }
    if (crc == APP_INFO_SUPPORT) {
        return ProcessOneFrameCRC(fileFrame, dataLen, fileInfo);
    } else {
        uint32_t frameDataLength = dataLen - FRAME_DATA_SEQ_OFFSET;
        fileInfo->seq = fileFrame->seq;
        int64_t writeLength = SoftBusPwriteFile(fileInfo->fileFd, fileFrame->fileData + FRAME_DATA_SEQ_OFFSET,
            frameDataLength, fileInfo->fileOffset);
        if (writeLength != frameDataLength) {
            SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "pwrite file failed");
            return SOFTBUS_ERR;
        }
        fileInfo->fileOffset += (uint64_t)writeLength;
        if (fileInfo->fileOffset > MAX_FILE_SIZE) {
            SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "file is too large, offset:%" PRIu64, fileInfo->fileOffset);
            return SOFTBUS_ERR;
        }
    }
    return SOFTBUS_OK;
}

static int32_t WriteFrameToFile(int32_t sessionId, const FileFrame *fileFrame)
{
    if (SoftBusMutexLock(&g_recvFileInfoLock.lock) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "lock write frame fail");
        return SOFTBUS_LOCK_ERR;
    }
    FileRecipientInfo *recipient = GetRecipientNoLock(sessionId);
    if (recipient == NULL) {
        SoftBusMutexUnlock(&g_recvFileInfoLock.lock);
        return SOFTBUS_NOT_FIND;
    }
    int32_t result = SOFTBUS_ERR;
    uint32_t dataLen;
    if (UnpackFileDataFrame(recipient, (FileFrame *)fileFrame, &dataLen) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "unpack file data frame fail");
        SoftBusMutexUnlock(&g_recvFileInfoLock.lock);
        return SOFTBUS_ERR;
    }
    SingleFileInfo *fileInfo = (SingleFileInfo *)(&(recipient->recvFileInfo[recipient->curRecvIndex]));
    if (ProcessOneFrame(fileFrame, dataLen, recipient->crc, fileInfo) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "write one frame error");
        goto EXIT_ERR;
    }
    fileInfo->timeOut = 0;
    if (recipient->fileListener.recvListener.OnReceiveFileProcess != NULL) {
        recipient->fileListener.recvListener.OnReceiveFileProcess(sessionId, fileInfo->filePath,
            fileInfo->fileOffset, fileInfo->fileSize);
    }
    if ((fileFrame->frameType == TRANS_SESSION_FILE_LAST_FRAME) ||
        (fileFrame->frameType == TRANS_SESSION_FILE_ONLYONE_FRAME)) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "process last frame, seq: %u", fileFrame->seq);
        (void)FileUnLock(fileInfo->fileFd);
        SoftBusCloseFile(fileInfo->fileFd);
        fileInfo->fileFd = INVALID_FD;
    }
    (void)SoftBusMutexUnlock(&g_recvFileInfoLock.lock);
    return SOFTBUS_OK;
EXIT_ERR:
    (void)SendFileTransResult(recipient->channelId, 0, result, IS_RECV_RESULT);
    (void)FileUnLock(fileInfo->fileFd);
    SoftBusCloseFile(fileInfo->fileFd);
    SoftBusRemoveFile(fileInfo->filePath);
    ListDelete(&recipient->node);
    SoftBusFree(recipient);
    if (recipient->fileListener.recvListener.OnFileTransError != NULL) {
        recipient->fileListener.recvListener.OnFileTransError(sessionId);
    }
    (void)SoftBusMutexUnlock(&g_recvFileInfoLock.lock);
    return SOFTBUS_ERR;
}

static int32_t ProcessFileListData(int32_t sessionId, const FileFrame *frame)
{
    if (SoftBusMutexLock(&g_recvFileInfoLock.lock) != SOFTBUS_OK) {
        return SOFTBUS_LOCK_ERR;
    }
    FileRecipientInfo *recipient = GetRecipientNoLock(sessionId);
    if (recipient == NULL) {
        SoftBusMutexUnlock(&g_recvFileInfoLock.lock);
        return SOFTBUS_NOT_FIND;
    }
    int32_t ret = SOFTBUS_ERR;
    int32_t fileCount;
    char *firstFilePath = BufferToFileList(frame->data, frame->frameLength, &fileCount);
    if (firstFilePath == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "buffer to file list fail");
        goto EXIT_ERR;
    }
    char *fullRecvPath = GetFullRecvPath(firstFilePath, recipient->fileListener.rootDir);
    SoftBusFree(firstFilePath);
    if (IsPathValid(fullRecvPath) == false) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "file list path is invalid");
        SoftBusFree(fullRecvPath);
        goto EXIT_ERR;
    }
    char *absRecvPath = (char *)SoftBusCalloc(PATH_MAX + 1);
    if (absRecvPath == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "calloc absFullDir fail");
        SoftBusFree(fullRecvPath);
        goto EXIT_ERR;
    }
    if (GetAndCheckRealPath(fullRecvPath, absRecvPath) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "get recv abs file path fail");
        SoftBusFree(fullRecvPath);
        SoftBusFree(absRecvPath);
        goto EXIT_ERR;
    }
    if (recipient->fileListener.recvListener.OnReceiveFileFinished != NULL) {
        recipient->fileListener.recvListener.OnReceiveFileFinished(sessionId, absRecvPath, fileCount);
    }
    SoftBusFree(fullRecvPath);
    SoftBusFree(absRecvPath);
    ret = SOFTBUS_OK;
EXIT_ERR:
    if (ret != SOFTBUS_OK && recipient->fileListener.recvListener.OnFileTransError != NULL) {
        recipient->fileListener.recvListener.OnFileTransError(sessionId);
    }
    ListDelete(&recipient->node);
    SoftBusFree(recipient);
    (void)SoftBusMutexUnlock(&g_recvFileInfoLock.lock);
    return ret;
}

static int32_t ProcessFileRecvResult(int32_t sessionId, uint32_t seq, int32_t result)
{
    if (SoftBusMutexLock(&g_sendFileInfoLock.lock) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "process recv result lock fail");
        return SOFTBUS_LOCK_ERR;
    }
    SendListenerInfo *item = NULL;
    SendListenerInfo *info = NULL;
    LIST_FOR_EACH_ENTRY(item, &g_sendListenerInfoList, SendListenerInfo, node) {
        if (item->sessionId == sessionId) {
            info = item;
            info->result = result;
            break;
        }
    }
    (void)SoftBusMutexUnlock(&g_sendFileInfoLock.lock);
    if (info != NULL) {
        (void)SetPendingPacketData(sessionId, seq, NULL);
        return SOFTBUS_OK;
    }
    return SOFTBUS_NOT_FIND;
}

static int32_t ProcessFileSendResult(int32_t sessionId, uint32_t seq, int32_t result)
{
    if (SoftBusMutexLock(&g_recvFileInfoLock.lock) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "process send result lock fail");
        return SOFTBUS_LOCK_ERR;
    }
    FileRecipientInfo *item = NULL;
    FileRecipientInfo *info = NULL;
    LIST_FOR_EACH_ENTRY(item, &g_recvRecipientInfoList, FileRecipientInfo, node) {
        if (item->sessionId == sessionId) {
            info = item;
            info->result = result;
            break;
        }
    }
    (void)SoftBusMutexUnlock(&g_recvFileInfoLock.lock);
    if (info != NULL) {
        (void)SetPendingPacketData(sessionId, seq, NULL);
        return SOFTBUS_OK;
    }
    return SOFTBUS_NOT_FIND;
}

static int32_t ProcessFileTransResult(int32_t sessionId, const FileFrame *frame)
{
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "proxy channel send file result. session id: %d", sessionId);
    uint32_t seq;
    int32_t result;
    uint32_t side;
    if (UnpackFileTransResultFrame(frame->data, frame->frameLength, &seq, &result, &side) != SOFTBUS_OK) {
        return SOFTBUS_ERR;
    }
    if (side == IS_RECV_RESULT) {
        return ProcessFileRecvResult(sessionId, seq, result);
    } else if (side == IS_SEND_RESULT) {
        return ProcessFileSendResult(sessionId, seq, result);
    }
    return SOFTBUS_OK;
}

static int32_t ProcessCrcCheckSumData(int32_t sessionId, const FileFrame *frame)
{
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "proxy channel recv file crc data. session id: %d, len: %d",
        sessionId, frame->frameLength);

    if (SoftBusMutexLock(&g_recvFileInfoLock.lock) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "lock write frame fail");
        return SOFTBUS_LOCK_ERR;
    }
    FileRecipientInfo *recipient = GetRecipientNoLock(sessionId);
    if (recipient == NULL) {
        (void)SoftBusMutexUnlock(&g_recvFileInfoLock.lock);
        return SOFTBUS_NOT_FIND;
    }
    int32_t result = UnpackFileCrcCheckSum(recipient, (FileFrame *)frame);
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "verification crc check sum, ret: %d", result);
    int32_t ret = SendFileTransResult(recipient->channelId, frame->seq, result, IS_RECV_RESULT);
    (void)SoftBusMutexUnlock(&g_recvFileInfoLock.lock);
    return (ret == SOFTBUS_OK) ? result : ret;
}

static int32_t ProcessFileAckRequest(int32_t sessionId, const FileFrame *frame)
{
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "proxy channel recv file ack request. session id: %d, len: %u",
        sessionId, frame->frameLength);
    if (SoftBusMutexLock(&g_recvFileInfoLock.lock) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "lock write frame fail");
        return SOFTBUS_LOCK_ERR;
    }
    FileRecipientInfo *recipient = GetRecipientNoLock(sessionId);
    if (recipient == NULL) {
        (void)SoftBusMutexUnlock(&g_recvFileInfoLock.lock);
        return SOFTBUS_NOT_FIND;
    }
    uint32_t startSeq;
    uint32_t value;
    if (UnpackAckReqAndResData((FileFrame *)frame, &startSeq, &value) != SOFTBUS_ERR) {
        return SOFTBUS_ERR;
    }
    SingleFileInfo *file = (SingleFileInfo *)(&(recipient->recvFileInfo[recipient->curRecvIndex]));
    if (startSeq != file->startSeq) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "start seq not equal. recv: %u, cur: %u",
            startSeq, file->startSeq);
        return SOFTBUS_ERR;
    }
    file->timeOut = 0;
    file->preStartSeq = startSeq;
    file->startSeq = startSeq + FILE_SEND_ACK_INTERVAL;
    value = (uint32_t)(file->seqResult & FILE_SEND_ACK_RESULT_SUCCESS);
    file->preSeqResult = value;
    file->seqResult = (file->seqResult >> FILE_SEND_ACK_INTERVAL);
    int32_t ret = SendFileAckReqAndResData(recipient->channelId, startSeq, value,
        TRANS_SESSION_FILE_ACK_RESPONSE_SENT);
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "send file ack response, ret: %d", ret);
    (void)SoftBusMutexUnlock(&g_recvFileInfoLock.lock);
    return ret;
}

static int32_t ProcessFileAckResponse(int32_t sessionId, const FileFrame *frame)
{
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "proxy channel recv file ack response. session id: %d len: %u",
        sessionId, frame->frameLength);
    if (frame->data == NULL || frame->frameLength == 0) {
        return SOFTBUS_INVALID_PARAM;
    }
    if (SoftBusMutexLock(&g_sendFileInfoLock.lock) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "proxy recv ack response SoftBusMutexLock failed");
        return SOFTBUS_LOCK_ERR;
    }
    SendListenerInfo *item = NULL;
    LIST_FOR_EACH_ENTRY(item, &g_sendListenerInfoList, SendListenerInfo, node) {
        if (item->sessionId == sessionId) {
            TransPendData pendData;
            pendData.data = (char *)SoftBusCalloc(frame->frameLength);
            if (pendData.data == NULL) {
                (void)SoftBusMutexUnlock(&g_sendFileInfoLock.lock);
                return SOFTBUS_MALLOC_ERR;
            }
            (void)memcpy_s(pendData.data, frame->frameLength, frame->data, frame->frameLength);
            pendData.len = frame->frameLength;
            if (SetPendingPacketData((uint32_t)sessionId, (uint64_t)(item->waitSeq), &pendData) != SOFTBUS_OK) {
                SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "proxy recv ack response SetPendingPacketData fail");
                (void)SoftBusMutexUnlock(&g_sendFileInfoLock.lock);
                return SOFTBUS_ERR;
            }
            (void)SoftBusMutexUnlock(&g_sendFileInfoLock.lock);
            return SOFTBUS_OK;
        }
    }
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "proxy recv ack response not find. session id: %d", sessionId);
    (void)SoftBusMutexUnlock(&g_sendFileInfoLock.lock);
    return SOFTBUS_NOT_FIND;
}

int32_t ProcessRecvFileFrameData(int32_t sessionId, int32_t channelId, const FileFrame *oneFrame)
{
    if (oneFrame->frameLength > PROXY_MAX_PACKET_SIZE) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "len > PROXY_MAX_PACKET_SIZE");
        return SOFTBUS_ERR;
    }
    int32_t ret;
    switch (oneFrame->frameType) {
        case TRANS_SESSION_FILE_FIRST_FRAME:
            SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "create file from frame start sessionId: %d", sessionId);
            ret = CreateFileFromFrame(sessionId, channelId, oneFrame);
            SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "create file from frame ret: %d", ret);
            break;
        case TRANS_SESSION_FILE_ONGOINE_FRAME:
        case TRANS_SESSION_FILE_ONLYONE_FRAME:
        case TRANS_SESSION_FILE_LAST_FRAME:
            ret = WriteFrameToFile(sessionId, oneFrame);
            if (ret != SOFTBUS_OK) {
                SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "write frame fail ret: %d", ret);
            }
            break;
        case TRANS_SESSION_FILE_ACK_REQUEST_SENT:
            ret = ProcessFileAckRequest(sessionId, oneFrame);
            break;
        case TRANS_SESSION_FILE_ACK_RESPONSE_SENT:
            ret = ProcessFileAckResponse(sessionId, oneFrame);
            break;
        case TRANS_SESSION_FILE_CRC_CHECK_FRAME:
            ret = ProcessCrcCheckSumData(sessionId, oneFrame);
            SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "process crc check sun. sessionId: %d, ret: %d",
                sessionId, ret);
            break;
        case TRANS_SESSION_FILE_RESULT_FRAME:
            ret = ProcessFileTransResult(sessionId, oneFrame);
            break;
        case TRANS_SESSION_FILE_ALLFILE_SENT:
            ret = ProcessFileListData(sessionId, oneFrame);
            SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "process file list data. sessionId: %d, ret: %d",
                sessionId, ret);
            break;
        default:
            SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "frame type is invalid sessionId: %d", sessionId);
            return SOFTBUS_ERR;
    }
    return ret;
}
