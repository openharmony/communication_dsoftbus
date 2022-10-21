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

#include <inttypes.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

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
} SendListenerInfo;

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
    return ServerIpcSendMessage(channelId, CHANNEL_TYPE_PROXY, data, len, type);
}

static int32_t SendFileTransResult(int32_t channelId, uint32_t seq, int32_t result, uint32_t side)
{
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "send file result seq %u side %u result %d", seq, side, result);
    uint32_t len = FRAME_HEAD_LEN + FRAME_DATA_SEQ_OFFSET + sizeof(uint32_t) + sizeof(int32_t);
    char *data = (char *)SoftBusCalloc(len);
    if (data == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "SendFileTransResult malloc failed.len=%d.", len);
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
    }
    SoftBusFree(data);
    return ret;
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

static void ClearRecipientResources(FileRecipientInfo *info)
{
    if (info->recvFileInfo.fileFd != INVALID_FD) {
        (void)FileUnLock(info->recvFileInfo.fileFd);
        SoftBusCloseFile(info->recvFileInfo.fileFd);
        info->recvFileInfo.fileFd = INVALID_FD;
    }
    if (info->recvState == TRANS_FILE_RECV_ERR_STATE) {
        SoftBusRemoveFile(info->recvFileInfo.filePath);
        if (info->crc == APP_INFO_FILE_FEATURES_SUPPORT) {
            (void)SendFileTransResult(info->channelId, info->recvFileInfo.seq, SOFTBUS_ERR, IS_RECV_RESULT);
        }
        if (info->fileListener.recvListener.OnFileTransError != NULL) {
            info->fileListener.recvListener.OnFileTransError(info->sessionId);
        }
    }
}
static void SetRecipientRecvState(FileRecipientInfo *recipient, int32_t state)
{
    if (SoftBusMutexLock(&g_recvFileInfoLock.lock) != SOFTBUS_OK) {
        return;
    }
    if (recipient->recvState != TRANS_FILE_RECV_ERR_STATE) {
        recipient->recvState = state;
        if (state == TRANS_FILE_RECV_IDLE_STATE) {
            recipient->recvFileInfo.fileStatus = NODE_IDLE;
        }
    }
    (void)SoftBusMutexUnlock(&g_recvFileInfoLock.lock);
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
        if (info->recvState == TRANS_FILE_RECV_IDLE_STATE) {
            continue;
        }
        if (info->recvFileInfo.timeOut >= FILE_TRANS_TIMEOUT) {
            SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "file %s recv timeout, recv state %d",
                info->recvFileInfo.filePath, info->recvState);
            info->recvFileInfo.fileStatus = NODE_ERR;
            info->recvState = TRANS_FILE_RECV_ERR_STATE;
            info->recvFileInfo.timeOut = 0;
            info->objRefCount--;
            ListDelete(&info->node);
            if (info->objRefCount == 0) {
                ClearRecipientResources(info);
                SoftBusFree(info);
            }
        } else {
            info->recvFileInfo.timeOut++;
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
            SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "recvfile mutex init fail!");
            return SOFTBUS_ERR;
        }
        g_recvFileInfoLock.lockInitFlag = true;
    }
    if (InitPendingPacket() != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "InitPendingPacket fail!");
        return SOFTBUS_ERR;
    }
    if (RegisterTimeoutCallback(SOFTBUS_PROXY_SENDFILE_TIMER_FUN, ProxyFileTransTimerProc) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "register sendfile timer fail");
    }
    return SOFTBUS_OK;
}
void ClinetTransProxyFileManagerDeinit(void)
{
    (void)RegisterTimeoutCallback(SOFTBUS_PROXY_SENDFILE_TIMER_FUN, NULL);
    if (SoftBusMutexDestroy(&g_sendFileInfoLock.lock) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "destroy send file lock fail");
    }
    g_sendFileInfoLock.lockInitFlag = false;
    if (SoftBusMutexDestroy(&g_recvFileInfoLock.lock) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "destroy recv file lock fail");
    }
    g_recvFileInfoLock.lockInitFlag = false;
}

static int32_t SendFileAckReqAndResData(int32_t channelId, uint32_t startSeq, uint32_t value, int32_t type)
{
    uint32_t len = FRAME_HEAD_LEN + FRAME_DATA_SEQ_OFFSET + FRAME_DATA_SEQ_OFFSET;
    char *data = (char *)SoftBusCalloc(len);
    if (data == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "SendFileAckReqAndResData calloc fail! len=%d.", len);
        return SOFTBUS_MALLOC_ERR;
    }
    *(uint32_t *)data = FILE_MAGIC_NUMBER;
    *(int64_t *)(data + FRAME_MAGIC_OFFSET) = (FRAME_DATA_SEQ_OFFSET + FRAME_DATA_SEQ_OFFSET);
    *(uint32_t *)(data + FRAME_HEAD_LEN) = startSeq;
    *(uint32_t *)(data + FRAME_HEAD_LEN + FRAME_DATA_SEQ_OFFSET) = value;
    int32_t ret = ProxyChannelSendFileStream(channelId, data, len, type);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "conn send ack buf fail %d.", ret);
    }
    SoftBusFree(data);
    return ret;
}
static int32_t UnpackAckReqAndResData(FileFrame *frame, uint32_t *startSeq, uint32_t *value)
{
    if (frame == NULL || startSeq == NULL || value == NULL || frame->data == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    if (frame->frameLength < FRAME_HEAD_LEN + FRAME_DATA_SEQ_OFFSET + FRAME_DATA_SEQ_OFFSET) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "unpack ack data len %d fail.", frame->frameLength);
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
    (*startSeq) = (*(uint32_t *)(frame->fileData));
    (*value) = (*(uint32_t *)(frame->fileData + FRAME_DATA_SEQ_OFFSET));
    return SOFTBUS_OK;
}

static int64_t PackReadFileData(FileFrame *fileFrame, uint64_t readLength, uint64_t fileOffset,
    SendListenerInfo *info)
{
    int64_t len = SoftBusPreadFile(info->fd, fileFrame->fileData + FRAME_DATA_SEQ_OFFSET, readLength, fileOffset);
    if (len <= 0) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "pread src file failed. ret: %d.", len);
        return len;
    }
    if (info->crc == APP_INFO_FILE_FEATURES_SUPPORT) {
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
static int64_t PackReadFileRetransData(FileFrame *fileFrame, uint32_t seq, uint64_t readLength, uint64_t fileOffset,
    const SendListenerInfo *info)
{
    int64_t len = SoftBusPreadFile(info->fd, fileFrame->fileData + FRAME_DATA_SEQ_OFFSET, readLength, fileOffset);
    if (len <= 0) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "pread src file failed. ret: %d", len);
        return len;
    }
    uint64_t dataLen = len + FRAME_DATA_SEQ_OFFSET;
    fileFrame->frameLength = FRAME_HEAD_LEN + dataLen + FRAME_CRC_LEN;
    if (fileFrame->frameLength > PROXY_MAX_PACKET_SIZE) {
        return SOFTBUS_ERR;
    }
    uint16_t crc = RTU_CRC(fileFrame->fileData + FRAME_DATA_SEQ_OFFSET, len);
    (*(uint32_t *)(fileFrame->data)) = fileFrame->magic;
    (*(uint64_t *)(fileFrame->data + FRAME_MAGIC_OFFSET)) = dataLen;
    (*(uint32_t *)(fileFrame->fileData)) = seq;
    (*(uint16_t *)(fileFrame->fileData + dataLen)) = crc;

    int32_t ret = ProxyChannelSendFileStream(info->channelId, (char *)fileFrame->data,
        fileFrame->frameLength, FrameIndexToType((uint64_t)seq, info->frameNum));
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "conn send buf fail %d", ret);
        return ret;
    }
    return len;
}
static int32_t UnpackFileDataFrame(FileRecipientInfo *info, FileFrame *fileFrame, uint32_t *fileDataLen)
{
    if (info->crc == APP_INFO_FILE_FEATURES_SUPPORT) {
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
        *fileDataLen = dataLen;
        fileFrame->crc = crc;
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
    if ((info != NULL) && (info->crc != APP_INFO_FILE_FEATURES_SUPPORT)) {
        return SOFTBUS_OK;
    }
    if ((info == NULL) || (seq <= 0)) {
        return SOFTBUS_INVALID_PARAM;
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
    int64_t len = PackReadFileRetransData(&fileFrame, seq, readLength, fileOffset, info);
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
    if (data == NULL || len != sizeof(AckResponseData)) {
        return SOFTBUS_OK;
    }
    AckResponseData *resData = (AckResponseData *)data;
    uint32_t startSeq = resData->startSeq;
    uint32_t seqResult = resData->seqResult;
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
        return SOFTBUS_INVALID_PARAM;
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
        return SOFTBUS_INVALID_PARAM;
    }
    if (strncpy_s(dirPath, dirPathLen, fullPath, dirLen) != EOK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "strcpy_s dir path error, dirLen[%d]", dirLen);
        return SOFTBUS_MEM_ERR;
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
        return SOFTBUS_INVALID_PARAM;
    }
    char *absFullDir = (char *)SoftBusCalloc(PATH_MAX + 1);
    if (absFullDir == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "calloc absFullDir failed");
        SoftBusFree(dirPath);
        return SOFTBUS_MALLOC_ERR;
    }
    int32_t fileNameLength = -1;
    int32_t dirPathLength = -1;
    const char *fileName = TransGetFileName(fullPath);
    if (fileName == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "get file name failed");
        goto EXIT_ERR;
    }
    if (GetAndCheckRealPath(dirPath, absFullDir) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "get full abs file failed");
        goto EXIT_ERR;
    }
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "dirPath[%s], realFullDir[%s]", dirPath, absFullDir);
    fileNameLength = strlen(fileName);
    dirPathLength = strlen(absFullDir);
    if (pathSize < (fileNameLength + dirPathLength + 1)) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "copy name is too large, dirLen:%d, fileNameLen:%d",
            dirPathLength, fileNameLength);
        goto EXIT_ERR;
    }
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "fileName[%s][%d]", fileName, fileNameLength);
    if (sprintf_s(recvAbsPath, pathSize, "%s/%s", absFullDir, fileName) < 0) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "sprintf_s filename error");
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
        return SOFTBUS_INVALID_PARAM;
    }
    uint32_t len = (uint32_t)strlen(filePath);
    int32_t ret;
    char *tempPath = (char *)SoftBusCalloc(len + 1);
    if (tempPath == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "calloc tempPath failed");
        return SOFTBUS_MALLOC_ERR;
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
    ret = GetAbsFullPath(filePath, recvAbsPath, pathSize);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "dest dir is invalid");
        return ret;
    }
    return SOFTBUS_OK;
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

static void DelSessionFileLock(ProxyFileMutexLock *sessionLock)
{
    if (sessionLock == NULL) {
        return;
    }

    if (SoftBusMutexLock(&g_sendFileInfoLock.lock) != 0) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "%s:lock mutex failed", __func__);
        return;
    }
    sessionLock->count--;
    if (sessionLock->count == 0) {
        ListDelete(&sessionLock->node);
        (void)SoftBusMutexDestroy(&sessionLock->sendLock);
        SoftBusFree(sessionLock);
    }
    (void)SoftBusMutexUnlock(&g_sendFileInfoLock.lock);
}

static int32_t AddSendListenerInfo(SendListenerInfo *info)
{
    if (info == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "add send listener info invalid param.");
        return SOFTBUS_INVALID_PARAM;
    }
    if (SoftBusMutexLock(&g_sendFileInfoLock.lock) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "proxy add send info lock fail");
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
    if (info == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "DelSendListenerInfo invalid param.");
        return;
    }
    (void)SoftBusMutexLock(&g_sendFileInfoLock.lock);
    ListDelete(&info->node);
    (void)SoftBusMutexUnlock(&g_sendFileInfoLock.lock);
}

static int32_t PackFileTransStartInfo(FileFrame *fileFrame, const char *destFile, uint64_t fileSize,
    const SendListenerInfo *info)
{
    if ((info == NULL) || (fileFrame == NULL) || (destFile == NULL)) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "PackFileTransStartInfo invalid param.");
        return SOFTBUS_INVALID_PARAM;
    }
    int32_t len = strlen(destFile);
    if (info->crc == APP_INFO_FILE_FEATURES_SUPPORT) {
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
    if ((info == NULL) || (fileFrame == NULL) || (file == NULL)) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "PackFileTransStartInfo invalid param.");
        return SOFTBUS_INVALID_PARAM;
    }
    uint8_t *fileNameData = NULL;
    uint64_t fileNameLen = 0;
    if (info->crc == APP_INFO_FILE_FEATURES_SUPPORT) {
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
    if (crc == APP_INFO_FILE_FEATURES_SUPPORT) {
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
    if (info == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "SendOneFrameFront invalid param.");
        return SOFTBUS_INVALID_PARAM;
    }
    if (info->crc != APP_INFO_FILE_FEATURES_SUPPORT) {
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
    if (info == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "SendOneFrameMiddle invalid param.");
        return SOFTBUS_INVALID_PARAM;
    }
    if (info->crc != APP_INFO_FILE_FEATURES_SUPPORT) {
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
        if (SendFileAckReqAndResData(info->channelId, info->seq - FILE_SEND_ACK_INTERVAL + 1, info->seq,
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
    if (info == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    if (info->crc != APP_INFO_FILE_FEATURES_SUPPORT) {
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
        uint32_t time = WAIT_ACK_TIME;
        if (frameType == TRANS_SESSION_FILE_LAST_FRAME || info->waitTimeoutCount >= WAIT_FRAME_ACK_TIMEOUT_COUNT) {
            time = WAIT_ACK_LAST_TIME;
        }
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
    if ((sendInfo == NULL) || (fileFrame == NULL)) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "SendOneFrameMiddle invalid param.");
        return SOFTBUS_INVALID_PARAM;
    }
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
    if (info == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "SendFileCrcCheckSum invalid param.");
        return SOFTBUS_INVALID_PARAM;
    }
    if (info->crc != APP_INFO_FILE_FEATURES_SUPPORT) {
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
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "Create Pend fail. id: %d, seq: %d", info->channelId, seq);
        SoftBusFree(data);
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
    if ((info == NULL) || (fileFrame == NULL)) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "UnpackFileCrcCheckSum invalid param.");
        return SOFTBUS_INVALID_PARAM;
    }
    if (info->crc == APP_INFO_FILE_FEATURES_SUPPORT) {
        SingleFileInfo *file = (SingleFileInfo *)(&info->recvFileInfo);
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
    if (sendInfo->crc == APP_INFO_FILE_FEATURES_SUPPORT) {
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
            int64_t len = PackReadFileData(&fileFrame, readLength, fileOffset, sendInfo);
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
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "send crc check sum");
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
    if (sendInfo == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "FileToFrameAndSendFile invalid param.");
        return SOFTBUS_INVALID_PARAM;
    }
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
    sendInfo->frameNum = frameNum;
    int32_t ret = FileToFrame(sendInfo, frameNum, destFile, fileSize);
    SoftBusFree(absSrcPath);
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "chanId: %d send file ret: %d", sendInfo->channelId, ret);
    return ret;
}

static void ClearSendInfo(SendListenerInfo *info)
{
    if (info->fd != INVALID_FD) {
        (void)FileUnLock(info->fd);
        SoftBusCloseFile(info->fd);
        info->fd = INVALID_FD;
    }
    info->fileSize = 0;
    info->frameNum = 0;
    info->seq = 0;
    info->waitSeq = 0;
    info->waitTimeoutCount = 0;
    info->result = SOFTBUS_OK;
    info->checkSumCRC = 0;
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
    ClearSendInfo((SendListenerInfo *)sendInfo);
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "chanId:%d send file %s ret:%d",
        sendInfo->channelId, sourceFile, ret);
    return ret;
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
    int32_t ret;
    for (uint32_t index = 0; index < fileCnt; index++) {
        ret = SendSingleFile(sendInfo, sFileList[index], dFileList[index]);
        if (ret != SOFTBUS_OK) {
            SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "send file %s failed.ret=%" PRId32, sFileList[index], ret);
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
    if (info == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "GetSendListenerInfoByChannelId invalid param.");
        return SOFTBUS_INVALID_PARAM;
    }
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

static int32_t CreateSendListenerInfo(SendListenerInfo **sendListenerInfo, int32_t channelId)
{
    SendListenerInfo *sendInfo = (SendListenerInfo *)SoftBusCalloc(sizeof(SendListenerInfo));
    if (sendInfo == NULL) {
        return SOFTBUS_MALLOC_ERR;
    }
    int32_t ret = SOFTBUS_ERR;
    do {
        ret = GetSendListenerInfoByChannelId(channelId, sendInfo);
        if (ret != SOFTBUS_OK) {
            break;
        }

        ret = AddSendListenerInfo(sendInfo);
        if (ret != SOFTBUS_OK) {
            break;
        }
    } while (false);

    if (ret != SOFTBUS_OK) {
        SoftBusFree(sendInfo);
        sendInfo = NULL;
    }

    *sendListenerInfo = sendInfo;
    return ret;
}

static void ReleaseSendListenerInfo(SendListenerInfo *sendInfo)
{
    if (sendInfo == NULL) {
        return;
    }
    DelSendListenerInfo(sendInfo);
    SoftBusFree(sendInfo);
}

int32_t ProxyChannelSendFile(int32_t channelId, const char *sFileList[], const char *dFileList[], uint32_t fileCnt)
{
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "proxy send file trans start");
    if ((fileCnt == 0) || (fileCnt > MAX_SEND_FILE_NUM)) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "sendfile arg filecnt[%d] error", fileCnt);
        return SOFTBUS_ERR;
    }
    if (sFileList == NULL || !IsValidFileString(sFileList, fileCnt, MAX_FILE_PATH_NAME_LEN)) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "sendfile invalid arg sFileList");
        return SOFTBUS_ERR;
    }
    if (dFileList == NULL || !IsValidFileString(dFileList, fileCnt, MAX_FILE_PATH_NAME_LEN)) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "sendfile invalid arg dFileList");
        return SOFTBUS_ERR;
    }

    ProxyFileMutexLock *sessionLock = GetSessionFileLock(channelId);
    if (sessionLock == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "proxy send file get file lock failed");
        return SOFTBUS_LOCK_ERR;
    }
    if (SoftBusMutexLock(&sessionLock->sendLock) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "proxy send file lock file mutex failed");
        DelSessionFileLock(sessionLock);
        return SOFTBUS_LOCK_ERR;
    }

    SendListenerInfo *sendInfo = NULL;
    int32_t ret = SOFTBUS_ERR;
    do {
        ret = CreateSendListenerInfo(&sendInfo, channelId);
        if (ret != SOFTBUS_OK || sendInfo == NULL) {
            SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "create send listener info failed! ret=%" PRId32, ret);
            break;
        }
        ret = ProxyStartSendFile(sendInfo, sFileList, dFileList, fileCnt);
        if (ret != SOFTBUS_OK) {
            SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "proxy send file failed!ret=%" PRId32, ret);
            DeletePendingPacket(sendInfo->sessionId, sendInfo->waitSeq);
            ret = SOFTBUS_TRANS_PROXY_SENDMSG_ERR;
            break;
        }
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "proxy send file trans ok");
    } while (false);

    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "proxy send file trans error");
        if (sendInfo != NULL && sendInfo->fileListener.sendListener.OnFileTransError != NULL) {
            sendInfo->fileListener.sendListener.OnFileTransError(sendInfo->sessionId);
        }
    }

    if (sendInfo != NULL) {
        ReleaseSendListenerInfo(sendInfo);
        sendInfo = NULL;
    }

    (void)SoftBusMutexUnlock(&sessionLock->sendLock);
    DelSessionFileLock(sessionLock);
    return ret;
}

static bool CheckRecvFileExist(const char *absFullPath)
{
    if (absFullPath == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "absFullPath is null");
        return false;
    }
    if (SoftBusMutexLock(&g_recvFileInfoLock.lock) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "lock file timer failed");
        return false;
    }
    FileRecipientInfo *info = NULL;
    LIST_FOR_EACH_ENTRY(info, &g_recvRecipientInfoList, FileRecipientInfo, node) {
        if (info->recvState == TRANS_FILE_RECV_IDLE_STATE || info->recvFileInfo.fileStatus != NODE_BUSY) {
            continue;
        }
        if (strcmp(info->recvFileInfo.filePath, absFullPath) == 0) {
            (void)SoftBusMutexUnlock(&g_recvFileInfoLock.lock);
            return true;
        }
    }
    (void)SoftBusMutexUnlock(&g_recvFileInfoLock.lock);
    return false;
}
static int32_t PutToRecvFileList(FileRecipientInfo *recipient, const SingleFileInfo *file)
{
#define RETRY_WRITE_LOCK_TIMES 2
    if (recipient == NULL || file == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "file is null");
        return SOFTBUS_ERR;
    }
    if (recipient->recvFileInfo.fileStatus != NODE_IDLE) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "session receiving file");
        return SOFTBUS_ERR;
    }
    if (CheckRecvFileExist(file->filePath)) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "file is already exist and busy");
        return SOFTBUS_FILE_ERR;
    }
    if (memcpy_s(&recipient->recvFileInfo, sizeof(SingleFileInfo), file, sizeof(SingleFileInfo)) != EOK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "memcpy file info fail");
        return SOFTBUS_MEM_ERR;
    }
    int32_t fd = SoftBusOpenFileWithPerms(file->filePath,
        SOFTBUS_O_WRONLY | SOFTBUS_O_CREATE, SOFTBUS_S_IRUSR | SOFTBUS_S_IWUSR);
    if (fd < 0) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "open destFile fail");
        return SOFTBUS_FILE_ERR;
    }
    if (TryFileLock(fd, SOFTBUS_F_WRLCK, RETRY_WRITE_LOCK_TIMES) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "file busy");
        SoftBusCloseFile(fd);
        return SOFTBUS_FILE_ERR;
    }
    (void)ftruncate(fd, 0);
    recipient->recvFileInfo.fileStatus = NODE_BUSY;
    recipient->recvFileInfo.fileOffset = 0;
    recipient->recvFileInfo.timeOut = 0;
    recipient->recvFileInfo.fileFd = fd;
    return SOFTBUS_OK;
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

static void ReleaseRecipientRef(FileRecipientInfo *info)
{
    if (info == NULL || SoftBusMutexLock(&g_recvFileInfoLock.lock) != SOFTBUS_OK) {
        return;
    }
    info->objRefCount--;
    if (info->objRefCount == 0) {
        ListDelete(&info->node);
        ClearRecipientResources(info);
        SoftBusFree(info);
    }
    (void)SoftBusMutexUnlock(&g_recvFileInfoLock.lock);
}

static void DelRecipient(int32_t sessionId)
{
    if (SoftBusMutexLock(&g_recvFileInfoLock.lock) != SOFTBUS_OK) {
        return;
    }
    FileRecipientInfo *info = NULL;
    LIST_FOR_EACH_ENTRY(info, &g_recvRecipientInfoList, FileRecipientInfo, node) {
        if (info->sessionId == sessionId) {
            info->objRefCount--;
            if (info->objRefCount == 0) {
                ListDelete(&info->node);
                ClearRecipientResources(info);
                SoftBusFree(info);
            }
            break;
        }
    }
    (void)SoftBusMutexUnlock(&g_recvFileInfoLock.lock);
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
    info->objRefCount = 1;
    info->recvFileInfo.fileFd = INVALID_FD;
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
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "session[%d] unpack start info fail", info->sessionId);
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

static FileRecipientInfo *GetRecipientInCreateFileRef(int32_t sessionId, int32_t channelId)
{
    if (SoftBusMutexLock(&g_recvFileInfoLock.lock) != SOFTBUS_OK) {
        return NULL;
    }
    FileRecipientInfo *recipient = GetRecipientNoLock(sessionId);
    if (recipient == NULL) {
        recipient = CreateNewRecipient(sessionId, channelId);
        if (recipient == NULL) {
            SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "sessionId: %d create file recipient fail", sessionId);
            (void)SoftBusMutexUnlock(&g_recvFileInfoLock.lock);
            return NULL;
        }
    }
    if (recipient->recvState != TRANS_FILE_RECV_IDLE_STATE) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "sessionId: %d create file recvState(%d) fail",
            sessionId, recipient->recvState);
        (void)SoftBusMutexUnlock(&g_recvFileInfoLock.lock);
        return NULL;
    }
    recipient->recvState = TRANS_FILE_RECV_START_STATE;
    recipient->objRefCount++;
    (void)SoftBusMutexUnlock(&g_recvFileInfoLock.lock);
    return recipient;
}

static FileRecipientInfo *GetRecipientInProcessRef(int32_t sessionId)
{
    if (SoftBusMutexLock(&g_recvFileInfoLock.lock) != SOFTBUS_OK) {
        return NULL;
    }
    FileRecipientInfo *recipient = GetRecipientNoLock(sessionId);
    if (recipient == NULL || recipient->recvState == TRANS_FILE_RECV_IDLE_STATE) {
        SoftBusMutexUnlock(&g_recvFileInfoLock.lock);
        return NULL;
    }
    if (recipient->recvState == TRANS_FILE_RECV_START_STATE) {
        recipient->recvState = TRANS_FILE_RECV_PROCESS_STATE;
    }
    recipient->objRefCount++;
    (void)SoftBusMutexUnlock(&g_recvFileInfoLock.lock);
    return recipient;
}

static int32_t CreateFileFromFrame(int32_t sessionId, int32_t channelId, const FileFrame *fileFrame)
{
    FileRecipientInfo *recipient = GetRecipientInCreateFileRef(sessionId, channelId);
    if (recipient == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "GetRecipientInCreateFileRef(%d) fail", sessionId);
        return SOFTBUS_ERR;
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
    if (PutToRecvFileList(recipient, file) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "put sessionId[%u] failed", recipient->sessionId);
        goto EXIT_ERR;
    }
    if (recipient->fileListener.recvListener.OnReceiveFileStarted != NULL) {
        recipient->fileListener.recvListener.OnReceiveFileStarted(sessionId, file->filePath, 1);
    }
    ReleaseRecipientRef(recipient);
    SoftBusFree(file);
    if (recipient->crc == APP_INFO_FILE_FEATURES_SUPPORT) {
        (void)SendFileTransResult(channelId, 0, SOFTBUS_OK, IS_RECV_RESULT);
    }
    return SOFTBUS_OK;
EXIT_ERR:
    SoftBusFree(file);
    if (recipient->crc == APP_INFO_FILE_FEATURES_SUPPORT) {
        (void)SendFileTransResult(channelId, 0, result, IS_RECV_RESULT);
    }
    if (recipient->fileListener.recvListener.OnFileTransError != NULL) {
        recipient->fileListener.recvListener.OnFileTransError(sessionId);
    }
    ReleaseRecipientRef(recipient);
    DelRecipient(sessionId);
    return SOFTBUS_ERR;
}

static int32_t WriteEmptyFrame(SingleFileInfo *fileInfo, int32_t count)
{
    if (fileInfo == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "WriteEmptyFrame invalid param.");
        return SOFTBUS_INVALID_PARAM;
    }
    
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
    if ((frame == NULL) || (fileInfo == NULL)) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "ProcessOneFrameCRC invalid param.");
        return SOFTBUS_INVALID_PARAM;
    }
    uint32_t seq = frame->seq;
    if (seq >= fileInfo->startSeq + FILE_SEND_ACK_INTERVAL) {
        return SOFTBUS_ERR;
    }
    uint64_t fileOffset = 0;
    uint32_t bit = seq % FILE_SEND_ACK_INTERVAL;
    bit = ((bit == 0) ? (FILE_SEND_ACK_INTERVAL - 1) : (bit - 1));
    if (seq >= fileInfo->startSeq) {
        int32_t seqDiff = seq - fileInfo->seq - 1;
        if (WriteEmptyFrame(fileInfo, seqDiff) != SOFTBUS_OK) {
            return SOFTBUS_ERR;
        }
        if ((seq >= fileInfo->preStartSeq + FILE_SEND_ACK_INTERVAL + WAIT_FRAME_ACK_TIMEOUT_COUNT - 1) ||
            (frame->frameType == TRANS_SESSION_FILE_LAST_FRAME && seq > FILE_SEND_ACK_INTERVAL)) {
            if ((fileInfo->preSeqResult & FILE_SEND_ACK_RESULT_SUCCESS) != FILE_SEND_ACK_RESULT_SUCCESS) {
                SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "recv file fail. frame loss");
                return SOFTBUS_ERR;
            }
        }
        fileInfo->seq = seq;
        fileOffset = fileInfo->fileOffset;
        fileInfo->seqResult |= 0x01 << bit;
    } else {
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
        fileInfo->checkSumCRC += frame->crc;
    }
    return SOFTBUS_OK;
}

static int32_t ProcessOneFrame(const FileFrame *fileFrame, uint32_t dataLen, int32_t crc, SingleFileInfo *fileInfo)
{
    if (fileInfo->fileStatus == NODE_ERR) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "fileStatus is error");
        return SOFTBUS_ERR;
    }
    if (crc == APP_INFO_FILE_FEATURES_SUPPORT) {
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
    FileRecipientInfo *recipient = GetRecipientInProcessRef(sessionId);
    if (recipient == NULL) {
        return SOFTBUS_NOT_FIND;
    }
    int32_t result = SOFTBUS_ERR;
    SingleFileInfo *fileInfo = &recipient->recvFileInfo;
    uint32_t dataLen;
    if (UnpackFileDataFrame(recipient, (FileFrame *)fileFrame, &dataLen) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "unpack file data frame fail");
        goto EXIT_ERR;
    }
    if (ProcessOneFrame(fileFrame, dataLen, recipient->crc, fileInfo) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "write one frame error");
        goto EXIT_ERR;
    }
    fileInfo->timeOut = 0;
    if (recipient->fileListener.recvListener.OnReceiveFileProcess != NULL) {
        recipient->fileListener.recvListener.OnReceiveFileProcess(sessionId, fileInfo->filePath,
            fileInfo->fileOffset, fileInfo->fileSize);
    }
    if (recipient->crc != APP_INFO_FILE_FEATURES_SUPPORT) {
        if ((fileFrame->frameType == TRANS_SESSION_FILE_LAST_FRAME) ||
            (fileFrame->frameType == TRANS_SESSION_FILE_ONLYONE_FRAME)) {
            SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "process last frame, seq: %u", fileFrame->seq);
            SetRecipientRecvState(recipient, TRANS_FILE_RECV_IDLE_STATE);
            (void)SoftBusMutexLock(&g_recvFileInfoLock.lock);
            (void)FileUnLock(fileInfo->fileFd);
            SoftBusCloseFile(fileInfo->fileFd);
            fileInfo->fileFd = INVALID_FD;
            (void)SoftBusMutexUnlock(&g_recvFileInfoLock.lock);
        }
    }
    ReleaseRecipientRef(recipient);
    return SOFTBUS_OK;
EXIT_ERR:
    if (recipient->crc == APP_INFO_FILE_FEATURES_SUPPORT) {
        (void)SendFileTransResult(recipient->channelId, 0, result, IS_RECV_RESULT);
    }
    SetRecipientRecvState(recipient, TRANS_FILE_RECV_ERR_STATE);
    if (recipient->fileListener.recvListener.OnFileTransError != NULL) {
        recipient->fileListener.recvListener.OnFileTransError(sessionId);
    }
    ReleaseRecipientRef(recipient);
    DelRecipient(sessionId);
    return SOFTBUS_ERR;
}

static int32_t ProcessFileListData(int32_t sessionId, const FileFrame *frame)
{
    FileRecipientInfo *recipient = GetRecipientInProcessRef(sessionId);
    if (recipient == NULL) {
        return SOFTBUS_NOT_FIND;
    }
    int32_t ret = SOFTBUS_ERR;
    int32_t fileCount;
    char *fullRecvPath = NULL;
    char *absRecvPath = NULL;
    char *firstFilePath = BufferToFileList(frame->data, frame->frameLength, &fileCount);
    if (firstFilePath == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "buffer to file list fail");
        goto EXIT_ERR;
    }
    fullRecvPath = GetFullRecvPath(firstFilePath, recipient->fileListener.rootDir);
    SoftBusFree(firstFilePath);
    if (IsPathValid(fullRecvPath) == false) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "file list path is invalid");
        SoftBusFree(fullRecvPath);
        goto EXIT_ERR;
    }
    absRecvPath = (char *)SoftBusCalloc(PATH_MAX + 1);
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
    SetRecipientRecvState(recipient, TRANS_FILE_RECV_IDLE_STATE);
    if (recipient->fileListener.recvListener.OnReceiveFileFinished != NULL) {
        recipient->fileListener.recvListener.OnReceiveFileFinished(sessionId, absRecvPath, fileCount);
    }
    SoftBusFree(fullRecvPath);
    SoftBusFree(absRecvPath);
    ret = SOFTBUS_OK;
EXIT_ERR:
    if (ret != SOFTBUS_OK) {
        if (recipient->fileListener.recvListener.OnFileTransError != NULL) {
            recipient->fileListener.recvListener.OnFileTransError(sessionId);
        }
        SetRecipientRecvState(recipient, TRANS_FILE_RECV_ERR_STATE);
    }
    ReleaseRecipientRef(recipient);
    DelRecipient(sessionId);
    return ret;
}

static int32_t ProcessFileRecvResult(int32_t sessionId, uint32_t seq, int32_t result)
{
    if (SoftBusMutexLock(&g_sendFileInfoLock.lock) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "process recv result lock fail");
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
    (void)seq;
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
        return SOFTBUS_OK;
    }
    return SOFTBUS_NOT_FIND;
}

static int32_t ProcessFileTransResult(int32_t sessionId, const FileFrame *frame)
{
    if (frame == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "ProcessFileTransResult invalid param.");
        return SOFTBUS_INVALID_PARAM;
    }
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
    if (frame == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "ProcessCrcCheckSumData invalid param.");
        return SOFTBUS_INVALID_PARAM;
    }
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "proxy channel recv file crc data. session id: %d, len: %d",
        sessionId, frame->frameLength);
    FileRecipientInfo *recipient = GetRecipientInProcessRef(sessionId);
    if (recipient == NULL) {
        return SOFTBUS_NOT_FIND;
    }
    int32_t result = UnpackFileCrcCheckSum(recipient, (FileFrame *)frame);
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "verification crc check sum, ret: %d", result);
    int32_t ret = SendFileTransResult(recipient->channelId, frame->seq, result, IS_RECV_RESULT);
    ReleaseRecipientRef(recipient);
    if (result != SOFTBUS_OK || ret != SOFTBUS_OK) {
        SetRecipientRecvState(recipient, TRANS_FILE_RECV_ERR_STATE);
        DelRecipient(sessionId);
        return SOFTBUS_ERR;
    }
    SetRecipientRecvState(recipient, TRANS_FILE_RECV_IDLE_STATE);
    return SOFTBUS_OK;
}

static int32_t ProcessFileAckRequest(int32_t sessionId, const FileFrame *frame)
{
    if (frame == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "ProcessFileAckRequest invalid param.");
        return SOFTBUS_INVALID_PARAM;
    }
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "proxy channel recv file ack request. session id: %d, len: %u",
        sessionId, frame->frameLength);
    FileRecipientInfo *recipient = GetRecipientInProcessRef(sessionId);
    if (recipient == NULL) {
        return SOFTBUS_NOT_FIND;
    }
    uint32_t startSeq;
    uint32_t value;
    if (UnpackAckReqAndResData((FileFrame *)frame, &startSeq, &value) != SOFTBUS_OK) {
        ReleaseRecipientRef(recipient);
        return SOFTBUS_ERR;
    }
    SingleFileInfo *file = &recipient->recvFileInfo;
    if (startSeq != file->startSeq) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "start seq not equal. recv: %u, cur: %u",
            startSeq, file->startSeq);
        ReleaseRecipientRef(recipient);
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
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "send file ack response, ret: %d", ret);
    ReleaseRecipientRef(recipient);
    return ret;
}

static int32_t ProcessFileAckResponse(int32_t sessionId, const FileFrame *frame)
{
    if ((frame == NULL) || (frame->data == NULL) || (frame->frameLength == 0)) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "ProcessFileAckResponse invalid param.");
        return SOFTBUS_INVALID_PARAM;
    }
    AckResponseData *data = (AckResponseData *)SoftBusCalloc(sizeof(AckResponseData));
    if (data == NULL) {
        return SOFTBUS_MALLOC_ERR;
    }
    TransPendData pendData = {
        .data = (char *)data,
        .len = sizeof(AckResponseData),
    };
    if (UnpackAckReqAndResData((FileFrame *)frame, &data->startSeq, &data->seqResult) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "proxy recv unpack ack response fail");
        SoftBusFree(data);
        return SOFTBUS_ERR;
    }
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "recv file ack response. session id: %d start seq: %u, value: %u",
        sessionId, data->startSeq, data->seqResult);
    if (SoftBusMutexLock(&g_sendFileInfoLock.lock) != SOFTBUS_OK) {
        SoftBusFree(data);
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "proxy recv ack response lock fail");
        return SOFTBUS_LOCK_ERR;
    }
    SendListenerInfo *item = NULL;
    LIST_FOR_EACH_ENTRY(item, &g_sendListenerInfoList, SendListenerInfo, node) {
        if (item->sessionId == sessionId) {
            if (SetPendingPacketData((uint32_t)sessionId, (uint64_t)(item->waitSeq), &pendData) != SOFTBUS_OK) {
                SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "proxy recv ack response set pend packet fail");
                (void)SoftBusMutexUnlock(&g_sendFileInfoLock.lock);
                SoftBusFree(data);
                return SOFTBUS_ERR;
            }
            (void)SoftBusMutexUnlock(&g_sendFileInfoLock.lock);
            return SOFTBUS_OK;
        }
    }
    (void)SoftBusMutexUnlock(&g_sendFileInfoLock.lock);
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "recv ack response not find. session id %d start seq %u",
        sessionId, data->startSeq);
    SoftBusFree(data);
    return SOFTBUS_NOT_FIND;
}

int32_t ProcessRecvFileFrameData(int32_t sessionId, int32_t channelId, const FileFrame *oneFrame)
{
    if (oneFrame == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "ProcessRecvFileFrameData invalid param.");
        return SOFTBUS_INVALID_PARAM;
    }
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
            SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "process crc check sum. sessionId: %d, ret: %d",
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