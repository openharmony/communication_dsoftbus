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

#include "client_trans_proxy_file_helper.h"

#include <limits.h>
#include <securec.h>
#include <stdbool.h>

#include "client_trans_proxy_file_manager.h"
#include "client_trans_proxy_manager.h"
#include "client_trans_session_manager.h"
#include "client_trans_socket_manager.h"
#include "softbus_adapter_errcode.h"
#include "softbus_adapter_file.h"
#include "softbus_adapter_mem.h"
#include "softbus_adapter_socket.h"
#include "softbus_app_info.h"
#include "softbus_def.h"
#include "softbus_error_code.h"
#include "softbus_utils.h"
#include "trans_log.h"

int32_t ProxyChannelSendFileStream(int32_t channelId, const char *data, uint32_t len, int32_t type)
{
    if (data == NULL) {
        TRANS_LOGI(TRANS_FILE, "data is null");
        return SOFTBUS_INVALID_PARAM;
    }
    ProxyChannelInfoDetail info;
    (void)memset_s(&info, sizeof(ProxyChannelInfoDetail), 0, sizeof(ProxyChannelInfoDetail));
    int32_t ret = ClientTransProxyGetInfoByChannelId(channelId, &info);
    TRANS_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret,
        TRANS_FILE, "client trans proxy get info by ChannelId fail");
    return TransProxyPackAndSendData(channelId, data, len, &info, (SessionPktType)type);
}

int32_t SendFileTransResult(int32_t channelId, uint32_t seq, int32_t result, uint32_t side)
{
    TRANS_LOGI(TRANS_FILE, "send file result seq=%{public}u, side=%{public}u, result=%{public}d", seq, side, result);
    uint32_t len = FRAME_HEAD_LEN + FRAME_DATA_SEQ_OFFSET + sizeof(uint32_t) + sizeof(int32_t);
    char *data = (char *)SoftBusCalloc(len);
    if (data == NULL) {
        TRANS_LOGE(TRANS_FILE, "malloc failedLen=%{public}d.", len);
        return SOFTBUS_MALLOC_ERR;
    }
    *(uint32_t *)data = SoftBusHtoLl(FILE_MAGIC_NUMBER);
    *(uint64_t *)(data + FRAME_MAGIC_OFFSET) =
        SoftBusHtoLll((FRAME_DATA_SEQ_OFFSET + sizeof(uint32_t) + sizeof(int32_t)));
    *(uint32_t *)(data + FRAME_HEAD_LEN) = SoftBusHtoLl(seq);
    *(uint32_t *)(data + FRAME_HEAD_LEN + FRAME_DATA_SEQ_OFFSET) = SoftBusHtoLl(side);
    *(int32_t *)(data + FRAME_HEAD_LEN + FRAME_DATA_SEQ_OFFSET + sizeof(uint32_t)) = SoftBusHtoLl((uint32_t)result);

    int32_t ret = ProxyChannelSendFileStream(channelId, data, len, TRANS_SESSION_FILE_RESULT_FRAME);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_FILE, "conn send file fail ret=%{public}d", ret);
    }
    SoftBusFree(data);
    return ret;
}

int32_t UnpackFileTransResultFrame(
    const uint8_t *data, uint32_t len, uint32_t *seq, int32_t *result, uint32_t *side)
{
    if (seq == NULL || result == NULL || side == NULL) {
        TRANS_LOGE(TRANS_FILE, "param invalid");
        return SOFTBUS_INVALID_PARAM;
    }
    if (data == NULL || len < FRAME_HEAD_LEN + FRAME_DATA_SEQ_OFFSET + FRAME_DATA_SEQ_OFFSET) {
        TRANS_LOGE(TRANS_FILE, "recv ack fail. responseLen=%{public}u", len);
        return SOFTBUS_TRANS_INVALID_DATA_LENGTH;
    }
    uint32_t magic = SoftBusLtoHl(*(uint32_t *)data);
    uint64_t dataLen = SoftBusLtoHll(*(uint64_t *)(data + FRAME_MAGIC_OFFSET));
    if (magic != FILE_MAGIC_NUMBER || dataLen != (FRAME_DATA_SEQ_OFFSET + sizeof(uint32_t) + sizeof(int32_t))) {
        TRANS_LOGE(
            TRANS_FILE, "recv ack response head fail. magic=%{public}u, dataLen=%{public}" PRIu64, magic, dataLen);
        return SOFTBUS_INVALID_DATA_HEAD;
    }
    (*seq) = SoftBusLtoHl((*(uint32_t *)(data + FRAME_HEAD_LEN)));
    (*side) = SoftBusLtoHl((*(uint32_t *)(data + FRAME_HEAD_LEN + FRAME_DATA_SEQ_OFFSET)));
    (*result) = (int32_t)SoftBusLtoHl(
        (uint32_t)(*(int32_t *)(data + FRAME_HEAD_LEN + FRAME_DATA_SEQ_OFFSET + sizeof(uint32_t))));
    TRANS_LOGI(TRANS_FILE, "seq=%{public}u, side=%{public}u, result=%{public}d", *seq, *side, *result);
    return SOFTBUS_OK;
}

int32_t SendFileAckReqAndResData(int32_t channelId, uint32_t startSeq, uint32_t value, int32_t type)
{
    uint32_t len = FRAME_HEAD_LEN + FRAME_DATA_SEQ_OFFSET + FRAME_DATA_SEQ_OFFSET;
    char *data = (char *)SoftBusCalloc(len);
    if (data == NULL) {
        TRANS_LOGE(TRANS_FILE, "calloc fail! len=%{public}d.", len);
        return SOFTBUS_MALLOC_ERR;
    }
    *(uint32_t *)data = SoftBusHtoLl(FILE_MAGIC_NUMBER);
    *(int64_t *)(data + FRAME_MAGIC_OFFSET) = SoftBusHtoLll((uint64_t)(FRAME_DATA_SEQ_OFFSET + FRAME_DATA_SEQ_OFFSET));
    *(uint32_t *)(data + FRAME_HEAD_LEN) = SoftBusHtoLl(startSeq);
    *(uint32_t *)(data + FRAME_HEAD_LEN + FRAME_DATA_SEQ_OFFSET) = SoftBusHtoLl(value);
    int32_t ret = ProxyChannelSendFileStream(channelId, data, len, type);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_FILE, "conn send ack buf fail ret=%{public}d.", ret);
    }
    SoftBusFree(data);
    return ret;
}

int32_t UnpackAckReqAndResData(FileFrame *frame, uint32_t *startSeq, uint32_t *value)
{
    if (frame == NULL || startSeq == NULL || value == NULL || frame->data == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    if (frame->frameLength < FRAME_HEAD_LEN + FRAME_DATA_SEQ_OFFSET + FRAME_DATA_SEQ_OFFSET) {
        TRANS_LOGE(TRANS_FILE, "unpack ack data fail. frameLen=%{public}d", frame->frameLength);
        return SOFTBUS_TRANS_INVALID_DATA_LENGTH;
    }
    frame->magic = SoftBusLtoHl((*(uint32_t *)(frame->data)));
    uint64_t dataLen = SoftBusLtoHll((*(uint64_t *)(frame->data + FRAME_MAGIC_OFFSET)));
    if (frame->magic != FILE_MAGIC_NUMBER || dataLen < FRAME_DATA_SEQ_OFFSET + FRAME_DATA_SEQ_OFFSET) {
        TRANS_LOGE(
            TRANS_FILE, "unpack ack head fail. magic=%{public}u, dataLen=%{public}" PRIu64, frame->magic, dataLen);
        return SOFTBUS_INVALID_DATA_HEAD;
    }
    frame->fileData = frame->data + FRAME_HEAD_LEN;
    (*startSeq) = SoftBusLtoHl((*(uint32_t *)(frame->fileData)));
    (*value) = SoftBusLtoHl((*(uint32_t *)(frame->fileData + FRAME_DATA_SEQ_OFFSET)));
    return SOFTBUS_OK;
}

int64_t PackReadFileData(FileFrame *fileFrame, uint64_t readLength, uint64_t fileOffset, SendListenerInfo *info)
{
    if (fileFrame == NULL || info == NULL) {
        TRANS_LOGE(TRANS_FILE, "param invalid");
        return SOFTBUS_INVALID_PARAM;
    }
    int64_t len = SoftBusPreadFile(info->fd, fileFrame->fileData + FRAME_DATA_SEQ_OFFSET, readLength, fileOffset);
    if (len <= 0) {
        TRANS_LOGE(TRANS_FILE, "pread src file failed. ret=%{public}" PRId64, len);
        return len;
    }
    if (info->crc == APP_INFO_FILE_FEATURES_SUPPORT && info->osType == OH_TYPE) {
        uint64_t dataLen = (uint64_t)len + FRAME_DATA_SEQ_OFFSET;
        fileFrame->frameLength = FRAME_HEAD_LEN + dataLen + FRAME_CRC_LEN;
        if (fileFrame->frameLength > info->packetSize) {
            TRANS_LOGE(TRANS_FILE, "frameLength invalid. frameLength=%{public}u", fileFrame->frameLength);
            return SOFTBUS_TRANS_INVALID_DATA_LENGTH;
        }
        uint16_t crc = RTU_CRC(fileFrame->fileData + FRAME_DATA_SEQ_OFFSET, len);
        (*(uint32_t *)(fileFrame->data)) = SoftBusHtoLl(fileFrame->magic);
        (*(uint64_t *)(fileFrame->data + FRAME_MAGIC_OFFSET)) = SoftBusHtoLll(dataLen);
        info->seq++;
        (*(uint32_t *)(fileFrame->fileData)) = SoftBusHtoLl(info->seq);
        (*(uint16_t *)(fileFrame->fileData + dataLen)) = SoftBusHtoLs(crc);
        info->checkSumCRC += crc;
    } else {
        uint64_t tmp = FRAME_DATA_SEQ_OFFSET + (uint64_t)len;
        if (tmp > UINT32_MAX) {
            TRANS_LOGE(TRANS_FILE, "Overflow error");
            return SOFTBUS_INVALID_NUM;
        }
        fileFrame->frameLength = (uint32_t)tmp;
        if (fileFrame->frameLength > info->packetSize) {
            TRANS_LOGE(TRANS_FILE, "frameLength invalid. frameLength=%{public}u", fileFrame->frameLength);
            return SOFTBUS_TRANS_INVALID_DATA_LENGTH;
        }
        (*(int32_t *)(fileFrame->fileData)) = SoftBusHtoLl((uint32_t)info->channelId);
    }
    return len;
}

static int64_t PackReadFileRetransData(
    FileFrame *fileFrame, uint32_t seq, uint64_t readLength, uint64_t fileOffset, const SendListenerInfo *info)
{
    if (fileFrame == NULL || info == NULL) {
        TRANS_LOGE(TRANS_FILE, "param invalid");
        return SOFTBUS_INVALID_PARAM;
    }
    int64_t len = SoftBusPreadFile(info->fd, fileFrame->fileData + FRAME_DATA_SEQ_OFFSET, readLength, fileOffset);
    if (len <= 0) {
        TRANS_LOGE(TRANS_FILE, "pread src file failed. ret=%{public}" PRId64, len);
        return len;
    }
    uint64_t dataLen = (uint64_t)len + FRAME_DATA_SEQ_OFFSET;
    fileFrame->frameLength = FRAME_HEAD_LEN + dataLen + FRAME_CRC_LEN;
    if (fileFrame->frameLength > info->packetSize) {
        TRANS_LOGE(TRANS_FILE, "frameLength invalid. frameLength=%{public}u", fileFrame->frameLength);
        return SOFTBUS_TRANS_INVALID_DATA_LENGTH;
    }
    uint16_t crc = RTU_CRC(fileFrame->fileData + FRAME_DATA_SEQ_OFFSET, len);
    (*(uint32_t *)(fileFrame->data)) = SoftBusHtoLl(fileFrame->magic);
    (*(uint64_t *)(fileFrame->data + FRAME_MAGIC_OFFSET)) = SoftBusHtoLll(dataLen);
    (*(uint32_t *)(fileFrame->fileData)) = SoftBusHtoLl(seq);
    (*(uint16_t *)(fileFrame->fileData + dataLen)) = SoftBusHtoLs(crc);

    int32_t ret = ProxyChannelSendFileStream(info->channelId, (char *)fileFrame->data, fileFrame->frameLength,
        FrameIndexToType((uint64_t)seq, info->frameNum));
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_FILE, "conn send buf fail ret=%{public}d", ret);
        return ret;
    }
    return len;
}

int32_t UnpackFileDataFrame(FileRecipientInfo *info, FileFrame *fileFrame, uint32_t *fileDataLen)
{
    if (info == NULL || fileFrame == NULL || fileDataLen == NULL) {
        TRANS_LOGE(TRANS_FILE, "param invalid");
        return SOFTBUS_INVALID_PARAM;
    }
    if (info->crc == APP_INFO_FILE_FEATURES_SUPPORT && info->osType == OH_TYPE) {
        if (fileFrame->frameLength <= FRAME_HEAD_LEN + FRAME_DATA_SEQ_OFFSET + FRAME_CRC_LEN) {
            TRANS_LOGE(TRANS_FILE, "frameLength invalid. frameLength=%{public}u", fileFrame->frameLength);
            return SOFTBUS_TRANS_INVALID_DATA_LENGTH;
        }
        fileFrame->magic = SoftBusLtoHl((*(uint32_t *)(fileFrame->data)));
        uint64_t dataLen = SoftBusLtoHll((*(uint64_t *)(fileFrame->data + FRAME_MAGIC_OFFSET)));
        if (fileFrame->magic != FILE_MAGIC_NUMBER ||
            dataLen != fileFrame->frameLength - (FRAME_HEAD_LEN + FRAME_CRC_LEN)) {
            TRANS_LOGE(TRANS_FILE, "unpack data frame failed. magic=%{public}u, dataLen=%{public}" PRIu64,
                fileFrame->magic, dataLen);
            return SOFTBUS_INVALID_DATA_HEAD;
        }
        fileFrame->fileData = fileFrame->data + FRAME_HEAD_LEN;
        fileFrame->seq = SoftBusLtoHl((*(uint32_t *)(fileFrame->fileData)));
        uint16_t recvCRC = SoftBusLtoHs((*(uint16_t *)(fileFrame->fileData + dataLen)));
        uint16_t crc = RTU_CRC(fileFrame->fileData + FRAME_DATA_SEQ_OFFSET, dataLen - FRAME_DATA_SEQ_OFFSET);
        if (crc != recvCRC) {
            TRANS_LOGE(
                TRANS_FILE, "crc check fail recvCrc=%{public}u, crc=%{public}u", (uint32_t)recvCRC, (uint32_t)crc);
            return SOFTBUS_FILE_ERR;
        }
        *fileDataLen = dataLen;
        fileFrame->crc = crc;
    } else {
        fileFrame->fileData = fileFrame->data;
        if (fileFrame->frameLength <= FRAME_DATA_SEQ_OFFSET) {
            TRANS_LOGE(TRANS_FILE, "frameLength invalid. frameLength=%{public}u", fileFrame->frameLength);
            return SOFTBUS_TRANS_INVALID_DATA_LENGTH;
        }
        fileFrame->seq = SoftBusLtoHl((*(uint32_t *)(fileFrame->fileData)));
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
        TRANS_LOGE(TRANS_FILE, "param invalid");
        return SOFTBUS_INVALID_PARAM;
    }
    FileFrame fileFrame = { 0 };
    fileFrame.data = (uint8_t *)SoftBusCalloc(info->packetSize);
    if (fileFrame.data == NULL) {
        TRANS_LOGE(TRANS_FILE, "data calloc fail");
        return SOFTBUS_MALLOC_ERR;
    }
    fileFrame.magic = FILE_MAGIC_NUMBER;
    fileFrame.fileData = fileFrame.data + FRAME_HEAD_LEN;
    uint64_t frameDataSize = info->packetSize - FRAME_HEAD_LEN - FRAME_DATA_SEQ_OFFSET - FRAME_CRC_LEN;
    uint64_t fileOffset = frameDataSize * ((uint32_t)seq - 1);
    if (fileOffset >= info->fileSize) {
        TRANS_LOGE(TRANS_FILE, "retrans file frame failed, seq=%{public}d", seq);
        SoftBusFree(fileFrame.data);
        return SOFTBUS_INVALID_PARAM;
    }
    uint64_t remainedSize = info->fileSize - fileOffset;
    uint64_t readLength = (remainedSize < frameDataSize) ? remainedSize : frameDataSize;
    int64_t len = PackReadFileRetransData(&fileFrame, seq, readLength, fileOffset, info);
    if (len <= 0) {
        TRANS_LOGE(TRANS_FILE, "retrans file frame failed");
        SoftBusFree(fileFrame.data);
        return SOFTBUS_TRANS_INVALID_DATA_LENGTH;
    }
    SoftBusFree(fileFrame.data);
    return SOFTBUS_OK;
}

int32_t AckResponseDataHandle(const SendListenerInfo *info, const char *data, uint32_t len)
{
    if (info == NULL || data == NULL || len != sizeof(AckResponseData)) {
        TRANS_LOGE(TRANS_FILE, "data or len invalid");
        return SOFTBUS_OK;
    }
    AckResponseData *resData = (AckResponseData *)data;
    uint32_t startSeq = resData->startSeq;
    uint32_t seqResult = resData->seqResult;
    if (seqResult != FILE_SEND_ACK_RESULT_SUCCESS) {
        for (int32_t i = 0; i < FILE_SEND_ACK_INTERVAL; i++) {
            if (((seqResult >> i) & 0x01) == 0x01) {
                continue;
            }
            uint32_t failSeq = startSeq + (uint32_t)i;
            int32_t ret = RetransFileFrameBySeq(info, (int32_t)failSeq);
            TRANS_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, TRANS_FILE, "retrans file fail!");
        }
    }
    return SOFTBUS_OK;
}

char *GetFullRecvPath(const char *filePath, const char *recvRootDir)
{
    if ((filePath == NULL) || (recvRootDir == NULL)) {
        TRANS_LOGE(TRANS_FILE, "filePath or rootDir is null");
        return NULL;
    }
    int32_t rootDirLength = (int32_t)strlen(recvRootDir);
    int32_t filePathLength = (int32_t)strlen(filePath);
    bool isNeedAddSep = true;
    if (((filePathLength > 0) && (filePath[0] == PATH_SEPARATOR)) ||
        ((rootDirLength > 0) && (recvRootDir[rootDirLength - 1] == PATH_SEPARATOR))) {
        isNeedAddSep = false;
    }
    int32_t destFullPathLength =
        (int32_t)((isNeedAddSep) ? (rootDirLength + sizeof('/') + filePathLength) : (rootDirLength + filePathLength));
    char *recvFullPath = (char *)SoftBusCalloc(destFullPathLength + 1);
    if (recvFullPath == NULL) {
        TRANS_LOGE(TRANS_FILE, "recvFullPath is null");
        return NULL;
    }
    int32_t ret;
    if (isNeedAddSep) {
        ret = sprintf_s(recvFullPath, destFullPathLength + 1, "%s/%s", recvRootDir, filePath);
    } else {
        ret = sprintf_s(recvFullPath, destFullPathLength + 1, "%s%s", recvRootDir, filePath);
    }
    if (ret < 0) {
        TRANS_LOGE(TRANS_FILE, "create fullPath fail");
        SoftBusFree(recvFullPath);
        return NULL;
    }
    return recvFullPath;
}

static int32_t GetDirPath(const char *fullPath, char *dirPath, int32_t dirPathLen)
{
    if ((fullPath == NULL) || (strlen(fullPath) < 1) || (fullPath[strlen(fullPath) - 1] == PATH_SEPARATOR)) {
        TRANS_LOGE(TRANS_FILE, "invalid input param");
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
        TRANS_LOGE(TRANS_FILE, "dirLen >= dirPathLen. dirLen=%{public}d, dirPathLen=%{public}d", dirLen, dirPathLen);
        return SOFTBUS_INVALID_PARAM;
    }
    if (strncpy_s(dirPath, dirPathLen, fullPath, dirLen) != EOK) {
        TRANS_LOGE(TRANS_FILE, "strcpy_s dir path error, dirLen=%{public}d", dirLen);
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
        TRANS_LOGE(TRANS_FILE, "get dir path failed");
        SoftBusFree(dirPath);
        return SOFTBUS_INVALID_PARAM;
    }
    char *absFullDir = (char *)SoftBusCalloc(PATH_MAX + 1);
    if (absFullDir == NULL) {
        TRANS_LOGE(TRANS_FILE, "calloc absFullDir failed");
        SoftBusFree(dirPath);
        return SOFTBUS_MALLOC_ERR;
    }
    int32_t fileNameLength = -1;
    int32_t dirPathLength = -1;
    const char *fileName = TransGetFileName(fullPath);
    if (fileName == NULL) {
        TRANS_LOGE(TRANS_FILE, "get file name failed");
        goto EXIT_ERR;
    }
    if (GetAndCheckRealPath(dirPath, absFullDir) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_FILE, "get full abs file failed");
        goto EXIT_ERR;
    }
    TRANS_LOGI(TRANS_FILE, "dirPath=%{private}s, absFullDir=%{private}s", dirPath, absFullDir);
    fileNameLength = (int32_t)strlen(fileName);
    dirPathLength = (int32_t)strlen(absFullDir);
    if (pathSize < (fileNameLength + dirPathLength + 1)) {
        TRANS_LOGE(TRANS_FILE, "copy name is too large, dirLen=%{public}d, fileNameLen=%{public}d",
            dirPathLength, fileNameLength);
        goto EXIT_ERR;
    }
    TRANS_LOGI(TRANS_FILE, "fileName=%{private}s, fileNameLen=%{public}d", fileName, fileNameLength);
    if (sprintf_s(recvAbsPath, pathSize, "%s/%s", absFullDir, fileName) < 0) {
        TRANS_LOGE(TRANS_FILE, "sprintf_s filename error");
        goto EXIT_ERR;
    }
    TRANS_LOGI(TRANS_FILE, "recvAbsPath=%{private}s", recvAbsPath);
    SoftBusFree(absFullDir);
    SoftBusFree(dirPath);
    return SOFTBUS_OK;

EXIT_ERR:
    SoftBusFree(dirPath);
    SoftBusFree(absFullDir);
    return SOFTBUS_FILE_ERR;
}

int32_t CreateDirAndGetAbsPath(const char *filePath, char *recvAbsPath, int32_t pathSize)
{
    if ((filePath == NULL) || (recvAbsPath == NULL)) {
        TRANS_LOGE(TRANS_FILE, "invalid input");
        return SOFTBUS_INVALID_PARAM;
    }
    uint32_t len = (uint32_t)strlen(filePath);
    int32_t ret;
    char *tempPath = (char *)SoftBusCalloc(len + 1);
    if (tempPath == NULL) {
        TRANS_LOGE(TRANS_FILE, "calloc tempPath failed");
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
                TRANS_LOGE(TRANS_FILE, "mkdir failed errno=%{public}d", errno);
                SoftBusFree(tempPath);
                return SOFTBUS_FILE_ERR;
            }
        }
    }

    SoftBusFree(tempPath);
    ret = GetAbsFullPath(filePath, recvAbsPath, pathSize);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGI(TRANS_FILE, "dest dir is invalid");
        return ret;
    }
    return SOFTBUS_OK;
}
