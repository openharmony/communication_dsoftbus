/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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

#include "nstackx_dfile_frame.h"
#include "nstackx_util.h"
#include "nstackx_error.h"
#include "nstackx_dfile.h"
#include "nstackx_dfile_log.h"
#include "nstackx_dfile_config.h"
#include "nstackx_dev.h"
#include "securec.h"

#define TAG "nStackXDFile"

const char *GetFrameName(DFileFrameType frameType)
{
    uint32_t i;

    static const char *frameNameList[] = {
        [NSTACKX_DFILE_FILE_HEADER_FRAME] = "FILE_HEADER_FRAME",
        [NSTACKX_DFILE_FILE_HEADER_CONFIRM_FRAME] = "FILE_HEADER_CONFIRM_FRAME",
        [NSTACKX_DFILE_FILE_TRANSFER_REQ_FRAME] = "FILE_TRANSFER_REQ_FRAME",
        [NSTACKX_DFILE_FILE_DATA_FRAME] = "FILE_DATA_FRAME",
        [NSTACKX_DFILE_FILE_TRANSFER_DONE_FRAME] = "FILE_TRANSFER_DONE_FRAME",
        [NSTACKX_DFILE_FILE_TRANSFER_DONE_ACK_FRAME] = "FILE_TRANSFER_DONE_ACK_FRAME",
        [NSTACKX_DFILE_SETTING_FRAME] = "SETTING_FRAME",
        [NSTACKX_DFILE_RST_FRAME] = "RST_FRAME",
    };

    for (i = 0; i < sizeof(frameNameList) / sizeof(frameNameList[0]); i++) {
        if (i == frameType) {
            return frameNameList[i];
        }
    }

    return "unknown";
}

uint64_t GetTarTotalBlockLength(FileList *fileList)
{
    char pathSeparator = '/';
    uint64_t tarFilesTotalLen = 0;
    uint64_t blockCnt;
    uint32_t i;
    int32_t ret;
    struct stat statInfo;
    char *path = NULL;

    for (i = 0; i < fileList->num; i++) {
        tarFilesTotalLen += BLOCK_LEN;

        path = fileList->list[i].fullFileName;
        if (strlen(path) > MAX_NAME_LEN) {
            // +1 because of the string end '\0'
            tarFilesTotalLen += BLOCK_LEN +
                (((strlen(path) + 1 - (long long)(path[0] == pathSeparator) + BLOCK_LEN - 1) / BLOCK_LEN) * BLOCK_LEN);
        }

        ret = stat(path, &statInfo);
        if (ret != NSTACKX_EOK) {
            DFILE_LOGE(TAG, "get stat error: %d", ret);
            return 0;
        }

        // file body length
        blockCnt = (uint64_t)((statInfo.st_size + BLOCK_LEN - 1) / BLOCK_LEN);
        tarFilesTotalLen += (blockCnt * BLOCK_LEN);
    }

    // file tail paddings length
    tarFilesTotalLen += BLOCK_LEN;

    return tarFilesTotalLen;
}

static int32_t EncodeFileInfo(FileList *fileList, uint16_t fileId, uint8_t *buffer, size_t length,
    size_t *fileInfoSize)
{
    FileInfoUnit *fileInfoUnit = (FileInfoUnit *)buffer;
    const char *fileName = NULL;
    uint16_t fileNameLen;
    size_t remainLength;
    uint64_t filesTotalLen;

    if (fileId == 0) {
        if (fileList->packedUserData != NULL) {
            fileName = (char *)fileList->packedUserData;
            fileNameLen = fileList->packedUserDataLen;
        } else {
            fileName = fileList->userData;
            fileNameLen = (uint16_t)strlen(fileName);
        }
        filesTotalLen = 0;
    } else {
        fileName = FileListGetRemotePath(fileList, fileId);
        if (fileName == NULL) {
            fileName = FileListGetFileName(fileList, fileId);
        }
        fileNameLen = (uint16_t)strlen(fileName);
        if (fileList->tarFlag == NSTACKX_FALSE) {
            filesTotalLen = FileListGetFileSize(fileList, fileId);
        } else {
            filesTotalLen = GetTarTotalBlockLength(fileList);
        }
    }

    if (length <= offsetof(FileInfoUnit, fileName)) {
        /* Running out of buffer */
        DFILE_LOGE(TAG, "buffer length %zu is not enough", length);
        return NSTACKX_EAGAIN;
    }
    remainLength = length - offsetof(FileInfoUnit, fileName);
    if (memcpy_s(fileInfoUnit->fileName, remainLength, fileName, fileNameLen) != EOK) {
        /* Running out of buffer */
        DFILE_LOGE(TAG, "memcpy_s fileName error. remain length %zu, fileNameLen %hu", remainLength, fileNameLen);
        return NSTACKX_EAGAIN;
    }
    fileInfoUnit->fileId = htons(fileId);
    fileInfoUnit->fileSize = htobe64(filesTotalLen);
    fileInfoUnit->fileNameLength = htons(fileNameLen);
    *fileInfoSize = offsetof(FileInfoUnit, fileName) + fileNameLen;
    return NSTACKX_EOK;
}

/* Caller should make sure that "length" can cover the minimum header length */
void EncodeFileHeaderFrameSp(FileList *fileList, int32_t *fileId, uint8_t *buffer, size_t length,
    size_t *frameLength)
{
    FileHeaderFrame *headerFrame = (FileHeaderFrame *)buffer;
    size_t offset = 0;
    size_t fileInfoSize = 0;
    size_t bufferLength = length;
    int32_t nextFileId;
    int32_t lastAddedFileId = *fileId;
    uint32_t fileNum;

    /* Remaining buffer length for fileInfoUnit */
    bufferLength -= (sizeof(uint16_t) + DFILE_FRAME_HEADER_LEN);

    if (fileList->tarFlag == NSTACKX_TRUE) {
        fileNum = 1;
    } else {
        fileNum = FileListGetNum(fileList);
    }

    do {
        if (lastAddedFileId == (int32_t)fileNum || bufferLength <= offset) {
            break;
        }

        nextFileId = lastAddedFileId + 1;
        if (FileListGetFileNameAcked(fileList, (uint16_t)nextFileId) ||
            (nextFileId == 0 && fileList->userData == NULL && fileList->packedUserData == NULL)) {
            DFILE_LOGI(TAG, "SKIP FILE ID %d", nextFileId);
            lastAddedFileId = nextFileId;
            continue;
        }

        if (EncodeFileInfo(fileList, (uint16_t)nextFileId, &headerFrame->fileInfoUnit[offset],
            bufferLength - offset, &fileInfoSize) != NSTACKX_EOK) {
            DFILE_LOGE(TAG, "EncodeFileInfo fileId %d failed", nextFileId);
            break;
        }

        offset += fileInfoSize;
        lastAddedFileId = nextFileId;
    } while (NSTACKX_TRUE);

    headerFrame->header.type = NSTACKX_DFILE_FILE_HEADER_FRAME;
    if (fileList->userData != NULL) {
        SetDfileFrameUserDataFlag(&headerFrame->header);
    }

    if (fileList->pathType > 0) {
        SetDfileFramePathTypeFlag(&headerFrame->header);
    }
    /* set no sync flag */
    if (fileList->noSyncFlag) {
        SetDfileFrameNoSyncFlag(&headerFrame->header);
    }
    /* Add "node number" */
    offset += sizeof(uint16_t);
    headerFrame->header.length = htons((uint16_t)offset);
    headerFrame->nodeNumber = htons((uint16_t)fileNum);
    /* Update internal buffer length */
    *frameLength = DFILE_FRAME_HEADER_LEN + offset;
    *fileId = lastAddedFileId;
}

void EncodeFileHeaderFrame(FileList *fileList, int32_t *fileId, uint8_t *buffer, size_t length,
    size_t *frameLength)
{
    EncodeFileHeaderFrameSp(fileList, fileId, buffer, length, frameLength);
}

/* Caller should make sure that "length" can cover the minimum header length */
void EncodeFileHeaderConfirmFrame(FileList *fileList, uint16_t *fileId, uint8_t *buffer, size_t length,
    size_t *frameLength)
{
    FileHeaderConfirmFrame *confirmFrame = (FileHeaderConfirmFrame *)buffer;
    size_t bufferLength = length;
    uint16_t payloadLength;
    uint16_t nextFileId;
    uint16_t lastAckedFileId = *fileId;
    uint16_t i = 0;

    /* Remaining buffer length for payload */
    bufferLength -= DFILE_FRAME_HEADER_LEN;

    if ((fileList->userDataFlag & NSTACKX_DFILE_HEADER_FRAME_USER_DATA_FLAG) &&
        (fileList->userDataFlag & NSTACKX_FLAGS_FILE_NAME_RECEIVED)) {
        confirmFrame->fileId[i] = 0;
        i++;
    }

    do {
        if (lastAckedFileId == FileListGetNum(fileList)) {
            break;
        }

        nextFileId = lastAckedFileId + 1;
        if (!FileListGetFileNameReceived(fileList, nextFileId)) {
            lastAckedFileId = nextFileId;
            DFILE_LOGE(TAG, "fileId %u is not acked yet", nextFileId);
            continue;
        }
        if (i >= (bufferLength >> 1)) {
            break;
        }
        confirmFrame->fileId[i++] = htons(nextFileId);
        lastAckedFileId = nextFileId;
    } while (NSTACKX_TRUE);

    payloadLength = (uint16_t)(i * sizeof(uint16_t)); /* length should be within MTU to avoid overflow */
    confirmFrame->header.type = NSTACKX_DFILE_FILE_HEADER_CONFIRM_FRAME;
    /* Don't have to set flag for ACK frame */
    confirmFrame->header.flag = 0;
    confirmFrame->header.length = htons(payloadLength);

    /* Update internal buffer length */
    *frameLength = DFILE_FRAME_HEADER_LEN + payloadLength;
    *fileId = lastAckedFileId;
}

/* Caller should make sure that "length" can cover the minimum header length */
void EncodeFileTransferDoneFrame(uint8_t *buffer, size_t length, uint16_t fileIdList[], uint32_t fileIdNum,
                                 size_t *frameLength)
{
    uint32_t i;
    uint32_t maxIdNum;
    uint16_t payloadLength;
    FileTransferDoneFrame *transferDoneFrame = (FileTransferDoneFrame *)buffer;

    maxIdNum = (uint32_t)((length - DFILE_FRAME_HEADER_LEN) / sizeof(uint16_t));
    if (maxIdNum > fileIdNum) {
        maxIdNum = fileIdNum;
    }

    for (i = 0; i < maxIdNum; i++) {
        transferDoneFrame->fileId[i] = htons(fileIdList[i]);
    }

    transferDoneFrame->header.type = NSTACKX_DFILE_FILE_TRANSFER_DONE_FRAME;

    payloadLength = (uint16_t)(maxIdNum * sizeof(uint16_t));
    transferDoneFrame->header.length = htons(payloadLength);

    *frameLength = DFILE_FRAME_HEADER_LEN + payloadLength;
}

/* Caller should make sure that "length" can cover the minimum header length */
void EncodeSettingFrame(uint8_t *buffer, size_t length, size_t *frameLength, const SettingFrame *settingFramePara)
{
    SettingFrame *settingFrame = (SettingFrame *)buffer;

    *frameLength = sizeof(SettingFrame);
    if (*frameLength > length) {
        return;
    }
    settingFrame->header.type = NSTACKX_DFILE_SETTING_FRAME;
    settingFrame->header.flag = 0;
    settingFrame->header.sessionId = 0;
    settingFrame->header.transId = 0;
    settingFrame->mtu = htons(settingFramePara->mtu);
    settingFrame->connType = htons(settingFramePara->connType);
    settingFrame->dFileVersion = htonl(NSTACKX_DFILE_VERSION);
    settingFrame->abmCapability = 0;
    settingFrame->header.length = htons(*frameLength - DFILE_FRAME_HEADER_LEN);
    settingFrame->capability = htonl(settingFramePara->capability);
    settingFrame->dataFrameSize = htonl(settingFramePara->dataFrameSize);
    settingFrame->capsCheck = htonl(settingFramePara->capsCheck);
    settingFrame->cipherCapability = htonl(settingFramePara->cipherCapability);
}

/* Caller should make sure that "length" can cover the minimum header length */
void EncodeRstFrame(uint8_t *buffer, size_t length, size_t *frameLength, uint16_t transId, uint16_t errCode)
{
    RstFrame *rstFrame = (RstFrame *)buffer;
    uint16_t payloadLength;

    payloadLength = sizeof(uint16_t);
    *frameLength = DFILE_FRAME_HEADER_LEN + payloadLength;
    if (*frameLength > length) {
        return;
    }
    rstFrame->header.type = NSTACKX_DFILE_RST_FRAME;
    rstFrame->header.flag = 0;
    rstFrame->header.sessionId = 0;
    rstFrame->header.transId = htons(transId);
    rstFrame->code = htons(errCode);
    rstFrame->header.length = htons(payloadLength);
}

void EncodeBackPressFrame(uint8_t *buffer, size_t length, size_t *frameLength, uint8_t recvListOverIo)
{
    BackPressureFrame *backPressFrame = (BackPressureFrame *)buffer;
    uint16_t payloadLength;

    payloadLength = sizeof(DataBackPressure);
    *frameLength = DFILE_FRAME_HEADER_LEN + payloadLength;
    if (*frameLength > length) {
        return;
    }

    backPressFrame->header.type = NSTACKX_DFILE_FILE_BACK_PRESSURE_FRAME;
    backPressFrame->header.flag = 0;
    backPressFrame->header.sessionId = 0;
    backPressFrame->header.transId = 0;
    backPressFrame->header.length = htons(payloadLength);
    backPressFrame->backPressure.recvListOverIo = recvListOverIo;
    backPressFrame->backPressure.recvBufThreshold = 0;
    backPressFrame->backPressure.stopSendPeriod = htonl(0);
}

/* Caller should make sure that "length" can cover the minimum header length */
void EncodeFileTransferDoneAckFrame(uint8_t *buffer, size_t length, uint16_t transId, size_t *frameLength)
{
    FileTransferDoneAckFrame *transferDoneAckFrame = (FileTransferDoneAckFrame *)buffer;

    *frameLength = DFILE_FRAME_HEADER_LEN;
    if (*frameLength > length) {
        return;
    }
    transferDoneAckFrame->header.type = NSTACKX_DFILE_FILE_TRANSFER_DONE_ACK_FRAME;
    transferDoneAckFrame->header.transId = htons(transId);
}

int32_t DecodeDFileFrame(const uint8_t *buffer, size_t bufferLength, DFileFrame **frame)
{
    DFileFrame *dFileFrame = (DFileFrame *)buffer;
    uint16_t payloadLength;

    if (bufferLength < DFILE_FRAME_HEADER_LEN) {
        DFILE_LOGE(TAG, "drop malformed frame");
        return NSTACKX_EFAILED;
    }

    payloadLength = ntohs(dFileFrame->header.length);
    if (bufferLength - DFILE_FRAME_HEADER_LEN != payloadLength) {
        DFILE_LOGE(TAG, "drop malformed frame");
        return NSTACKX_EFAILED;
    }

    *frame = dFileFrame;
    return NSTACKX_EOK;
}

static inline void SetDfileHeaderFrameUserDataFlag(FileList *fileList)
{
    fileList->userDataFlag = fileList->userDataFlag | NSTACKX_DFILE_HEADER_FRAME_USER_DATA_FLAG;
}

static inline uint8_t CheckDfileHeaderFrameUserDataFlag(uint8_t flag)
{
    return flag & NSTACKX_DFILE_HEADER_FRAME_USER_DATA_FLAG;
}

static inline uint8_t CheckDfileHeaderFramePathTypeFlag(uint8_t flag)
{
    return flag & NSTACKX_DFILE_HEADER_FRAME_PATH_TYPE_FLAG;
}

static inline uint8_t CheckDfileHeaderFrameNoSyncFlag(uint8_t flag)
{
    return flag & NSTACKX_DFILE_HEADER_FRAME_NO_SYNC_FLAG;
}

int32_t DecodeFileHeaderFrameSp(FileList *fileList, FileHeaderFrame *headerFrame)
{
    FileInfoUnit *fileInfoUnit = NULL;
    size_t offset = 0;
    if (ntohs(headerFrame->header.length) <= sizeof(uint16_t)) {
        return NSTACKX_EFAILED;
    }
    uint8_t *buffer = (uint8_t *)headerFrame->fileInfoUnit;
    uint16_t length = ntohs(headerFrame->header.length) - sizeof(uint16_t);
    uint16_t nodeNumber = ntohs(headerFrame->nodeNumber);
    int32_t ret;
    if (FileListSetNum(fileList, nodeNumber) != NSTACKX_EOK) {
        return NSTACKX_EFAILED;
    }
    if (CheckDfileHeaderFrameUserDataFlag(headerFrame->header.flag) != 0 ||
        (CheckDfileHeaderFramePathTypeFlag(headerFrame->header.flag) != 0)) {
        SetDfileHeaderFrameUserDataFlag(fileList);
    }
    if (CheckDfileHeaderFrameNoSyncFlag(headerFrame->header.flag) != 0) {
        fileList->noSyncFlag = NSTACKX_TRUE;
    }
    while (offset < length) {
        fileInfoUnit = (FileInfoUnit *)&buffer[offset];
        if (length - offset <= offsetof(FileInfoUnit, fileName)) {
            DFILE_LOGE(TAG, "length %u is too small", length);
            return NSTACKX_EFAILED;
        }
        size_t fileNameLength = ntohs(fileInfoUnit->fileNameLength);
        uint16_t fileId = ntohs(fileInfoUnit->fileId);
        if ((fileId == 0) && !(CheckDfileHeaderFrameUserDataFlag(headerFrame->header.flag)) &&
            !(CheckDfileHeaderFramePathTypeFlag(headerFrame->header.flag))) {
            /* Invalid file id, discard the whole frame. */
            return NSTACKX_EFAILED;
        }
        /*
         * fileNameLength validation:
         * 1) Minimum value:
         *    For normal file name (file id != 0), it should be > 0;
         *    For user data (file id = 0), 0 is allowed.
         * 2) Maximum value: should be <= remaining buffer - offsetof(FileInfoUnit, fileName)
         */
        if ((fileId != 0 && fileNameLength == 0) ||
            (fileNameLength > (length - offset - offsetof(FileInfoUnit, fileName)))) {
            return NSTACKX_EFAILED;
        }
        if (fileId == 0) {
            ret = FileListAddUserData(fileList, fileInfoUnit->fileName, fileNameLength, headerFrame->header.flag);
        } else {
            uint64_t fileSize = be64toh(fileInfoUnit->fileSize);
            ret = FileListAddFile(fileList, fileId, fileInfoUnit->fileName, fileNameLength, fileSize);
        }
        if (ret != NSTACKX_EOK) {
            return NSTACKX_EFAILED;
        }
        offset += (offsetof(FileInfoUnit, fileName) + fileNameLength);
    }

    return NSTACKX_EOK;
}

int32_t DecodeFileHeaderFrame(FileList *fileList, FileHeaderFrame *headerFrame)
{
    return DecodeFileHeaderFrameSp(fileList, headerFrame);
}

int32_t DecodeFileHeaderConfirmFrame(FileList *fileList, FileHeaderConfirmFrame *confirmFrame)
{
    uint16_t fileId;
    uint16_t i;
    size_t length = ntohs(confirmFrame->header.length);
    DFILE_LOGI(TAG, "header confirm frame length %u", length);
    /* Make sure payload buffer should contain valid number of file ID. */
    if (length == 0 || length % sizeof(uint16_t) != 0) {
        return NSTACKX_EFAILED;
    }
    uint16_t *fileIdList = confirmFrame->fileId;
    uint16_t fileIdCount = (uint16_t)(length >> 1);

    for (i = 0; i < fileIdCount; i++) {
        fileId = ntohs(fileIdList[i]);
        if (fileId > FileListGetNum(fileList)) {
            DFILE_LOGE(TAG, "Invalid file ID %u", fileId);
            continue;
        }
        FileListSetFileNameAcked(fileList, fileId);
    }

    return NSTACKX_EOK;
}

int16_t GetFileIdFromFileDataFrame(const FileList *fileList, const FileDataFrame *dataFrame)
{
    uint16_t fileId;

    fileId = ntohs(dataFrame->fileId);
    if (fileId == NSTACKX_RESERVED_FILE_ID || fileId > FileListGetNum(fileList)) {
        return 0;
    }

    return (int16_t)fileId;
}

int32_t DecodeFileTransferDoneFrame(FileList *fileList, FileTransferDoneFrame *transferDoneFrame)
{
    uint32_t i;
    uint32_t fileIdNum;
    uint16_t fileId;

    uint16_t length = ntohs(transferDoneFrame->header.length);
    if (length == 0 || length % sizeof(uint16_t) != 0) {
        return NSTACKX_EFAILED;
    }
    fileIdNum = length / sizeof(uint16_t);

    DFILE_LOGI(TAG, "transId %u, FileTransferDone:fileIdNum %u, file number %u",
         ntohs(transferDoneFrame->header.transId), fileIdNum, FileListGetNum(fileList));
    for (i = 0; i < fileIdNum; i++) {
        fileId = ntohs(transferDoneFrame->fileId[i]);
        if (fileId == 0 || fileId > FileListGetNum(fileList)) {
            continue;
        }
        FileListSetFileSendSuccess(fileList, fileId);
    }
    return NSTACKX_EOK;
}

static uint8_t IsSettingFrameLengthValid(const SettingFrame *hostSettingFrame, uint16_t payloadLength)
{
    /*
     * From dfile with historical version NSTACKX_DFILE_VERSION_0, whose setting frame is composed of header,
     * mtu and connType.
     */
    size_t hostFrameLength = 0;
    if (payloadLength == (hostFrameLength += sizeof(hostSettingFrame->mtu) + sizeof(hostSettingFrame->connType))) {
        return NSTACKX_TRUE;
    }

    if (payloadLength == (hostFrameLength += sizeof(hostSettingFrame->dFileVersion))) {
        return NSTACKX_TRUE;
    }

    if (payloadLength == (hostFrameLength += sizeof(hostSettingFrame->abmCapability))) {
        return NSTACKX_TRUE;
    }

    if (payloadLength == (hostFrameLength += sizeof(hostSettingFrame->capability))) {
        return NSTACKX_TRUE;
    }

    if (payloadLength == (hostFrameLength += sizeof(hostSettingFrame->dataFrameSize))) {
        return NSTACKX_TRUE;
    }

    if (payloadLength == (hostFrameLength += sizeof(hostSettingFrame->capsCheck))) {
        return NSTACKX_TRUE;
    }

    if (payloadLength == (hostFrameLength += sizeof(hostSettingFrame->productVersion))) {
        return NSTACKX_TRUE;
    }

    if (payloadLength == (hostFrameLength += sizeof(hostSettingFrame->isSupport160M))) {
        return NSTACKX_TRUE;
    }

    if (payloadLength ==
        (hostFrameLength += sizeof(hostSettingFrame->isSupportMtp) + sizeof(hostSettingFrame->mtpPort))) {
        return NSTACKX_TRUE;
    }

    if (payloadLength == (hostFrameLength += sizeof(hostSettingFrame->headerEnc))) {
        return NSTACKX_TRUE;
    }

    if (payloadLength == (hostFrameLength += sizeof(hostSettingFrame->mtpCapability))) {
        return NSTACKX_TRUE;
    }

    if (payloadLength == (hostFrameLength += sizeof(hostSettingFrame->cipherCapability))) {
        return NSTACKX_TRUE;
    }
    /*
     * From dfile with the same version with local dfile.
     */
    if (payloadLength >= sizeof(SettingFrame) - DFILE_FRAME_HEADER_LEN) {
        return NSTACKX_TRUE;
    }

    return NSTACKX_FALSE;
}

static uint8_t IsSettingFrameMtuAndTypeValid(const SettingFrame *netSettingFrame)
{
    if (ntohs(netSettingFrame->mtu) < NSTACKX_MIN_MTU_SIZE ||
        ntohs(netSettingFrame->connType) == CONNECT_TYPE_NONE ||
        ntohs(netSettingFrame->connType) >= CONNECT_TYPE_MAX) {
        return NSTACKX_FALSE;
    }
    return NSTACKX_TRUE;
}

static void DecodeSettingFrameDfxPayload(uint16_t payloadLength, SettingFrame *netSettingFrame,
    SettingFrame *hostSettingFrame)
{
    if (payloadLength > (sizeof(hostSettingFrame->mtu) + sizeof(hostSettingFrame->connType) +
        sizeof(hostSettingFrame->dFileVersion) + sizeof(hostSettingFrame->abmCapability) +
        sizeof(hostSettingFrame->capability) + sizeof(hostSettingFrame->dataFrameSize) +
        sizeof(hostSettingFrame->capsCheck))) {
        if (strnlen(netSettingFrame->productVersion, VERSION_STR_LEN) == VERSION_STR_LEN) {
            (void)memset_s(hostSettingFrame->productVersion, VERSION_STR_LEN, 0, VERSION_STR_LEN);
            DFILE_LOGD(TAG, "DFX, remote productVersion is wrong");
        } else {
            DFILE_LOGD(TAG, "DFX, remote productVersion: %s", netSettingFrame->productVersion);
            if (strncpy_s(hostSettingFrame->productVersion, VERSION_STR_LEN,
                netSettingFrame->productVersion, strlen(netSettingFrame->productVersion)) != 0) {
                DFILE_LOGW(TAG, "DFX, Decode strncpy ProductVersion fail");
            }
        }
    }

    if (payloadLength > (sizeof(hostSettingFrame->mtu) + sizeof(hostSettingFrame->connType) +
        sizeof(hostSettingFrame->dFileVersion) + sizeof(hostSettingFrame->abmCapability) +
        sizeof(hostSettingFrame->capability) + sizeof(hostSettingFrame->dataFrameSize) +
        sizeof(hostSettingFrame->capsCheck) + sizeof(hostSettingFrame->productVersion))) {
        hostSettingFrame->isSupport160M = netSettingFrame->isSupport160M;
        DFILE_LOGD(TAG, "DFX, DecodeSettingFrame, isSupport160M:%d", hostSettingFrame->isSupport160M);
    }
}

static void DecodeSettingFrameInner(uint16_t payloadLength, SettingFrame *netSettingFrame,
    SettingFrame *hostSettingFrame)
{
    size_t hostFrameLength = 0;

    hostSettingFrame->dFileVersion = ntohl(netSettingFrame->dFileVersion);
    hostSettingFrame->abmCapability = ntohl(netSettingFrame->abmCapability);
    hostFrameLength += sizeof(hostSettingFrame->mtu) + sizeof(hostSettingFrame->connType) +
                       sizeof(hostSettingFrame->dFileVersion) + sizeof(hostSettingFrame->abmCapability);

    if (payloadLength > hostFrameLength) {
        hostSettingFrame->capability = ntohl(netSettingFrame->capability);
    }
    hostFrameLength += sizeof(hostSettingFrame->capability);

    if (payloadLength > hostFrameLength) {
        hostSettingFrame->dataFrameSize = ntohl(netSettingFrame->dataFrameSize);
    }
    hostFrameLength += sizeof(hostSettingFrame->dataFrameSize);

    if (payloadLength > hostFrameLength) {
        hostSettingFrame->capsCheck = ntohl(netSettingFrame->capsCheck);
    }

    /* DFX */
    DecodeSettingFrameDfxPayload(payloadLength, netSettingFrame, hostSettingFrame);
    hostFrameLength += sizeof(hostSettingFrame->capsCheck) + sizeof(hostSettingFrame->productVersion) +
                       sizeof(hostSettingFrame->isSupport160M);

    if (payloadLength > hostFrameLength) {
        hostSettingFrame->isSupportMtp = netSettingFrame->isSupportMtp;
        hostSettingFrame->mtpPort = netSettingFrame->mtpPort;
    }
    hostFrameLength += sizeof(hostSettingFrame->isSupportMtp) + sizeof(hostSettingFrame->mtpPort);

    if (payloadLength > hostFrameLength) {
        hostSettingFrame->headerEnc = netSettingFrame->headerEnc;
    }
    hostFrameLength += sizeof(hostSettingFrame->headerEnc);

    if (payloadLength > hostFrameLength) {
        hostSettingFrame->mtpCapability = ntohl(netSettingFrame->mtpCapability);
    }
    hostFrameLength += sizeof(hostSettingFrame->mtpCapability);

    if (payloadLength > hostFrameLength) {
        hostSettingFrame->cipherCapability = ntohl(netSettingFrame->cipherCapability);
    }
    hostFrameLength += sizeof(hostSettingFrame->cipherCapability);
}

static int32_t DFileCheckSettingFrame(SettingFrame *netSettingFrame, SettingFrame *hostSettingFrame)
{
    if (netSettingFrame->header.sessionId != 0 || netSettingFrame->header.transId != 0) {
        DFILE_LOGE(TAG, "error transId for Setting Frame");
        return NSTACKX_EFAILED;
    }
    uint16_t payloadLength = ntohs(netSettingFrame->header.length);
    if (!IsSettingFrameLengthValid(hostSettingFrame, payloadLength)) {
        DFILE_LOGE(TAG, "illegal setting frame length %u", payloadLength);
        return NSTACKX_EFAILED;
    }
    if (!IsSettingFrameMtuAndTypeValid(netSettingFrame)) {
        DFILE_LOGE(TAG, "illegal setting frame mtu or type");
        return NSTACKX_EFAILED;
    }
    return NSTACKX_EOK;
}

/*
 * Note: netSettingFrame is a malloced buffer with length reading from network, so it is not reliable and its length
 * may be shorter than sizeof(SettingFrame).
 */
int32_t DecodeSettingFrame(SettingFrame *netSettingFrame, SettingFrame *hostSettingFrame)
{
    if (DFileCheckSettingFrame(netSettingFrame, hostSettingFrame) != NSTACKX_EOK) {
        return NSTACKX_EFAILED;
    }
    uint16_t payloadLength = ntohs(netSettingFrame->header.length);
    hostSettingFrame->header.sessionId = netSettingFrame->header.sessionId;
    hostSettingFrame->mtu = ntohs(netSettingFrame->mtu);
    hostSettingFrame->connType = ntohs(netSettingFrame->connType);

    if (payloadLength == sizeof(hostSettingFrame->mtu) + sizeof(hostSettingFrame->connType)) {
        /*
         * In this condition, this netSettingFrame is from an old version and doesn't have the member dFileVersion.
         * Then the dFileVersion will be set to zero by defulat.
         * Note that the usage of netSettingFrame->dFileVersion is illegal in this condition.
         */
        DFILE_LOGI(TAG, "this setting frame is from an old version whose setting frame doesn't "
                "have the member dFileVersion");
        hostSettingFrame->dFileVersion = 0;
    } else if (payloadLength == sizeof(hostSettingFrame->mtu) + sizeof(hostSettingFrame->connType) +
        sizeof(hostSettingFrame->dFileVersion)) {
        hostSettingFrame->dFileVersion = ntohl(netSettingFrame->dFileVersion);
        hostSettingFrame->abmCapability = 0;
    } else {
        DecodeSettingFrameInner(payloadLength, netSettingFrame, hostSettingFrame);
    }
    DFILE_LOGI(TAG, "local version is %u, remote version is %u capability 0x%x dataFrameSize %u capsCheck 0x%x "
        "cipherCaps 0x%x",
        NSTACKX_DFILE_VERSION, hostSettingFrame->dFileVersion, hostSettingFrame->capability,
        hostSettingFrame->dataFrameSize, hostSettingFrame->capsCheck,
        hostSettingFrame->cipherCapability);
    return NSTACKX_EOK;
}

int32_t DecodeRstFrame(RstFrame *rstFrame, uint16_t *code, uint16_t **fileIdList, uint16_t *listCount)
{
    uint16_t payloadLen = ntohs(rstFrame->header.length);
    if (payloadLen < sizeof(uint16_t) || (payloadLen - sizeof(uint16_t)) % sizeof(uint16_t) != 0) {
        return NSTACKX_EFAILED;
    }
    *code = ntohs(rstFrame->code);

    if (fileIdList != NULL && listCount != NULL) {
        *fileIdList = rstFrame->fileId;
        *listCount = (payloadLen - sizeof(uint16_t)) / sizeof(uint16_t);
    }
    return NSTACKX_EOK;
}

int32_t DecodeBackPressFrame(const BackPressureFrame *backPressFrame, DataBackPressure *backPressInfo)
{
    uint16_t payloadLen = ntohs(backPressFrame->header.length);
    if (payloadLen < sizeof(BackPressureFrame) - sizeof(DFileFrameHeader)) {
        return NSTACKX_EFAILED;
    }

    backPressInfo->recvListOverIo = backPressFrame->backPressure.recvListOverIo;
    backPressInfo->recvBufThreshold = backPressFrame->backPressure.recvBufThreshold;
    backPressInfo->stopSendPeriod = ntohl(backPressFrame->backPressure.stopSendPeriod);

    return NSTACKX_EOK;
}
