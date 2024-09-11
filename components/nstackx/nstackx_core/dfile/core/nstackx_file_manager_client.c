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

#include "nstackx_file_manager_client.h"

#include "securec.h"

#include "nstackx_dev.h"
#include "nstackx_dfile_mp.h"
#include "nstackx_dfile_session.h"
#include "nstackx_error.h"
#include "nstackx_event.h"
#include "nstackx_dfile_log.h"
#ifdef MBEDTLS_INCLUDED
#include "nstackx_mbedtls.h"
#else
#include "nstackx_openssl.h"
#endif
#include "nstackx_util.h"

#define TAG "nStackXDFile"

static void CheckSendListFullAndWait(FileManager *fileManager, sem_t *sem)
{
    int32_t semValue;
    SemGetValue(sem, &semValue);
    if (semValue == 0) {
        fileManager->sendListFullTimes++;
    }
    SemWait(sem);
}

static int32_t ReadFromFile(FileManager *fileManager, FileInfo *fileInfo, uint64_t offset, uint8_t *buffer,
    uint32_t bufferLength)
{
    uint32_t readLength;
    DFileSession *session = fileManager->context;

    offset += fileInfo->startOffset;
    if (fileInfo->tarData != NULL) {
        if (offset + bufferLength > fileInfo->writeOffset ||
            memcpy_s(buffer, bufferLength, fileInfo->tarData + offset, bufferLength) != EOK) {
            DFILE_LOGE(TAG, "memcpy_s failed");
            return NSTACKX_EFAILED;
        }
        fileInfo->fileOffset = offset + bufferLength;
        return NSTACKX_EOK;
    }
    if (fileInfo->fd == NSTACKX_INVALID_FD) {
#ifdef BUILD_FOR_WINDOWS
        fileInfo->fd = fopen(fileInfo->fileName, "rb");
#else
        fileInfo->fd = open(fileInfo->fileName, O_RDONLY);
#endif
        if (fileInfo->fd == NSTACKX_INVALID_FD) {
            fileInfo->errCode = ConvertErrCode(errno);
            DFILE_LOGE(TAG, "file open failed, path %s errno %d", fileInfo->fileName, errno);
            return NSTACKX_EFAILED;
        }
        fileInfo->fileOffset = 0;
    }

    if (SetFileOffset(fileInfo, offset) != NSTACKX_EOK) {
        fileInfo->errCode = FILE_MANAGER_FILE_EOTHER;
        DFILE_LOGE(TAG, "set file offset failed");
        return NSTACKX_EFAILED;
    }

    if (CapsNoRW(session)) {
        readLength = bufferLength;
    } else {
#ifdef BUILD_FOR_WINDOWS
        readLength = (uint32_t)fread(buffer, 1, bufferLength, fileInfo->fd);
#else
        /* use pread because fseek have multi-thread issue in case of multi-path handle same file scenario */
        readLength = (uint32_t)pread(fileInfo->fd, buffer, bufferLength, (int64_t)offset);
#endif
    }

    if (readLength != bufferLength) {
        DFILE_LOGE(TAG, "fread error %d read %u target %hu", GetErrno(), readLength, bufferLength);
        fileInfo->errCode = FILE_MANAGER_FILE_EOTHER;
        return NSTACKX_EFAILED;
    }

    fileInfo->fileOffset += readLength;
    return NSTACKX_EOK;
}

static FileDataFrame *GetEncryptedDataFrame(FileManager *fileManager, CryptPara *cryptPara, FileInfo *fileInfo,
                                            uint32_t targetSequence)
{
    uint8_t *buffer = NULL;
    uint16_t frameOffset, targetLenth;
    FileDataFrame *fileDataFrame = NULL;
    uint64_t fileOffset;
    uint32_t payLoadLen;
    fileOffset = ((uint64_t)fileInfo->standardBlockSize) * ((uint64_t)targetSequence);
    if (targetSequence == fileInfo->totalBlockNum - 1) {
        targetLenth = (uint16_t)(fileInfo->fileSize - fileOffset);
    } else {
        targetLenth = fileInfo->standardBlockSize;
    }
    if (targetLenth == 0) {
        DFILE_LOGE(TAG, "target length is zero");
        fileInfo->errCode = FILE_MANAGER_FILE_EOTHER;
        return NULL;
    }
    buffer = (uint8_t *)calloc(targetLenth, 1);
    if (buffer == NULL) {
        fileInfo->errCode = FILE_MANAGER_ENOMEM;
        return NULL;
    }
    if (ReadFromFile(fileManager, fileInfo, fileOffset, buffer, targetLenth) != NSTACKX_EOK) {
        goto L_END;
    }
    fileManager->iorBytes += (uint64_t)targetLenth;
    payLoadLen = targetLenth + GCM_ADDED_LEN;
    frameOffset = offsetof(FileDataFrame, blockPayload);
    fileDataFrame = (FileDataFrame *)calloc(1, frameOffset + payLoadLen);
    if (fileDataFrame == NULL) {
        fileInfo->errCode = FILE_MANAGER_ENOMEM;
        goto L_END;
    }
    fileDataFrame->header.length = htons(frameOffset + payLoadLen - sizeof(DFileFrameHeader));
    fileDataFrame->fileId = htons(fileInfo->fileId);
    fileDataFrame->blockSequence = htonl(targetSequence);
    if (AesGcmEncrypt(buffer, targetLenth, cryptPara, (uint8_t *)fileDataFrame + frameOffset, payLoadLen) == 0) {
        fileInfo->errCode = FILE_MANAGER_FILE_EOTHER;
        free(fileDataFrame);
        fileDataFrame = NULL;
        DFILE_LOGE(TAG, "data encrypt failed");
    }

L_END:
    free(buffer);
    return fileDataFrame;
}

static FileDataFrame *GetNoEncryptedDataFrame(FileManager *fileManager, FileInfo *fileInfo, uint32_t targetSequence)
{
    uint16_t frameOffset, targetLenth;
    FileDataFrame *fileDataFrame = NULL;
    uint64_t fileOffset;
    uint8_t *buffer = NULL;

    fileOffset = ((uint64_t)fileInfo->standardBlockSize) * ((uint64_t)targetSequence);
    if (targetSequence == fileInfo->totalBlockNum - 1) {
        targetLenth = (uint16_t)(fileInfo->fileSize - fileOffset);
    } else {
        targetLenth = fileInfo->standardBlockSize;
    }
    frameOffset = offsetof(FileDataFrame, blockPayload);
    fileDataFrame = (FileDataFrame *)calloc(1, frameOffset + targetLenth);
    if (fileDataFrame == NULL) {
        fileInfo->errCode = FILE_MANAGER_ENOMEM;
        DFILE_LOGE(TAG, "fileDataFrame calloc failed");
        return NULL;
    }
    buffer = (uint8_t *)fileDataFrame + frameOffset;
    if (ReadFromFile(fileManager, fileInfo, fileOffset, buffer, targetLenth) != NSTACKX_EOK) {
        free(fileDataFrame);
        DFILE_LOGE(TAG, "read file failed");
        return NULL;
    }
    fileManager->iorBytes += (uint64_t)targetLenth;
    fileDataFrame->header.length = htons(frameOffset + targetLenth - sizeof(DFileFrameHeader));
    fileDataFrame->fileId = htons(fileInfo->fileId);
    fileDataFrame->blockSequence = htonl(targetSequence);
    return fileDataFrame;
}

int32_t GetEncryptedDataTarFrame(CryptPara *cryptPara, uint16_t fileId, FileListTask *fileList, uint16_t targetLenth)
{
    uint16_t frameOffset;
    FileDataFrame *fileDataFrame = NULL;
    uint32_t payLoadLen;
    int32_t errCode = FILE_MANAGER_EOK;
    uint32_t targetSequence = (uint32_t)(fileList->tarFileInfo.maxSequenceSend);
    FileDataFrame *buffer = fileList->tarFrame;

    frameOffset = offsetof(FileDataFrame, blockPayload);
    payLoadLen = targetLenth + GCM_ADDED_LEN;
    fileDataFrame = (FileDataFrame *)calloc(1, frameOffset + payLoadLen);
    if (fileDataFrame == NULL) {
        errCode = FILE_MANAGER_ENOMEM;
        return errCode;
    }
    fileDataFrame->header.length = htons(frameOffset + payLoadLen - sizeof(DFileFrameHeader));
    fileDataFrame->fileId = htons(fileId);
    fileDataFrame->blockSequence = htonl(targetSequence);
    if (AesGcmEncrypt(buffer->blockPayload, targetLenth, cryptPara, fileDataFrame->blockPayload, payLoadLen) == 0) {
        DFILE_LOGE(TAG, "AesGcmEncrypt failed, %d-%d", targetLenth, payLoadLen);
        errCode = FILE_MANAGER_FILE_EOTHER;
    }

    if (memcpy_s(buffer, fileList->maxFrameLength, fileDataFrame, frameOffset + payLoadLen) != EOK) {
        DFILE_LOGE(TAG, "memcpy error");
        errCode = FILE_MANAGER_FILE_EOTHER;
    }
    free(fileDataFrame);

    return errCode;
}

int32_t GetNoEncryptedDataTarFrame(uint16_t fileId, FileListTask *fileList, uint16_t targetLenth)
{
    FileDataFrame *fileDataFrame = fileList->tarFrame;
    if (fileDataFrame == NULL) {
        return FILE_MANAGER_ENOMEM;
    }

    fileDataFrame->header.length = htons(targetLenth + sizeof(FileDataFrame) - sizeof(DFileFrameHeader));
    fileDataFrame->fileId = htons(fileId);
    fileDataFrame->blockSequence = htonl((uint32_t)fileList->tarFileInfo.maxSequenceSend);
    return FILE_MANAGER_EOK;
}

static int32_t GetRetranBlockInfo(FileListTask *fileList, uint16_t *fileId, uint32_t *blockSeq, uint32_t *linkSeq)
{
    List *curFront = NULL;
    uint8_t isPoped;
    SendRetranRequestNode *retranNode = NULL;
    if (MutexListPopFront(&fileList->sendRetranList, &curFront, &isPoped) != NSTACKX_EOK) {
        if (isPoped) {
            retranNode = (SendRetranRequestNode *)curFront;
            free(retranNode);
        }
        DFILE_LOGE(TAG, "Pop sendRetranList's head error");
        fileList->errCode = FILE_MANAGER_EMUTEX;
        return NSTACKX_EFAILED;
    }
    retranNode = (SendRetranRequestNode *)curFront;
    *fileId = retranNode->fileId;
    *blockSeq = retranNode->blockSequence;
    *linkSeq = retranNode->linkSequence;
    free(retranNode);
    if (*fileId == 0 || *fileId > fileList->fileNum) {
        DFILE_LOGE(TAG, "The file ID %u is illegal: totalBlockNum %u", *fileId, fileList->fileNum);
        return NSTACKX_EFAILED;
    }
    return NSTACKX_EOK;
}

FileDataFrame *CreateRetranBlockFrame(FileManager *fileManager, FileListTask *fileList)
{
    FileInfo *fileInfo = NULL;
    uint16_t fileId;
    uint32_t blockSequence, linkSequence;
    FileDataFrame *fileDataFrame = NULL;

    if (GetRetranBlockInfo(fileList, &fileId, &blockSequence, &linkSequence) != NSTACKX_EOK) {
        return NULL;
    }

    if (fileList->tarFlag != NSTACKX_TRUE) {
        fileInfo = &fileList->fileInfo[fileId - 1];
    } else {
        fileInfo = &fileList->tarFileInfo;
    }
    if (blockSequence >= fileInfo->totalBlockNum) {
        DFILE_LOGE(TAG, "The retryBlock %u is larger than totalBlockNum %u", blockSequence, fileInfo->totalBlockNum);
        return NULL;
    }
    if (fileInfo->errCode != FILE_MANAGER_EOK) {
        DFILE_LOGE(TAG, "The processing file is error transId: %u fileId: %u", fileList->transId, fileInfo->fileId);
        return NULL;
    }

    if (fileList->cryptPara.keylen > 0) {
        fileDataFrame = GetEncryptedDataFrame(fileManager, &fileList->cryptPara, fileInfo, blockSequence);
    } else {
        fileDataFrame = GetNoEncryptedDataFrame(fileManager, fileInfo, blockSequence);
    }

    if (fileDataFrame == NULL) {
        CloseFile(fileInfo);
        NotifyFileMsg(fileList, fileInfo->fileId, FILE_MANAGER_SEND_FAIL);
        return NULL;
    }
    fileList->hasUnInsetFrame = NSTACKX_TRUE;
    fileDataFrame->header.flag |= NSTACKX_DFILE_DATA_FRAME_RETRAN_FLAG;
    if (blockSequence == fileInfo->totalBlockNum - 1) {
        fileDataFrame->header.flag |= NSTACKX_DFILE_DATA_FRAME_END_FLAG;
    }
    fileDataFrame->header.transId = htons(fileList->transId);
    fileDataFrame->header.type = NSTACKX_DFILE_FILE_DATA_FRAME;

    /* The files with smaller file id should be closed to match the limit of the number. */
    if (MAX_SEND_FILE_OPENED_PER_LIST <= 1 ||
        (!fileList->tarFlag && fileList->sendFileProcessed >= MAX_SEND_FILE_OPENED_PER_LIST + fileInfo->fileId - 1)) {
        CloseFile(fileInfo);
    }
    return fileDataFrame;
}

static FileInfo *GetTarFileInfo(FileListTask *fileList)
{
    (void)fileList;
    return NULL;
}

static FileInfo *GetFileInfo(FileListTask *fileList)
{
    uint16_t fileId;
    uint32_t blockSequence;
    FileInfo *fileInfo = NULL;
    if (fileList->tarFlag == NSTACKX_TRUE) {
        return GetTarFileInfo(fileList);
    }
    if (fileList->newReadOutSet.fileId > 0) {
        if (PthreadMutexLock(&fileList->newReadOutSet.lock) != 0) {
            DFILE_LOGE(TAG, "pthread mutex lock error");
            fileList->errCode = FILE_MANAGER_EMUTEX;
            return NULL;
        }
        fileId = fileList->newReadOutSet.fileId;
        blockSequence = fileList->newReadOutSet.blockSequence;
        fileList->newReadOutSet.fileId = 0;
        fileList->newReadOutSet.blockSequence = 0;
        if (PthreadMutexUnlock(&fileList->newReadOutSet.lock) != 0) {
            DFILE_LOGE(TAG, "pthread mutex unlock error");
            fileList->errCode = FILE_MANAGER_EMUTEX;
            return NULL;
        }
        if (fileId > 0 && fileId <= fileList->fileNum && blockSequence < fileList->fileInfo[fileId - 1].totalBlockNum) {
            fileList->sendFileProcessed = (uint16_t)(fileId - 1);
            fileList->fileInfo[fileId - 1].maxSequenceSend = (int64_t)blockSequence - 1;
            for (uint16_t i = fileId + 1; i <= fileList->fileNum; i++) {
                fileList->fileInfo[i - 1].maxSequenceSend = -1;
                /* Close all files with larger fileId than new outset. */
                CloseFile(&fileList->fileInfo[i - 1]);
            }
            /* new outset has been set and bytesTransferred of fileList should be reset */
            fileList->bytesTransferred = FileListGetBytesTransferred(fileList, NSTACKX_TRUE);
        }
    }
    if (fileList->sendFileProcessed >= fileList->fileNum) {
        return NULL;
    }

    fileInfo = &fileList->fileInfo[fileList->sendFileProcessed];
    if (fileInfo->errCode != FILE_MANAGER_EOK || fileInfo->fileSize == 0) {
        fileList->sendFileProcessed++;
        /* error ouccred and bytesTransferred of fileList should be reset */
        fileList->bytesTransferred = FileListGetBytesTransferred(fileList, NSTACKX_TRUE);
        return NULL;
    }
    return fileInfo;
}

static void UpdateFileLisSendStatus(FileListTask *fileList, FileInfo *fileInfo, uint8_t *isEnd)
{
    if (fileList->bytesTransferred >=
        fileList->bytesTransferredLastRecord + NSTACKX_KILO_BYTES * KILO_BYTES_TRANSFER_NOTICE_THRESHOLD) {
        fileList->bytesTransferredLastRecord = fileList->bytesTransferred;
        NotifyFileListMsg(fileList, FILE_MANAGER_TRANS_IN_PROGRESS);
    }
    if (fileInfo->maxSequenceSend == (int32_t)(fileInfo->totalBlockNum - 1)) {
        /* The files with smaller file id should be closed to match the limit of the number of opened files */
        if (fileInfo->fileId >= MAX_SEND_FILE_OPENED_PER_LIST) {
            CloseFile(&fileList->fileInfo[fileInfo->fileId - MAX_SEND_FILE_OPENED_PER_LIST]);
            if (!fileList->tarFlag) {
                /* error ouccred and bytesTransferred of fileList should be reset */
                fileList->bytesTransferred = FileListGetBytesTransferred(fileList, NSTACKX_TRUE);
            }
        }

        fileList->sendFileProcessed++;
        *isEnd = NSTACKX_TRUE;
    }
}

void UpdateTarFileListSendStatus(FileListTask *fileList)
{
    uint64_t bytesTransFerred;
    bytesTransFerred = FileListGetBytesTransferred(fileList, NSTACKX_TRUE);
    if (bytesTransFerred >=
        fileList->bytesTransferredLastRecord + NSTACKX_KILO_BYTES * KILO_BYTES_TRANSFER_NOTICE_THRESHOLD) {
        fileList->bytesTransferredLastRecord = bytesTransFerred;
        NotifyFileListMsg(fileList, FILE_MANAGER_TRANS_IN_PROGRESS);
    }
    if (fileList->tarFileInfo.maxSequenceSend == (int32_t)(fileList->tarFileInfo.totalBlockNum - 1)) {
        fileList->sendFileProcessed = fileList->fileNum;
        if (MAX_SEND_FILE_OPENED_PER_LIST <= 1) { // Macro maybe changed
            FileInfo *fileInfo = GetFileInfo(fileList);
            if (fileInfo != NULL) {
                CloseFile(fileInfo);
            }
        }
    }
}

static FileDataFrame *CreateSendBlockFrame(FileManager *fileManager, FileListTask *fileList)
{
    FileInfo *fileInfo = NULL;
    uint8_t isStartFrame = NSTACKX_FALSE;
    uint8_t isEndFrame = NSTACKX_FALSE;
    FileDataFrame *fileDataFrame = NULL;
    fileInfo = GetFileInfo(fileList);
    if (fileInfo == NULL) {
        return NULL;
    }
    if (fileInfo->maxSequenceSend == -1) {
        isStartFrame = NSTACKX_TRUE;
    }
    if (fileList->cryptPara.keylen > 0) {
        fileDataFrame = GetEncryptedDataFrame(fileManager, &fileList->cryptPara, fileInfo,
                                              (uint32_t)(fileInfo->maxSequenceSend + 1));
    } else {
        fileDataFrame = GetNoEncryptedDataFrame(fileManager, fileInfo, (uint32_t)(fileInfo->maxSequenceSend + 1));
    }
    if (fileDataFrame == NULL) {
        DFILE_LOGE(TAG, "Can't get data from file");
        fileList->sendFileProcessed++;
        CloseFile(fileInfo);
        NotifyFileMsg(fileList, fileInfo->fileId, FILE_MANAGER_SEND_FAIL);
        return NULL;
    }
    fileList->hasUnInsetFrame = NSTACKX_TRUE;
    fileInfo->maxSequenceSend++;
    if (fileList->tarFlag != NSTACKX_TRUE) {
        fileList->bytesTransferred += fileInfo->standardBlockSize;
        UpdateFileLisSendStatus(fileList, fileInfo, &isEndFrame);
    } else {
        UpdateTarFileListSendStatus(fileList);
    }
    fileDataFrame->header.transId = htons(fileList->transId);
    fileDataFrame->header.type = NSTACKX_DFILE_FILE_DATA_FRAME;
    if (isEndFrame) {
        fileDataFrame->header.flag |= NSTACKX_DFILE_DATA_FRAME_END_FLAG;
    } else if (isStartFrame) {
        fileDataFrame->header.flag |= NSTACKX_DFILE_DATA_FRAME_START_FLAG;
    } else {
        fileDataFrame->header.flag |= NSTACKX_DFILE_DATA_FRAME_CONTINUE_FLAG;
    }
    return fileDataFrame;
}

static int32_t PushFileBlockFrame(FileManager *fileManager, const FileListTask *fileList,
                                  const FileDataFrame *fileDataFrame,
                                  uint8_t isRetran, uint8_t *isAdded)
{
    BlockFrame *blockFrame = NULL;
    SendBlockFrameListPara *para = &fileManager->sendBlockFrameListPara[fileList->bindedSendBlockListIdx];
    *isAdded = NSTACKX_FALSE;
    blockFrame = (BlockFrame *)calloc(1, sizeof(BlockFrame));
    if (blockFrame == NULL) {
        DFILE_LOGE(TAG, "calloc error");
        fileManager->errCode = FILE_MANAGER_ENOMEM;
        NotifyFileManagerMsg(fileManager, FILE_MANAGER_INNER_ERROR);
        return NSTACKX_EFAILED;
    }
    blockFrame->sendLen = 0;
    blockFrame->fileDataFrame = (FileDataFrame *)fileDataFrame;
    blockFrame->socketIndex = fileList->socketIndex;

    if (PthreadMutexLock(&para->sendBlockFrameList.lock) != 0) {
        free(blockFrame);
        DFILE_LOGE(TAG, "pthread mutex lock error");
        fileManager->errCode = FILE_MANAGER_EMUTEX;
        goto L_ERR_FILE_MANAGER;
    }
    if (isRetran) {
        ListInsertHead(para->sendRetranListTail, &blockFrame->list);
        para->sendRetranListTail = &blockFrame->list;
    } else {
        ListInsertTail(&para->sendBlockFrameList.head, &blockFrame->list);
    }
    *isAdded = NSTACKX_TRUE;
    para->sendBlockFrameList.size++;
    if (PthreadMutexUnlock(&para->sendBlockFrameList.lock) != 0) {
        DFILE_LOGE(TAG, "pthread mutex unlock error");
        fileManager->errCode = FILE_MANAGER_EMUTEX;
        goto L_ERR_FILE_MANAGER;
    }
    return NSTACKX_EOK;
L_ERR_FILE_MANAGER:
    NotifyFileManagerMsg(fileManager, FILE_MANAGER_INNER_ERROR);
    return NSTACKX_EFAILED;
}

void ClearSendFileList(FileManager *fileManager, FileListTask *fileList)
{
    SendRetranRequestNode *retranNode = NULL;
    for (uint32_t i = 0; i < fileList->fileNum; i++) {
        CloseFile(&fileList->fileInfo[i]);
        free(fileList->fileInfo[i].fileName);
        fileList->fileInfo[i].fileName = NULL;
    }
    if (fileList->tarFlag) {
        CloseFile(&fileList->tarFileInfo);
    }
    free(fileList->tarFileInfo.fileName);
    fileList->tarFileInfo.fileName = NULL;
    if (fileList->tarFileInfo.tarData != NULL) {
        free(fileList->tarFileInfo.tarData);
        fileList->tarFileInfo.tarData = NULL;
        NSTACKX_ATOM_FETCH_SUB(&fileManager->totalPackInMemory, fileList->tarFileInfo.fileSize);
    }
    SemDestroy(&fileList->semStop);
    if (PthreadMutexLock(&fileList->sendRetranList.lock) != 0) {
        DFILE_LOGE(TAG, "pthread mutex lock error");
    }
    while (fileList->sendRetranList.size > 0) {
        retranNode = (SendRetranRequestNode *)ListPopFront(&fileList->sendRetranList.head);
        fileList->sendRetranList.size--;
        free(retranNode);
        retranNode = NULL;
    }
    if (PthreadMutexUnlock(&fileList->sendRetranList.lock) != 0) {
        DFILE_LOGE(TAG, "pthread mutex unlock error");
    }
    MutexListDestory(&fileList->sendRetranList);
    ClearCryptCtx(fileList->cryptPara.ctx);
    PthreadMutexDestroy(&fileList->newReadOutSet.lock);
    (void)memset_s(fileList, sizeof(FileListTask), 0, sizeof(FileListTask));
    free(fileList);
}

uint8_t PushRetranBlockFrame(FileManager *fileManager, const FileListTask *fileList, const FileDataFrame *fileDataFrame)
{
    uint8_t ret = NSTACKX_FALSE;
    SendBlockFrameListPara *para = &fileManager->sendBlockFrameListPara[fileList->bindedSendBlockListIdx];
    if (fileDataFrame == NULL) {
        DFILE_LOGE(TAG, "frame is NULL");
        return ret;
    }
    CheckSendListFullAndWait(fileManager, &para->semBlockListNotFull);
    if (CheckManager(fileManager) != NSTACKX_EOK) {
        return ret;
    }
    if (PushFileBlockFrame(fileManager, fileList, fileDataFrame, NSTACKX_TRUE, &ret) != NSTACKX_EOK) {
        DFILE_LOGE(TAG, "push retran block error");
    }
    return ret;
}

uint8_t PushSendBlockFrame(FileManager *fileManager, const FileListTask *fileList, const FileDataFrame *fileDataFrame)
{
    uint8_t isAdded = NSTACKX_FALSE;

    SendBlockFrameListPara *para = &fileManager->sendBlockFrameListPara[fileList->bindedSendBlockListIdx];
    if (fileDataFrame == NULL) {
        return NSTACKX_FALSE;
    }

    CheckSendListFullAndWait(fileManager, &para->semBlockListNotFull);
    if (CheckManager(fileManager) != NSTACKX_EOK) {
        return NSTACKX_FALSE;
    }
    if (PushFileBlockFrame(fileManager, fileList, fileDataFrame, NSTACKX_FALSE, &isAdded) != NSTACKX_EOK) {
        return NSTACKX_FALSE;
    }

    return isAdded;
}

static uint8_t CreateSendBlockTarFrames(FileManager *fileManager, FileListTask *fileList)
{
    (void)fileManager;
    (void)fileList;
    return NSTACKX_FALSE;
}

void SendTaskProcess(FileManager *fileManager, FileListTask *fileList)
{
    FileDataFrame *fileDataFrame = NULL;
    uint8_t isAdded;
    uint8_t isEmpty;
    SendBlockFrameListPara *para = &fileManager->sendBlockFrameListPara[fileList->bindedSendBlockListIdx];
    while (NSTACKX_TRUE) {
        if (CheckFilelist(fileList) != NSTACKX_EOK || CheckManager(fileManager) != NSTACKX_EOK) {
            break;
        }
        isEmpty = NSTACKX_FALSE;
        if (fileList->sendRetranList.size == 0) {
            isEmpty = NSTACKX_TRUE;
        }
        if (isEmpty != NSTACKX_TRUE) {
            fileDataFrame = CreateRetranBlockFrame(fileManager, fileList);
            isAdded = PushRetranBlockFrame(fileManager, fileList, fileDataFrame);
        } else if (fileList->sendFileProcessed >= fileList->fileNum && fileList->newReadOutSet.fileId == 0) {
            SemWait(&fileList->semStop);
            continue;
        } else {
            if ((fileList->tarFlag == NSTACKX_TRUE) && (fileList->tarFinished != NSTACKX_TRUE)) {
                isAdded = CreateSendBlockTarFrames(fileManager, fileList);
            } else {
                fileDataFrame = CreateSendBlockFrame(fileManager, fileList);
                isAdded = PushSendBlockFrame(fileManager, fileList, fileDataFrame);
            }
        }
        if (fileDataFrame != NULL) {
            if (isAdded != NSTACKX_TRUE) {
                free(fileDataFrame);
                SemPost(&para->semBlockListNotFull);
            }
            fileList->hasUnInsetFrame = NSTACKX_FALSE;
        }
    }

    if (fileList->errCode != FILE_MANAGER_EOK) {
        DFILE_LOGE(TAG, "send task process failed %d", fileList->errCode);
        NotifyFileListMsg(fileList, FILE_MANAGER_SEND_FAIL);
    }
}

uint64_t PackGetTarBlockLen(const FileListTask *fmFileList)
{
    char pathSeparator = '/';
    uint64_t tarFilesTotalLen = 0;
    uint64_t blockCnt;
    uint32_t i;
    char *path = NULL;

    for (i = 0; i < fmFileList->fileNum; i++) {
        tarFilesTotalLen += BLOCK_LEN;

        path = fmFileList->fileInfo[i].fileName;
        if (strlen(path) > MAX_NAME_LEN) {
            // +1 because of the string end '\0'
            tarFilesTotalLen += BLOCK_LEN +
                (((strlen(path) + 1 - (long long)(path[0] == pathSeparator) + BLOCK_LEN - 1) / BLOCK_LEN) * BLOCK_LEN);
        }

        // file body length
        blockCnt = (fmFileList->fileInfo[i].fileSize + BLOCK_LEN - 1) / BLOCK_LEN;
        tarFilesTotalLen += (blockCnt * BLOCK_LEN);
    }

    // file tail paddings length
    tarFilesTotalLen += BLOCK_LEN;

    return tarFilesTotalLen;
}

static int32_t AddTarFileInfo(const char *tarFileName, FileListTask *fmFileList, uint16_t standardBlockSize)
{
    uint64_t tarFilesTotalLen;
    tarFilesTotalLen = PackGetTarBlockLen(fmFileList);
    fmFileList->blockOffset = 0;
    fmFileList->tarFrame = NULL;
    fmFileList->tarFileInfo.fd = NSTACKX_INVALID_FD;
    fmFileList->tarFileInfo.fileSize = tarFilesTotalLen;
    fmFileList->tarFileInfo.standardBlockSize = standardBlockSize;
    fmFileList->tarFileInfo.totalBlockNum = (uint32_t)((tarFilesTotalLen + standardBlockSize - 1) / standardBlockSize);
    fmFileList->tarFileInfo.fileId = 1;
    fmFileList->tarFileInfo.maxSequenceSend = -1;
    fmFileList->tarFileInfo.tarData = NULL;
    fmFileList->tarFileInfo.writeOffset = 0;
    DFILE_LOGI(TAG, "tarLen: %llu, blockNum: %u, endLen: %llu", tarFilesTotalLen,
         fmFileList->tarFileInfo.totalBlockNum, tarFilesTotalLen % standardBlockSize);
    fmFileList->tarFileInfo.fileName = realpath(tarFileName, NULL);
    if ((fmFileList->tarFileInfo.fileName == NULL) ||
        (!IsAccessiblePath(fmFileList->tarFileInfo.fileName, R_OK, S_IFREG))) {
        return NSTACKX_EFAILED;
    }
    fmFileList->tarFd = NULL;
    fmFileList->totalBytes = fmFileList->tarFileInfo.fileSize;
    return NSTACKX_EOK;
}

static int32_t AddSendFileInfo(const SendFileListInfo *fileListInfo,
                               FileListTask *fmFileList, uint16_t standardBlockSize)
{
    uint16_t i;
    FileInfo *fileInfo = NULL;
    for (i = 0; i < fmFileList->fileNum; i++) {
        if (fileListInfo->fileList[i] == NULL) {
            goto L_ERR_FILE_MANAGER;
        }
        fileInfo = &fmFileList->fileInfo[i];
        fileInfo->fileName = realpath(fileListInfo->fileList[i], NULL);
        if (fileInfo->fileName == NULL || !IsAccessiblePath(fileInfo->fileName, R_OK, S_IFREG)) {
            DFILE_LOGE(TAG, "can't get canonicalized absolute pathname, error(%d)", errno);
            goto L_ERR_FILE_MANAGER;
        }
        fileInfo->fileSize = fileListInfo->fileSize[i];
        fileInfo->standardBlockSize = standardBlockSize;
        fileInfo->totalBlockNum = (uint32_t)(fileInfo->fileSize / standardBlockSize);
        if (fileInfo->fileSize % standardBlockSize != 0) {
            fileInfo->totalBlockNum++;
        }
        fmFileList->totalBytes += fileInfo->fileSize;
        fileInfo->fileId = i + 1;
        fileInfo->startOffset = fileListInfo->startOffset[i];
        fileInfo->maxSequenceSend = -1;
        fileInfo->fd = NSTACKX_INVALID_FD;
        fileInfo->errCode = FILE_MANAGER_EOK;
        fileInfo->fileOffset = 0;
        fileInfo->tarData = NULL;
        fileInfo->writeOffset = 0;
    }

    if (fmFileList->tarFlag &&
        AddTarFileInfo(fileListInfo->fileList[fmFileList->fileNum], fmFileList, standardBlockSize) != NSTACKX_EOK) {
        goto L_ERR_FILE_MANAGER;
    }

    return NSTACKX_EOK;
L_ERR_FILE_MANAGER:
    for (i = 0; i < fmFileList->fileNum; i++) {
        free(fmFileList->fileInfo[i].fileName);
        fmFileList->fileInfo[i].fileName = NULL;
    }
    return NSTACKX_EFAILED;
}

static int32_t InitSendFilesOutSet(FileListTask *fmFileList)
{
    if (PthreadMutexInit(&fmFileList->newReadOutSet.lock, NULL) != 0) {
        DFILE_LOGE(TAG, "PthreadMutexInit error");
        return NSTACKX_EFAILED;
    }
    fmFileList->newReadOutSet.fileId = 0;
    fmFileList->newReadOutSet.blockSequence = 0;
    return NSTACKX_EOK;
}

static FileListTask *CreateSendFileList(const SendFileListInfo *fileListInfo,
                                        uint16_t standardBlockSize, const FileListMsgPara *msgPara)
{
    FileListTask *fmFileList = NULL;
    fmFileList = (FileListTask *)calloc(1, sizeof(FileListTask));
    if (fmFileList == NULL) {
        DFILE_LOGE(TAG, "file list calloc error");
        return NULL;
    }
    fmFileList->transId = fileListInfo->transId;
    fmFileList->fileNum = fileListInfo->fileNum;
    fmFileList->tarFlag = fileListInfo->tarFlag;
    fmFileList->smallFlag = fileListInfo->smallFlag;
    if (SemInit(&fmFileList->semStop, 0, 0) != 0) {
        DFILE_LOGE(TAG, "SemInit error");
        goto L_ERR_FILE_MANAGER;
    }
    fmFileList->runStatus = FILE_LIST_STATUS_IDLE;
    fmFileList->stopType = FILE_LIST_TRANSFER_FINISH;
    fmFileList->isOccupied = NSTACKX_FALSE;
    fmFileList->errCode = FILE_MANAGER_EOK;
    fmFileList->sendFileProcessed = 0;

    if (MutexListInit(&fmFileList->sendRetranList, NSTACKX_MAX_RETRAN_BLOCK_NUM) != NSTACKX_EOK) {
        DFILE_LOGE(TAG, "sendRetranList init error");
        SemDestroy(&fmFileList->semStop);
        goto L_ERR_FILE_MANAGER;
    }

    if (InitSendFilesOutSet(fmFileList) != NSTACKX_EOK) {
        SemDestroy(&fmFileList->semStop);
        MutexListDestory(&fmFileList->sendRetranList);
        DFILE_LOGE(TAG, "InitRetranFilesInfo error");
        goto L_ERR_FILE_MANAGER;
    }

    if (AddSendFileInfo(fileListInfo, fmFileList, standardBlockSize) != NSTACKX_EOK) {
        DFILE_LOGE(TAG, "AddSendFileInfo init error");
        SemDestroy(&fmFileList->semStop);
        MutexListDestory(&fmFileList->sendRetranList);
        PthreadMutexDestroy(&fmFileList->newReadOutSet.lock);
        goto L_ERR_FILE_MANAGER;
    }

    if (msgPara != NULL) {
        fmFileList->msgReceiver = msgPara->msgReceiver;
        fmFileList->context = msgPara->context;
    }
    return fmFileList;
L_ERR_FILE_MANAGER:
    (void)memset_s(fmFileList, sizeof(FileListTask), 0, sizeof(FileListTask));
    free(fmFileList);
    return NULL;
}

static uint32_t GetTargetSendBlockListIdx(const FileManager *fileManager)
{
    uint32_t ret = 0;
    uint32_t bindingNum = NSTACKX_MAX_PROCESSING_TASK_NUM;

    for (uint32_t i = 0; i < fileManager->sendFrameListNum; i++) {
        if (fileManager->sendBlockFrameListPara[i].bandingTransNum < bindingNum) {
            bindingNum = fileManager->sendBlockFrameListPara[i].bandingTransNum;
            ret = i;
        }
    }
    return ret;
}

int32_t FileManagerSendFileTask(FileManager *fileManager, const SendFileListInfo *fileListInfo,
                                const FileListMsgPara *msgPara)
{
    FileListTask *fmFileList = NULL;
    uint16_t standardBlockSize;
    if (CheckSenderManager(fileManager) != NSTACKX_EOK || fileListInfo == NULL ||
        fileListInfo->fileNum == 0 || fileListInfo->fileNum > NSTACKX_DFILE_MAX_FILE_NUM) {
        DFILE_LOGE(TAG, "Invalid input");
        return NSTACKX_EINVAL;
    }
    if (fileManager->taskList.size >= fileManager->taskList.maxSize) {
        DFILE_LOGE(TAG, "task list is full");
        return NSTACKX_EFAILED;
    }
    standardBlockSize = GetStandardBlockSize(fileManager);
    if (standardBlockSize == 0) {
        DFILE_LOGE(TAG, "max frame length is too small");
        return NSTACKX_EFAILED;
    }

    fmFileList = CreateSendFileList(fileListInfo, standardBlockSize, msgPara);
    if (fmFileList == NULL) {
        DFILE_LOGE(TAG, "Can't creat fmFileList");
        return NSTACKX_EFAILED;
    }
    fmFileList->maxFrameLength = fileManager->maxFrameLength;
    fmFileList->epollfd = fileManager->epollfd;
    fmFileList->eventNodeChain = fileManager->eventNodeChain;
    if (fileManager->keyLen > 0 && SetCryptPara(fmFileList, fileManager->key, fileManager->keyLen) != NSTACKX_EOK) {
        ClearSendFileList(fileManager, fmFileList);
        return NSTACKX_EFAILED;
    }
    PeerInfo *peerinfo = ClientGetPeerInfoByTransId((DFileSession *)fileManager->context);
    if (!peerinfo) {
        ClearSendFileList(fileManager, fmFileList);
        return NSTACKX_EFAILED;
    }
    fmFileList->socketIndex = peerinfo->socketIndex;
    fmFileList->bindedSendBlockListIdx = GetTargetSendBlockListIdx(fileManager);
    if (MutexListAddNode(&fileManager->taskList, &fmFileList->list, NSTACKX_FALSE) != NSTACKX_EOK) {
        DFILE_LOGE(TAG, "Add task to list error");
        ClearSendFileList(fileManager, fmFileList);
        fileManager->errCode = FILE_MANAGER_EMUTEX;
        NotifyFileManagerMsg(fileManager, FILE_MANAGER_INNER_ERROR);
        return NSTACKX_EFAILED;
    }
    fileManager->totalBytes += fmFileList->totalBytes;
    fileManager->sendBlockFrameListPara[fmFileList->bindedSendBlockListIdx].bandingTransNum++;
    SemPost(&fileManager->semTaskListNotEmpty);
    return NSTACKX_EOK;
}

static int32_t GetRetranFileLostBlocks(const FileListTask *fileList, uint16_t fileId, uint32_t blockSequence)
{
    uint32_t ret = 0;

    if (fileList->tarFlag && fileList->tarFinished) {
        return (int32_t)(fileList->tarFileInfo.totalBlockNum - blockSequence);
    }

    for (uint16_t i = fileId; i <= fileList->sendFileProcessed + 1 && i <= fileList->fileNum; i++) {
        ret += (uint32_t)(fileList->fileInfo[i - 1].maxSequenceSend + 1);
    }

    if (ret >= blockSequence) {
        ret -= blockSequence;
    } else {
        ret = 0;
    }

    if (ret > INT32_MAX) {
        ret = INT32_MAX;
    }
    return (int32_t)ret;
}

static uint8_t IsValidOutSet(const FileListTask *fileList, uint16_t fileId, uint32_t blockSequence)
{
    uint32_t totalBlockNum;
    uint16_t fileNum;
    fileNum = (fileList->tarFlag == NSTACKX_TRUE) ? 1 : fileList->fileNum;
    if (fileId == 0 || fileId > fileNum) {
        DFILE_LOGE(TAG, "new outset fileId is illegal");
        return NSTACKX_FALSE;
    }

    totalBlockNum = (fileList->tarFlag == NSTACKX_TRUE) ?
                     fileList->tarFileInfo.totalBlockNum : fileList->fileInfo[fileId - 1].totalBlockNum;
    if (blockSequence >= totalBlockNum) {
        DFILE_LOGE(TAG, "new outset blockSequence is illegal");
        return NSTACKX_FALSE;
    }
    return NSTACKX_TRUE;
}

int32_t FileManagerResetSendOutSet(FileManager *fileManager, uint16_t fileId, uint32_t blockSequence, uint16_t transId)
{
    FileListTask *fileList = NULL;
    uint8_t isErrorOccurred;
    int32_t ret;

    if (CheckSenderManager(fileManager) != NSTACKX_EOK ||
        fileManager->maxFrameLength <= offsetof(FileDataFrame, blockPayload)) {
        DFILE_LOGE(TAG, "Invalid input");
        return NSTACKX_EINVAL;
    }
    fileList = GetFileListById(&fileManager->taskList, transId, &isErrorOccurred);
    if (isErrorOccurred) {
        DFILE_LOGE(TAG, "get target file list error");
        goto L_ERR_FILE_MANAGER;
    }

    if (CheckFilelistNotStop(fileList) != NSTACKX_EOK) {
        DFILE_LOGE(TAG, "target file list is not available");
        return NSTACKX_EFAILED;
    }

    if (!IsValidOutSet(fileList, fileId, blockSequence)) {
        return NSTACKX_EFAILED;
    }

    ret = GetRetranFileLostBlocks(fileList, fileId, blockSequence);
    if (fileList->tarFlag && fileList->tarFinished != NSTACKX_TRUE) {
        return ret;
    }
    if (PthreadMutexLock(&fileList->newReadOutSet.lock) != 0) {
        DFILE_LOGE(TAG, "pthread mutex lock error");
        goto L_ERR_FILE_MANAGER;
    }
    fileList->newReadOutSet.blockSequence = blockSequence;
    fileList->newReadOutSet.fileId = fileId;

    if (PthreadMutexUnlock(&fileList->newReadOutSet.lock) != 0) {
        DFILE_LOGE(TAG, "pthread mutex unlock error");
        goto L_ERR_FILE_MANAGER;
    }
    SemPost(&fileList->semStop);
    return ret;

L_ERR_FILE_MANAGER:
    NotifyFileManagerMsg(fileManager, FILE_MANAGER_INNER_ERROR);
    if (fileList != NULL) {
        NotifyFileListMsg(fileList, FILE_MANAGER_SEND_FAIL);
    }
    return NSTACKX_EFAILED;
}

static SendBlockFrameListPara *GetSendBlockFrameListPara(FileManager *fileManager, uint32_t tid)
{
    SendBlockFrameListPara *para = NULL;

    if (tid < fileManager->sendFrameListNum) {
        para = &fileManager->sendBlockFrameListPara[tid];
        if (!ListIsEmpty(&para->sendBlockFrameList.head)) {
            return para;
        }
    }

    for (uint32_t i = 0; i < fileManager->sendFrameListNum; i++) {
        para = &fileManager->sendBlockFrameListPara[i];
        if (!ListIsEmpty(&para->sendBlockFrameList.head)) {
            return para;
        }
    }
    return NULL;
}

static int32_t GetMultipleBlockFrame(SendBlockFrameListPara *para, BlockFrame **block, int32_t nr)
{
    BlockFrame *frame = NULL;
    List *cur = NULL;
    int32_t cnt;

    for (cnt = 0; cnt < nr; ++cnt) {
        cur = ListPopFront(&para->sendBlockFrameList.head);
        if (cur == NULL) {
            break;
        }
        para->sendBlockFrameList.size--;
        if (para->sendRetranListTail == cur) {
            para->sendRetranListTail = &para->sendBlockFrameList.head;
        }
        if (frame != NULL) {
            frame->list.next = cur;
            frame = (BlockFrame *)(void *)cur;
        } else {
            frame = (BlockFrame *)(void *)cur;
            *block = frame;
        }
    }
    return cnt;
}

static int32_t GetDataFrameFromSendList(SendBlockFrameListPara *para, BlockFrame **block, int32_t nr)
{
    int32_t ret;

    if (PthreadMutexLock(&para->sendBlockFrameList.lock) != 0) {
        DFILE_LOGE(TAG, "pthread mutex lock error");
        return FILE_MANAGER_EMUTEX;
    }

    ret = GetMultipleBlockFrame(para, block, nr);

    if (PthreadMutexUnlock(&para->sendBlockFrameList.lock) != 0) {
        DFILE_LOGE(TAG, "pthread mutex unlock error");
    }
    for (int i = 0; i < ret; ++i) {
        SemPost(&para->semBlockListNotFull);
    }
    return ret;
}

int32_t FileManagerFileRead(FileManager *fileManager, uint32_t tid, BlockFrame **block, int32_t nr)
{
    int32_t ret;
    SendBlockFrameListPara *para = NULL;
    *block = NULL;

    if (CheckSenderManager(fileManager) != NSTACKX_EOK) {
        DFILE_LOGE(TAG, "Invalid input");
        return NSTACKX_EINVAL;
    }

    para = GetSendBlockFrameListPara(fileManager, tid);
    if (para == NULL || ListIsEmpty(&para->sendBlockFrameList.head)) {
        return 0;
    }
    ret = GetDataFrameFromSendList(para, block, nr);
    if (ret < 0) {
        fileManager->errCode = ret;
        NotifyFileManagerMsg(fileManager, FILE_MANAGER_INNER_ERROR);
        DFILE_LOGE(TAG, "GetDataFrameFromSendList failed");
        return ret;
    }
    if (*block != NULL) {
        RefreshBytesTransFerred(fileManager, *block);
    }

    return ret;
}

int32_t InitSendBlockLists(FileManager *fileManager)
{
    uint32_t i;
    SendBlockFrameListPara *para = NULL;
    uint32_t sendListSize = fileManager->maxSendBlockListSize;

    for (i = 0; i < fileManager->sendFrameListNum; i++) {
        para = &fileManager->sendBlockFrameListPara[i];
        if (MutexListInit(&para->sendBlockFrameList, sendListSize) != NSTACKX_EOK) {
            DFILE_LOGE(TAG, "sendBlockFrameList InitList error");
            goto L_ERR_FILE_MANAGER;
        }
        para->sendRetranListTail = &para->sendBlockFrameList.head;
    }
    return NSTACKX_EOK;

L_ERR_FILE_MANAGER:
    while (i > 0) {
        para = &fileManager->sendBlockFrameListPara[i - 1];
        MutexListDestory(&para->sendBlockFrameList);
        para->sendRetranListTail = NULL;
        i--;
    }
    return NSTACKX_EFAILED;
}

uint32_t GetMaxSendListSize(uint16_t connType)
{
    if (connType == CONNECT_TYPE_WLAN) {
        return NSTACKX_WLAN_SEND_BLOCK_QUEUE_MAX_LEN;
    } else if (connType == CONNECT_TYPE_P2P) {
        return NSTACKX_P2P_SEND_BLOCK_QUEUE_MAX_LEN;
    } else {
        DFILE_LOGE(TAG, "invalid connect type");
        return 0;
    }
}

uint16_t GetSendListNum(void)
{
    return 1;
}

void ClearSendFrameList(FileManager *fileManager)
{
    BlockFrame *blockFrame = NULL;
    uint32_t i;
    SendBlockFrameListPara *para = NULL;
    for (i = 0; i < fileManager->sendFrameListNum; i++) {
        para = &fileManager->sendBlockFrameListPara[i];
        if (PthreadMutexLock(&para->sendBlockFrameList.lock) != 0) {
            DFILE_LOGE(TAG, "pthread mutex lock error");
        }
        while (para->sendBlockFrameList.size > 0) {
            blockFrame = (BlockFrame *)ListPopFront(&para->sendBlockFrameList.head);
            para->sendBlockFrameList.size--;
            if (blockFrame != NULL) {
                free(blockFrame->fileDataFrame);
                free(blockFrame);
                blockFrame = NULL;
            }
        }
        para->sendRetranListTail = &para->sendBlockFrameList.head;
        if (PthreadMutexUnlock(&para->sendBlockFrameList.lock) != 0) {
            DFILE_LOGE(TAG, "pthread mutex unlock error");
        }
        MutexListDestory(&para->sendBlockFrameList);
    }
}

uint8_t FileManagerIsLastBlockRead(FileManager *fileManager, uint16_t transId)
{
    FileListTask *fileList = NULL;
    uint8_t isErrorOccurred;
    if (fileManager == NULL) {
        return NSTACKX_FALSE;
    }
    fileList = GetFileListById(&fileManager->taskList, transId, &isErrorOccurred);
    if (isErrorOccurred) {
        fileManager->errCode = FILE_MANAGER_EMUTEX;
        NotifyFileManagerMsg(fileManager, FILE_MANAGER_INNER_ERROR);
        return NSTACKX_FALSE;
    }
    if (fileList == NULL) {
        return NSTACKX_FALSE;
    }
    if (fileList->newReadOutSet.fileId == 0 && fileList->sendFileProcessed == fileList->fileNum &&
        fileList->sendRetranList.size == 0 && !fileList->hasUnInsetFrame) {
        return NSTACKX_TRUE;
    }
    return NSTACKX_FALSE;
}

uint8_t FileManagerHasPendingDataMp(FileManager *fileManager, uint8_t socketIndex)
{
    List *list = NULL;
    FileListTask *fileList = NULL;
    uint8_t hasPendingData = NSTACKX_FALSE;

    if (fileManager == NULL || fileManager->isSender != NSTACKX_TRUE) {
        return NSTACKX_FALSE;
    }

    if (fileManager->sendBlockFrameListPara[socketIndex].sendBlockFrameList.size > 0) {
        return NSTACKX_TRUE;
    }

    if (PthreadMutexLock(&fileManager->taskList.lock) != 0) {
        DFILE_LOGE(TAG, "pthread mutex lock error");
        fileManager->errCode = FILE_MANAGER_EMUTEX;
        NotifyFileManagerMsg(fileManager, FILE_MANAGER_INNER_ERROR);
        return NSTACKX_FALSE;
    }

    LIST_FOR_EACH(list, &fileManager->taskList.head) {
        fileList = (FileListTask *)list;
        if (fileList->socketIndex != socketIndex || CheckFilelistNotStop(fileList) != NSTACKX_EOK) {
            continue;
        }

        if (fileList->newReadOutSet.fileId > 0) {
            hasPendingData = NSTACKX_TRUE;
            break;
        }

        if (fileList->sendFileProcessed < fileList->fileNum) {
            hasPendingData = NSTACKX_TRUE;
            break;
        }
        if (fileList->sendRetranList.size > 0) {
            hasPendingData = NSTACKX_TRUE;
            break;
        }

        if (fileList->hasUnInsetFrame) {
            hasPendingData = NSTACKX_TRUE;
            break;
        }
    }
    if (PthreadMutexUnlock(&fileManager->taskList.lock) != 0) {
        DFILE_LOGE(TAG, "pthread mutex unlock error");
        fileManager->errCode = FILE_MANAGER_EMUTEX;
        NotifyFileManagerMsg(fileManager, FILE_MANAGER_INNER_ERROR);
    }

    return hasPendingData;
}

uint8_t FileManagerHasPendingDataInner(FileManager *fileManager)
{
    List *list = NULL;
    FileListTask *fileList = NULL;
    uint8_t hasPendingData = NSTACKX_FALSE;

    if (fileManager == NULL || fileManager->isSender != NSTACKX_TRUE) {
        return NSTACKX_FALSE;
    }

    if (PthreadMutexLock(&fileManager->taskList.lock) != 0) {
        DFILE_LOGE(TAG, "pthread mutex lock error");
        fileManager->errCode = FILE_MANAGER_EMUTEX;
        NotifyFileManagerMsg(fileManager, FILE_MANAGER_INNER_ERROR);
        return NSTACKX_FALSE;
    }

    LIST_FOR_EACH(list, &fileManager->taskList.head) {
        fileList = (FileListTask *)list;
        if (CheckFilelistNotStop(fileList) != NSTACKX_EOK) {
            continue;
        }

        if (fileList->newReadOutSet.fileId > 0) {
            hasPendingData = NSTACKX_TRUE;
            break;
        }

        if (fileList->sendFileProcessed < fileList->fileNum) {
            hasPendingData = NSTACKX_TRUE;
            break;
        }
        if (fileList->sendRetranList.size > 0) {
            hasPendingData = NSTACKX_TRUE;
            break;
        }

        if (fileList->hasUnInsetFrame) {
            hasPendingData = NSTACKX_TRUE;
            break;
        }
    }
    if (PthreadMutexUnlock(&fileManager->taskList.lock) != 0) {
        DFILE_LOGE(TAG, "pthread mutex unlock error");
        fileManager->errCode = FILE_MANAGER_EMUTEX;
        NotifyFileManagerMsg(fileManager, FILE_MANAGER_INNER_ERROR);
        return NSTACKX_FALSE;
    }
    for (uint32_t i = 0; i < fileManager->sendFrameListNum; i++) {
        if (fileManager->sendBlockFrameListPara[i].sendBlockFrameList.size > 0) {
            return NSTACKX_TRUE;
        }
    }

    return hasPendingData;
}

uint8_t FileManagerHasPendingData(FileManager *fileManager)
{
    return FileManagerHasPendingDataInner(fileManager);
}

int32_t FileManagerGetLastSequence(FileManager *fileManager, uint16_t transId, uint16_t fileId, uint32_t *sequence)
{
    FileListTask *fileList = NULL;
    uint8_t isErrorOccurred;
    if (fileManager == NULL || transId == 0 || fileId == 0) {
        DFILE_LOGE(TAG, "invalid input");
        return NSTACKX_EINVAL;
    }

    fileList = GetFileListById(&fileManager->taskList, transId, &isErrorOccurred);
    if (isErrorOccurred) {
        fileManager->errCode = FILE_MANAGER_EMUTEX;
        NotifyFileManagerMsg(fileManager, FILE_MANAGER_INNER_ERROR);
        DFILE_LOGE(TAG, "failed to get target fileList %hu", transId);
        return NSTACKX_EFAILED;
    }
    if (fileList == NULL || fileId > fileList->fileNum) {
        DFILE_LOGE(TAG, "failed to get target fileList %hu", transId);
        return NSTACKX_EFAILED;
    }

    if (fileList->fileInfo[fileId - 1].totalBlockNum == 0) {
        *sequence = 0;
    } else {
        *sequence = fileList->fileInfo[fileId - 1].totalBlockNum - 1;
    }
    return NSTACKX_EOK;
}
