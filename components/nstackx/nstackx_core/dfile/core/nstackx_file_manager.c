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

#include "nstackx_file_manager.h"
#include "nstackx_dfile_config.h"
#include "nstackx_dfile_session.h"
#include "nstackx_error.h"
#include "nstackx_event.h"
#include "nstackx_file_manager_client.h"
#include "nstackx_dfile_log.h"
#ifdef MBEDTLS_INCLUDED
#include "nstackx_mbedtls.h"
#else
#include "nstackx_openssl.h"
#endif
#include "nstackx_util.h"
#include "securec.h"

#define TAG "nStackXDFile"

static FileRecvState FileGetRecvStatus(FileInfo *fileInfo);

typedef struct {
    FileManagerMsgReceiver msgReceiver;
    FileManagerMsgType msgType;
    int32_t errCode;
    void *context;
} FileManagerMsgCtx;

typedef struct {
    FileListMsgReceiver msgReceiver;
    FileManagerMsgType msgType;
    uint16_t fileId;
    uint16_t transId;
    FileManagerMsg msg;
    void *context;
} FileListMsgCtx;

static void NotifyFileManagerMsgInner(void *arg)
{
    FileManagerMsgCtx *ctx = arg;
    ctx->msgReceiver(ctx->msgType, ctx->errCode, ctx->context);
    free(ctx);
    return;
}

static void NotifyFileListMsgInner(void *arg)
{
    FileListMsgCtx *ctx = arg;
    ctx->msgReceiver(ctx->fileId, ctx->msgType, &ctx->msg, ctx->context, ctx->transId);
    free(ctx);
    return;
}

void NotifyFileManagerMsg(const FileManager *fileManager, FileManagerMsgType msgType)
{
    FileManagerMsgCtx *ctx = NULL;
    if (fileManager->msgReceiver == NULL || !IsEpollDescValid(fileManager->epollfd)) {
        return;
    }
    ctx = (FileManagerMsgCtx *)calloc(1, sizeof(FileManagerMsgCtx));
    if (ctx == NULL) {
        return;
    }
    ctx->msgReceiver = fileManager->msgReceiver;
    ctx->msgType = msgType;
    ctx->context = fileManager->context;
    ctx->errCode = fileManager->errCode;
    if (PostEvent(fileManager->eventNodeChain, fileManager->epollfd, NotifyFileManagerMsgInner, ctx) != NSTACKX_EOK) {
        free(ctx);
        return;
    }
}

void NotifyFileListMsg(const FileListTask *fileList, FileManagerMsgType msgType)
{
    FileListMsgCtx *ctx = NULL;
    if (fileList == NULL) {
        DFILE_LOGE(TAG, "NotifyFileListMsg fileList error");
        return;
    }

    if (fileList->msgReceiver == NULL || !IsEpollDescValid(fileList->epollfd)) {
        return;
    }
    ctx = (FileListMsgCtx *)calloc(1, sizeof(FileListMsgCtx));
    if (ctx == NULL) {
        return;
    }
    if (msgType == FILE_MANAGER_TRANS_IN_PROGRESS) {
        if (fileList->bytesTransferredLastRecord >= fileList->totalBytes) {
            free(ctx);
            return;
        }
        ctx->msg.transferUpdate.bytesTransferred = fileList->bytesTransferredLastRecord;
        ctx->msg.transferUpdate.totalBytes = fileList->totalBytes;
        ctx->msg.transferUpdate.transId = fileList->transId;
    }

    ctx->msgReceiver = fileList->msgReceiver;
    ctx->fileId = NSTACKX_RESERVED_FILE_ID;
    ctx->msgType = msgType;
    ctx->msg.errorCode = fileList->errCode;
    ctx->context = fileList->context;
    ctx->transId = fileList->transId;
    if (PostEvent(fileList->eventNodeChain, fileList->epollfd, NotifyFileListMsgInner, ctx) != NSTACKX_EOK) {
        free(ctx);
        return;
    }
}

void NotifyFileMsg(const FileListTask *fileList, uint16_t fileId, FileManagerMsgType msgType)
{
    FileListMsgCtx *ctx = NULL;
    if (fileList->msgReceiver == NULL || !IsEpollDescValid(fileList->epollfd) || fileId == 0 ||
        fileId > fileList->fileNum) {
        return;
    }
    ctx = (FileListMsgCtx *)calloc(1, sizeof(FileListMsgCtx));
    if (ctx == NULL) {
        return;
    }
    ctx->msgReceiver = fileList->msgReceiver;
    ctx->fileId = fileId;
    ctx->msgType = msgType;
    ctx->msg.errorCode = fileList->fileInfo[fileId - 1].errCode;
    ctx->context = fileList->context;
    ctx->transId = fileList->transId;
    if (PostEvent(fileList->eventNodeChain, fileList->epollfd, NotifyFileListMsgInner, ctx) != NSTACKX_EOK) {
        free(ctx);
        return;
    }
}

int32_t ConvertErrCode(int32_t error)
{
    switch (error) {
        case ENOSPC:
            return FILE_MANAGER_FILE_ENOSPC;
        case ENOMEM:
            return FILE_MANAGER_FILE_ENOMEM;
        case ENFILE:
            return FILE_MANAGER_FILE_ENFILE;
        case EACCES:
            return FILE_MANAGER_FILE_EACCES;
        case ENAMETOOLONG:
            return FILE_MANAGER_FILE_ENAMETOOLONG;
        case ETXTBSY:
            return FILE_MANAGER_FILE_ETXTBSY;
        default:
            return FILE_MANAGER_FILE_EOTHER;
    }
}

int32_t MutexListInit(MutexList *mutexList, uint32_t maxSize)
{
    if (mutexList == NULL || maxSize == 0) {
        DFILE_LOGE(TAG, "list with lock dosn't exist of maxSize if zero");
        return NSTACKX_EINVAL;
    }
    (void)memset_s(mutexList, sizeof(MutexList), 0, sizeof(MutexList));
    if (PthreadMutexInit(&mutexList->lock, NULL) != 0) {
        DFILE_LOGE(TAG, "PthreadMutexInit error");
        return NSTACKX_EFAILED;
    }
    ListInitHead(&mutexList->head);
    mutexList->maxSize = maxSize;
    return NSTACKX_EOK;
}

void MutexListDestory(MutexList *mutexList)
{
    PthreadMutexDestroy(&mutexList->lock);
}

int32_t MutexListAddNode(MutexList *mutexList, List *element, uint8_t isFront)
{
    int32_t ret;
    if (PthreadMutexLock(&mutexList->lock) != 0) {
        DFILE_LOGE(TAG, "pthread mutex lock error");
        return NSTACKX_EFAILED;
    }
    if (mutexList->size == mutexList->maxSize) {
        DFILE_LOGE(TAG, "list is full");
        ret = NSTACKX_EFAILED;
    } else {
        if (isFront) {
            ListInsertHead(&mutexList->head, element);
        } else {
            ListInsertTail(&mutexList->head, element);
        }
        ret = NSTACKX_EOK;
        mutexList->size++;
    }
    if (PthreadMutexUnlock(&mutexList->lock) != 0) {
        DFILE_LOGE(TAG, "pthread mutex unlock error");
        return NSTACKX_EFAILED;
    }
    return ret;
}

int32_t MutexListPopFront(MutexList *mutexList, List **curFront, uint8_t *isPoped)
{
    int32_t ret;
    *isPoped = NSTACKX_FALSE;
    if (PthreadMutexLock(&mutexList->lock) != 0) {
        DFILE_LOGE(TAG, "pthread mutex lock error");
        return NSTACKX_EFAILED;
    }
    if (mutexList->size == 0) {
        ret = NSTACKX_EFAILED;
    } else {
        *curFront = ListPopFront(&mutexList->head);
        mutexList->size--;
        *isPoped = NSTACKX_TRUE;
        ret = NSTACKX_EOK;
    }
    if (PthreadMutexUnlock(&mutexList->lock) != 0) {
        DFILE_LOGE(TAG, "pthread mutex unlock error");
        return NSTACKX_EFAILED;
    }
    return ret;
}

static FileListTask *PrepareOneTaskByStatus(FileManager *fileManager, uint32_t runStatus, uint8_t *isErrorOccurred)
{
    List *pos = NULL;
    List *tmp = NULL;
    FileListTask *fileList = NULL;
    uint8_t isFound = NSTACKX_FALSE;
    *isErrorOccurred = NSTACKX_FALSE;

    if (fileManager == NULL) {
        return NULL;
    }
    if (PthreadMutexLock(&fileManager->taskList.lock) != 0) {
        DFILE_LOGE(TAG, "pthread mutex lock error");
        *isErrorOccurred = NSTACKX_TRUE;
        return NULL;
    }
    LIST_FOR_EACH_SAFE(pos, tmp, &fileManager->taskList.head) {
        fileList = (FileListTask *)pos;
        if (fileList->runStatus == runStatus) {
            if (fileList->isOccupied == NSTACKX_TRUE) {
                continue;
            }
            if (runStatus == FILE_LIST_STATUS_IDLE) {
                fileList->runStatus = FILE_LIST_STATUS_RUN;
                fileList->isOccupied = NSTACKX_TRUE;
            } else if (runStatus == FILE_LIST_STATUS_STOP) {
                ListRemoveNode(&fileList->list);
                fileManager->taskList.size--;
            } else {
            }
            isFound = NSTACKX_TRUE;
            break;
        }
    }
    if (PthreadMutexUnlock(&fileManager->taskList.lock) != 0) {
        DFILE_LOGE(TAG, "pthread mutex unlock error");
        *isErrorOccurred = NSTACKX_TRUE;
        if (runStatus != FILE_LIST_STATUS_STOP) {
            return NULL;
        }
    }

    if (isFound) {
        return fileList;
    }
    return NULL;
}

int32_t SetFileOffset(FileInfo *fileInfo, uint64_t fileOffset)
{
    if (fileInfo->fileOffset == fileOffset) {
        return NSTACKX_EOK;
    }
#ifdef BUILD_FOR_WINDOWS
    if (fseek(fileInfo->fd, (int64_t)fileOffset, SEEK_SET) != 0) {
        DFILE_LOGE(TAG, "fseek error");
        return NSTACKX_EFAILED;
    }
#else
#endif
    fileInfo->fileOffset = fileOffset;
    return NSTACKX_EOK;
}
void CloseFile(FileInfo *fileInfo)
{
    if (fileInfo == NULL) {
        return;
    }
    if (fileInfo->fd != NSTACKX_INVALID_FD) {
#ifdef BUILD_FOR_WINDOWS
        if (fclose(fileInfo->fd) != 0) {
            DFILE_LOGE(TAG, "fclose error");
        }
#else
        if (close(fileInfo->fd) != 0) {
            DFILE_LOGE(TAG, "close error");
        }
#endif
        fileInfo->fileOffset = 0;
        fileInfo->fd = NSTACKX_INVALID_FD;
    }
}

static uint64_t FileGetBytesTransferred(const FileInfo *fileInfo, uint8_t isSender)
{
    uint64_t lastBlockSize;
    uint64_t ret;
    if (fileInfo == NULL || fileInfo->fileSize == 0) {
        return 0;
    }
    if (isSender) {
        if (fileInfo->maxSequenceSend < 0) {
            return 0;
        }
        if (fileInfo->maxSequenceSend + 1 == fileInfo->totalBlockNum) {
            ret = fileInfo->fileSize;
        } else {
            ret = ((uint64_t)fileInfo->standardBlockSize) * ((uint64_t)fileInfo->maxSequenceSend + 1);
        }
    } else {
        if (!fileInfo->isEndBlockReceived) {
            ret = ((uint64_t)fileInfo->standardBlockSize) * ((uint64_t)fileInfo->receivedBlockNum);
        } else {
            lastBlockSize = fileInfo->fileSize % ((uint64_t)fileInfo->standardBlockSize);
            ret = ((uint64_t)fileInfo->standardBlockSize) * ((uint64_t)fileInfo->receivedBlockNum - 1) + lastBlockSize;
        }
    }

    if (ret > fileInfo->fileSize) {
        ret = fileInfo->fileSize;
    }
    return ret;
}

uint64_t FileListGetBytesTransferred(const FileListTask *fileList, uint8_t isSender)
{
    uint32_t i;
    uint64_t ret = 0;
    if ((fileList->tarFlag == NSTACKX_TRUE) && (isSender == NSTACKX_TRUE)) {
        if (fileList->tarFileInfo.maxSequenceSend < 0) {
            return 0;
        }
        if ((fileList->tarFileInfo.maxSequenceSend + 1) == (int32_t)fileList->tarFileInfo.totalBlockNum) {
            ret = fileList->tarFileInfo.fileSize;
        } else {
            ret = ((uint64_t)fileList->tarFileInfo.standardBlockSize) *
                  ((uint64_t)fileList->tarFileInfo.maxSequenceSend + 1);
        }
        return ret;
    }

    for (i = 0; i < fileList->fileNum; i++) {
        ret += FileGetBytesTransferred(&fileList->fileInfo[i], isSender);
    }
    return ret;
}

static void ClearRecvFileList(FileListTask *fileList)
{
    BlockFrame *blockFrame = NULL;
    for (uint32_t i = 0; i < fileList->fileNum; i++) {
        CloseFile(&fileList->fileInfo[i]);
        free(fileList->fileInfo[i].fileName);
        fileList->fileInfo[i].fileName = NULL;
    }
    SemDestroy(&fileList->semStop);
    if (PthreadMutexLock(&fileList->recvBlockList.lock) != 0) {
        DFILE_LOGE(TAG, "pthread mutex lock error");
    }
    while (fileList->recvBlockList.size > 0) {
        blockFrame = (BlockFrame *)ListPopFront(&fileList->recvBlockList.head);
        fileList->recvBlockList.size--;
        if (blockFrame != NULL) {
            free(blockFrame->fileDataFrame);
            free(blockFrame);
            blockFrame = NULL;
        }
    }
    if (PthreadMutexUnlock(&fileList->recvBlockList.lock) != 0) {
        DFILE_LOGE(TAG, "pthread mutex unlock error");
    }
    MutexListDestory(&fileList->recvBlockList);
    while (!ListIsEmpty(&fileList->innerRecvBlockHead)) {
        blockFrame = (BlockFrame *)ListPopFront(&fileList->innerRecvBlockHead);
        if (blockFrame == NULL) {
            continue;
        }
        free(blockFrame->fileDataFrame);
        free(blockFrame);
        blockFrame = NULL;
    }
    ClearCryptCtx(fileList->cryptPara.ctx);
    (void)memset_s(fileList, sizeof(FileListTask), 0, sizeof(FileListTask));
    free(fileList);
}

char *GetFullFilePath(const char *path, const char *fileName)
{
    int32_t ret;
    char *fullPath = NULL;
    uint32_t fullPathLength;
    if (path == NULL || fileName == NULL) {
        return NULL;
    }

    if ((CheckPathSeprator(path) == NSTACKX_TRUE) || (CheckFilenameSeprator(fileName) == NSTACKX_TRUE)) {
        fullPathLength = (uint32_t)(strlen(path) + strlen(fileName) + sizeof('\0'));
    } else {
        fullPathLength = (uint32_t)(strlen(path) + sizeof(PATH_SEPARATOR) + strlen(fileName) + sizeof('\0'));
    }

    fullPath = (char *)calloc(fullPathLength, sizeof(char));
    if (fullPath == NULL) {
        DFILE_LOGE(TAG, "full path calloc error");
        return NULL;
    }

    if ((CheckPathSeprator(path) == NSTACKX_TRUE) || (CheckFilenameSeprator(fileName) == NSTACKX_TRUE)) {
        ret = sprintf_s(fullPath, fullPathLength, "%s%s", path, fileName);
    } else {
        ret = sprintf_s(fullPath, fullPathLength, "%s%c%s", path, PATH_SEPARATOR, fileName);
    }

    if (ret == -1) {
        DFILE_LOGE(TAG, "splice path and file name error");
        free(fullPath);
        return NULL;
    }
    return fullPath;
}

static void ClearIncompleteRecvFiles(const char *path, FileListTask *fileList)
{
    char *fullPath = NULL;
    for (uint32_t i = 0; i < fileList->fileNum; i++) {
        if (fileList->fileInfo[i].errCode == FILE_MANAGER_EOK &&
            fileList->fileInfo[i].receivedBlockNum == fileList->fileInfo[i].totalBlockNum &&
            fileList->stopType == FILE_LIST_TRANSFER_FINISH) {
            continue;
        }
        CloseFile(&fileList->fileInfo[i]);
        fullPath = GetFullFilePath(path, fileList->fileInfo[i].fileName);
        if (fullPath != NULL) {
            DFILE_LOGE(TAG, "going to remove incomplete file %s", fileList->fileInfo[i].fileName);
            if (remove(fullPath) != 0) {
                DFILE_LOGE(TAG, "remove file failed. errno %d", errno);
            }
            free(fullPath);
        }
    }
    return;
}

static void FileInfoWriteInit(FileInfo *fileInfo, const char *path, uint8_t isTruncate)
{
    char *fullPath = GetFullFilePath(path, fileInfo->fileName);
    if (fullPath == NULL) {
        DFILE_LOGE(TAG, "Can't get full path");
        fileInfo->errCode = FILE_MANAGER_ENOMEM;
        return;
    }
    if (TestAndCreateDirectory(fullPath) != NSTACKX_EOK) {
        free(fullPath);
        fileInfo->errCode = FILE_MANAGER_FILE_EOTHER;
        DFILE_LOGE(TAG, "create directory failed");
        return;
    }
#ifdef BUILD_FOR_WINDOWS
    fileInfo->fd = fopen(fullPath, "wb");
#else
    if (isTruncate) {
        fileInfo->fd = open(fullPath, O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);
    } else {
        fileInfo->fd = open(fullPath, O_WRONLY | O_CREAT, S_IRUSR | S_IWUSR);
    }
#endif
    free(fullPath);
    if (fileInfo->fd == NSTACKX_INVALID_FD) {
        fileInfo->errCode = ConvertErrCode(errno);
        DFILE_LOGE(TAG, "can't open file, error(%d)", errno);
        return;
    }
    fileInfo->fileOffset = 0;
}

static int32_t WriteToFile(FileInfo *fileInfo, uint32_t blockSequence, uint16_t length, uint8_t *payLoad,
    FileListTask *fileList)
{
    uint64_t fileOffset;
    uint16_t ret = 0;
    int32_t pRet = 0;
    DFileSession *session = fileList->context;
    if (fileInfo->fd == NSTACKX_INVALID_FD) {
        FileInfoWriteInit(fileInfo, fileList->storagePath, NSTACKX_TRUE);
        if (fileInfo->fd == NSTACKX_INVALID_FD) {
            return NSTACKX_EFAILED;
        }
    }
    if (fileInfo->fileSize == 0 || payLoad == NULL || length == 0) {
        return NSTACKX_EOK;
    }
    fileOffset = ((uint64_t)fileInfo->standardBlockSize) * ((uint64_t)blockSequence);
    fileOffset += fileInfo->startOffset;
    if (SetFileOffset(fileInfo, fileOffset) != NSTACKX_EOK) {
        fileInfo->errCode = FILE_MANAGER_FILE_EOTHER;
        DFILE_LOGE(TAG, "set file offset failed");
        return NSTACKX_EFAILED;
    }
    if (CapsNoRW(session)) {
        ret = length;
    } else {
#ifdef BUILD_FOR_WINDOWS
        ret = (uint16_t)fwrite(payLoad, 1, length, fileInfo->fd);
#else
        /* use pwrite because fseek have multi-thread issue in case of multi-path handle same file scenario */
        pRet = (int32_t)pwrite(fileInfo->fd, payLoad, length, (int64_t)fileOffset);
        if (pRet >= 0) {
            ret = (uint16_t)pRet;
        }
#endif
    }
    if ((pRet < 0) || (ret < length)) {
        DFILE_LOGE(TAG, "fwrite error %d write %hu target %hu pRet:%d", GetErrno(), ret, length, pRet);
        fileInfo->errCode = FILE_MANAGER_FILE_EOTHER;
        return NSTACKX_EFAILED;
    }
    fileInfo->fileOffset += ret;
    if (++fileInfo->receivedBlockNum == fileInfo->totalBlockNum) {
        fileInfo->isEndBlockReceived = NSTACKX_TRUE;
    }
    return NSTACKX_EOK;
}

static int32_t GetFrameHearderInfo(FileListTask *fileList, BlockFrame *blockFrame, uint16_t *fileId,
    uint32_t *blockSequence, uint16_t *payloadLength)
{
    uint16_t transId, length;
    transId = ntohs(blockFrame->fileDataFrame->header.transId);
    *fileId = ntohs(blockFrame->fileDataFrame->fileId);
    *blockSequence = ntohl(blockFrame->fileDataFrame->blockSequence);
    length = ntohs(blockFrame->fileDataFrame->header.length);
    if (transId != fileList->transId || *fileId > fileList->fileNum || *fileId == 0) {
        DFILE_LOGE(TAG, "illegal transId (%hu) or fileId (%hu)", transId, *fileId);
        return NSTACKX_EFAILED;
    } else {
        FileInfo *info = &fileList->fileInfo[*fileId - 1];
        if (info->receivedBlockNum == info->totalBlockNum) {
            DFILE_LOGI(TAG, "fileId (%hu) has already finished written totalBlockNum %u", *fileId, info->totalBlockNum);
            *payloadLength = 0;
            return NSTACKX_EOK;
        }
    }

    if (*blockSequence >= fileList->fileInfo[*fileId - 1].totalBlockNum ||
        length <= sizeof(FileDataFrame) - sizeof(DFileFrameHeader) || length > NSTACKX_MAX_FRAME_SIZE) {
        DFILE_LOGE(TAG, "block sequence or length is illegal");
        fileList->errCode = FILE_MANAGER_LIST_EBLOCK;
        return NSTACKX_EFAILED;
    }

    *payloadLength = length + sizeof(DFileFrameHeader) - sizeof(FileDataFrame);
    return NSTACKX_EOK;
}

static void UpdateFileListRecvStatus(FileManager *fileManager, FileListTask *fileList, FileInfo *fileInfo, int32_t ret)
{
    if (ret != NSTACKX_EOK) {
        DFILE_LOGE(TAG, "WriteToFile error:transId %u, fileId %u", fileList->transId, fileInfo->fileId);
        CloseFile(fileInfo);
        fileList->recvFileProcessed++;
        NotifyFileMsg(fileList, fileInfo->fileId, FILE_MANAGER_RECEIVE_FAIL);
        return;
    }
    if (fileInfo->receivedBlockNum < fileInfo->totalBlockNum) {
        return;
    }
    CloseFile(fileInfo);
    fileList->recvFileProcessed++;
    if (fileList->recvFileProcessed == fileList->fileNum) {
        NotifyFileManagerMsg(fileManager, FILE_MANAGER_IN_PROGRESS);
    }
    NotifyFileMsg(fileList, fileInfo->fileId, FILE_MANAGER_RECEIVE_SUCCESS);
}

static int32_t WriteSingleBlockFrame(FileManager *fileManager, FileListTask *fileList, BlockFrame *blockFrame)
{
    FileInfo *fileInfo = NULL;
    uint16_t fileId, payloadLength;
    uint32_t blockSequence;
    uint8_t *payLoad = NULL;
    uint8_t *buffer = NULL;
    int32_t ret = NSTACKX_EFAILED;

    if (GetFrameHearderInfo(fileList, blockFrame, &fileId, &blockSequence, &payloadLength) != NSTACKX_EOK) {
        fileList->errCode = FILE_MANAGER_LIST_EBLOCK;
        return NSTACKX_EFAILED;
    }

    if (payloadLength == 0) {
        return NSTACKX_EOK;
    }

    fileInfo = &fileList->fileInfo[fileId - 1];
    if (fileInfo->errCode != FILE_MANAGER_EOK) {
        return NSTACKX_EOK;
    }

    payLoad = blockFrame->fileDataFrame->blockPayload;
    uint32_t dataLen;
    if (fileList->cryptPara.keylen > 0) {
        buffer = (uint8_t *)calloc(payloadLength, 1);
        if (buffer == NULL) {
            fileList->errCode = FILE_MANAGER_ENOMEM;
            return NSTACKX_EFAILED;
        }
        dataLen = AesGcmDecrypt(payLoad, payloadLength, &fileList->cryptPara, buffer, payloadLength);
        if (dataLen == 0) {
            fileInfo->errCode = FILE_MANAGER_FILE_EOTHER;
            payLoad = NULL;
            DFILE_LOGE(TAG, "data decrypt error");
        } else {
            payLoad = buffer;
            payloadLength = (uint16_t)dataLen;
        }
    }
    if (payLoad != NULL) {
        ret = WriteToFile(fileInfo, blockSequence, payloadLength, payLoad, fileList);
        if (ret == NSTACKX_EOK) {
            fileManager->iowBytes += (uint64_t)payloadLength;
        }
    }
    /*
     * When all blocks are received, fsync should be called before refreshing the receivedBlockNum.
     */
    if (fileList->noSyncFlag == NSTACKX_FALSE && fileInfo->isEndBlockReceived) {
        FileSync(fileInfo);
    }
    free(buffer);
    UpdateFileListRecvStatus(fileManager, fileList, fileInfo, ret);
    return ret;
}

static int32_t WriteBlockFrame(FileManager *fileManager, FileListTask *fileList)
{
    BlockFrame *blockFrame = NULL;
    while (!ListIsEmpty(&fileList->innerRecvBlockHead)) {
        if (CheckManager(fileManager) != NSTACKX_EOK || CheckFilelist(fileList) != NSTACKX_EOK) {
            break;
        }
        blockFrame = (BlockFrame *)ListPopFront(&fileList->innerRecvBlockHead);
        if (blockFrame == NULL) {
            DFILE_LOGE(TAG, "get a null block");
            continue;
        }
        if (WriteSingleBlockFrame(fileManager, fileList, blockFrame) != NSTACKX_EOK) {
            DFILE_LOGE(TAG, "write block frame failed");
            if (fileList->errCode != NSTACKX_EOK) {
                goto L_ERR_FILE_MANAGER;
            }
        }

        free(blockFrame->fileDataFrame);
        free(blockFrame);
        blockFrame = NULL;

        if (fileList->innerRecvSize > 0) {
            fileList->innerRecvSize--;
        }
    }
    return NSTACKX_EOK;
L_ERR_FILE_MANAGER:
    free(blockFrame->fileDataFrame);
    free(blockFrame);
    return NSTACKX_EFAILED;
}

static int32_t SwapRecvBlockListHead(MutexList *mutexList, uint8_t *isEmpty, List *newHead, uint32_t *size)
{
    List *front = NULL;
    List *back = NULL;
    *isEmpty = NSTACKX_FALSE;
    if (PthreadMutexLock(&mutexList->lock) != 0) {
        DFILE_LOGE(TAG, "pthread mutex lock error");
        return NSTACKX_EFAILED;
    }
    if (mutexList->size == 0) {
        *isEmpty = NSTACKX_TRUE;
    } else {
        front = mutexList->head.next;
        back = mutexList->head.prev;
        newHead->next = front;
        newHead->prev = back;
        front->prev = newHead;
        back->next = newHead;
        ListInitHead(&mutexList->head);
        *size = mutexList->size;
        mutexList->size = 0;
    }
    if (PthreadMutexUnlock(&mutexList->lock) != 0) {
        DFILE_LOGE(TAG, "pthread mutex unlock error");
        return NSTACKX_EFAILED;
    }
    return NSTACKX_EOK;
}

static void GenerateAllEmptyFiles(FileListTask *fileList)
{
    FileInfo *fileInfo = NULL;
    int32_t ret;
    for (uint32_t i = 0; i < fileList->fileNum; i++) {
        if (fileList->fileInfo[i].fileSize > 0) {
            continue;
        }
        fileInfo = &fileList->fileInfo[i];
        ret = WriteToFile(fileInfo, 0, 0, NULL, fileList);
        CloseFile(fileInfo);
        fileList->recvFileProcessed++;

        if (ret != NSTACKX_EOK) {
            DFILE_LOGE(TAG, "Create empty file error: transId %u, fileId %u", fileList->transId, fileInfo->fileId);
            NotifyFileMsg(fileList, fileInfo->fileId, FILE_MANAGER_RECEIVE_FAIL);
        } else {
            DFILE_LOGI(TAG, "Create empty file successfully: transId %u, fileId %u", fileList->transId, 
                    fileInfo->fileId);
            NotifyFileMsg(fileList, fileList->fileInfo[i].fileId, FILE_MANAGER_RECEIVE_SUCCESS);
        }
    }
}

static void FileListRefreshFileRecvStatus(FileListTask *fileList)
{
    if (fileList->recvFileProcessed >= fileList->fileNum) {
        return;
    }

    for (uint16_t i = 0; i < fileList->fileNum; i++) {
        if (FileGetRecvStatus(&fileList->fileInfo[i]) == STATE_RECEIVE_ONGOING) {
            fileList->fileInfo[i].errCode = FILE_MANAGER_FILE_EOTHER;
            DFILE_LOGE(TAG, "file list will be stopped and set incompleted file %u to fail", 
                    fileList->fileInfo[i].fileId);
            NotifyFileMsg(fileList, fileList->fileInfo[i].fileId, FILE_MANAGER_RECEIVE_FAIL);
        }
    }
    fileList->recvFileProcessed = fileList->fileNum;
}

static void RecvTaskProcess(FileManager *fileManager, FileListTask *fileList)
{
    uint8_t isEmpty = NSTACKX_FALSE;

    while (NSTACKX_TRUE) {
        if (CheckManager(fileManager) != NSTACKX_EOK || CheckFilelist(fileList) != NSTACKX_EOK ||
            fileList->recvFileProcessed >= fileList->fileNum) {
            break;
        }

        if (!fileList->isRecvEmptyFilesCreated) {
            GenerateAllEmptyFiles(fileList);
            fileList->isRecvEmptyFilesCreated = NSTACKX_TRUE;
            continue;
        }

        SemWait(&fileList->semStop);
        if (CheckManager(fileManager) != NSTACKX_EOK || CheckFilelist(fileList) != NSTACKX_EOK) {
            break;
        }
        if (SwapRecvBlockListHead(&fileList->recvBlockList, &isEmpty, &fileList->innerRecvBlockHead,
            &(fileList->innerRecvSize)) != NSTACKX_EOK) {
            DFILE_LOGE(TAG, "Swap receive block list head error:transId %u", fileList->transId);
            fileList->errCode = FILE_MANAGER_EMUTEX;
            break;
        }
        if (isEmpty) {
            if (fileList->allFileDataReceived) {
                fileList->dataWriteTimeoutCnt++;
            }
            if (fileList->dataWriteTimeoutCnt > NSTACKX_MAX_DATA_FWRITE_TIMEOUT_COUNT) {
                DFILE_LOGE(TAG, "some frames may lost or illegal and stop this file list");
                break;
            }
            continue;
        } else {
            fileList->dataWriteTimeoutCnt = 0;
        }
        if (WriteBlockFrame(fileManager, fileList) != NSTACKX_EOK) {
            DFILE_LOGE(TAG, "WriteBlockFrame error");
            continue;
        }
    }
    FileListRefreshFileRecvStatus(fileList);
    if (fileList->errCode != FILE_MANAGER_EOK) {
        NotifyFileListMsg(fileList, FILE_MANAGER_RECEIVE_FAIL);
        DFILE_LOGE(TAG, "recv task process failed");
    }
}

static void ClearFileList(FileManager *fileManager, FileListTask *fileList)
{
    if (fileManager->isSender) {
        ClearSendFileList(fileManager, fileList);
    } else {
        ClearIncompleteRecvFiles(fileList->storagePath, fileList);
        ClearRecvFileList(fileList);
    }
}

static void BindFileManagerThreadToTargetCpu(FileManager *fileManager, uint32_t idx)
{
    int32_t cpu;
    int32_t cpus = GetCpuNum();
    if (cpus >= FIRST_CPU_NUM_LEVEL) {
        return;
    } else if (cpus >= SECOND_CPU_NUM_LEVEL) {
        if (fileManager->isSender) {
            cpu = CPU_IDX_0;
        } else {
            cpu = CPU_IDX_2 + (int32_t)idx % FILE_MANAGER_THREADS_BINDED_CPU_NUM;
        }
    } else if (cpus >= THIRD_CPU_NUM_LEVEL) {
        if (fileManager->isSender) {
            cpu = CPU_IDX_0;
        } else {
            cpu = CPU_IDX_1;
        }
    } else {
        return;
    }
    StartThreadBindCore(cpu);
}

typedef struct {
    FileManager *fileManager;
    uint32_t threadIdx;
} FileManagerThreadCtx;

static void SetIOThreadName(uint32_t threadIdx)
{
    char name[MAX_THREAD_NAME_LEN] = {0};
    if (sprintf_s(name, sizeof(name), "%s%u", DFFILE_IO_THREAD_NAME_PREFIX, threadIdx) < 0) {
        DFILE_LOGE(TAG, "sprintf io thead name failed");
    }
    SetThreadName(name);
    DFILE_LOGI(TAG, "IO thread %u start", threadIdx);
}

static void DoTaskProcess(FileManager *fileManager, FileListTask *fileList)
{
    if (fileManager->isSender) {
        SendTaskProcess(fileManager, fileList);
    } else {
        RecvTaskProcess(fileManager, fileList);
    }
}

static void FileManagerPre(FileManager *fileManager, uint32_t threadIdx)
{
    SetIOThreadName(threadIdx);
    SetMaximumPriorityForThread();
    SetTidToBindInfo(fileManager->context, threadIdx);
}

static void AfterTaskProcess(FileManager *fileManager, FileListTask *fileList)
{
    fileList->isOccupied = NSTACKX_FALSE;
    SemPost(&fileManager->semTaskListNotEmpty);
}

static void *FileManagerThread(void *arg)
{
    FileManagerThreadCtx *ctx = (FileManagerThreadCtx *)arg;
    FileManager *fileManager = ctx->fileManager;
    uint32_t threadIdx = ctx->threadIdx;
    free(ctx);
    uint8_t isErrorOccurred = NSTACKX_FALSE;
    FileListTask *fileList = NULL;
    uint8_t isBind = NSTACKX_FALSE;
    FileManagerPre(fileManager, threadIdx);
    while (fileManager->runStatus == FILE_MANAGE_RUN) {
        SemWait(&fileManager->semTaskListNotEmpty);
        if (fileManager->runStatus != FILE_MANAGE_RUN) {
            break;
        }
        uint8_t isStopTaskDetached = NSTACKX_FALSE;
        fileList = PrepareOneTaskByStatus(fileManager, FILE_LIST_STATUS_STOP, &isErrorOccurred);
        if (isErrorOccurred) {
            fileManager->errCode = FILE_MANAGER_EMUTEX;
            NotifyFileManagerMsg(fileManager, FILE_MANAGER_INNER_ERROR);
            DFILE_LOGE(TAG, "error occuerd when get stop file list");
        }
        if (fileList != NULL) {
            isStopTaskDetached = NSTACKX_TRUE;
            DFILE_LOGI(TAG, "Thread %u is clearing fileList %u", threadIdx, fileList->transId);
            ClearFileList(fileManager, fileList);
        }
        if (isErrorOccurred || isStopTaskDetached) {
            continue;
        }

        fileList = PrepareOneTaskByStatus(fileManager, FILE_LIST_STATUS_IDLE, &isErrorOccurred);
        if (isErrorOccurred) {
            fileManager->errCode = FILE_MANAGER_EMUTEX;
            NotifyFileManagerMsg(fileManager, FILE_MANAGER_INNER_ERROR);
            DFILE_LOGE(TAG, "error occuerd when get idle file list");
            continue;
        }
        if (fileList == NULL || fileList->errCode != FILE_MANAGER_EOK) {
            continue;
        }
        DFILE_LOGI(TAG, "Thread %u is processing for fileList %u", threadIdx, fileList->transId);
        if (isBind == NSTACKX_FALSE && fileManager->transFlag == NSTACKX_TRUE) {
            BindFileManagerThreadToTargetCpu(fileManager, threadIdx);
            isBind = NSTACKX_TRUE;
        }
        DoTaskProcess(fileManager, fileList);
        AfterTaskProcess(fileManager, fileList);
    }
    return NULL;
}

static void WakeAllThread(FileManager *fileManager)
{
    uint32_t i;
    List *list = NULL;
    FileListTask *fileList = NULL;
    SendBlockFrameListPara *para = NULL;
    if (PthreadMutexLock(&fileManager->taskList.lock) != 0) {
        DFILE_LOGE(TAG, "pthread mutex lock error");
        return;
    }
    LIST_FOR_EACH(list, &fileManager->taskList.head) {
        fileList = (FileListTask *)list;
        SemPost(&fileList->semStop);
        para = &fileManager->sendBlockFrameListPara[fileList->bindedSendBlockListIdx];
        SemPost(&para->semBlockListNotFull);
    }
    if (PthreadMutexUnlock(&fileManager->taskList.lock) != 0) {
        DFILE_LOGE(TAG, "pthread mutex unlock error");
        return;
    }
    for (i = 0; i < NSTACKX_FILE_MANAGER_THREAD_NUM; i++) {
        SemPost(&fileManager->semTaskListNotEmpty);
    }
}

void StopFileManagerThreads(FileManager *fileManager)
{
    uint32_t i;
    uint32_t tryNum;

    if (fileManager == NULL || fileManager->runStatus == FILE_MANAGE_DESTROY) {
        return;
    }

    fileManager->runStatus = FILE_MANAGE_DESTROY;
    for (tryNum = 0; tryNum < THREAD_QUIT_TRY_TIMES; tryNum++) {
        WakeAllThread(fileManager);
    }

    for (i = 0; i < NSTACKX_FILE_MANAGER_THREAD_NUM; i++) {
        PthreadJoin(fileManager->fileManagerTid[i], NULL);
        DFILE_LOGI(TAG, "Total thread %u: %u quit", NSTACKX_FILE_MANAGER_THREAD_NUM, i + 1);
        fileManager->fileManagerTid[i] = INVALID_TID;
    }
}

static int32_t CreateFMThread(FileManager *fileManager)
{
    uint32_t i;
    FileManagerThreadCtx *ctx = NULL;

    for (i = 0; i < NSTACKX_FILE_MANAGER_THREAD_NUM; i++) {
        ctx = (FileManagerThreadCtx *)calloc(1, sizeof(FileManagerThreadCtx));
        if (ctx == NULL) {
            DFILE_LOGE(TAG, "the %u ctx create failed", i + 1);
            goto L_ERR_FILEMANAGER;
        }
        ctx->fileManager = fileManager;
        ctx->threadIdx = i;
        if ((PthreadCreate(&fileManager->fileManagerTid[i], NULL, FileManagerThread, ctx)) != 0) {
            DFILE_LOGE(TAG, "the %u thread create failed", i + 1);
            free(ctx);
            goto L_ERR_FILEMANAGER;
        }
    }
    return NSTACKX_EOK;

L_ERR_FILEMANAGER:
    fileManager->runStatus = FILE_MANAGE_DESTROY;
    for (int32_t j = 0; j < NSTACKX_FILE_MANAGER_THREAD_NUM; j++) {
        SemPost(&fileManager->semTaskListNotEmpty);
    }
    while (i > 0) {
        PthreadJoin(fileManager->fileManagerTid[i - 1], NULL);
        i--;
    }
    return NSTACKX_EFAILED;
}

uint16_t GetStandardBlockSize(const FileManager *fileManager)
{
    uint32_t standardBlockSize;

    if (fileManager->maxFrameLength <= offsetof(FileDataFrame, blockPayload)) {
        return 0;
    }

    standardBlockSize = fileManager->maxFrameLength - offsetof(FileDataFrame, blockPayload);

    if (fileManager->keyLen > 0) {
        if (standardBlockSize <= GCM_ADDED_LEN) {
            return 0;
        }
        standardBlockSize -= GCM_ADDED_LEN;
    }
    return (uint16_t)standardBlockSize;
}

int32_t SetCryptPara(FileListTask *fileList, const uint8_t key[], uint32_t keyLen)
{
    uint32_t aadLen;

    if (CapsChaCha(fileList->context)) {
        fileList->cryptPara.cipherType = CIPHER_CHACHA;
    } else {
        fileList->cryptPara.cipherType = CIPHER_AES_GCM;
        keyLen = AES_128_KEY_LENGTH;
    }

    if (memcpy_s(fileList->cryptPara.key, sizeof(fileList->cryptPara.key), key, keyLen) != EOK) {
        DFILE_LOGE(TAG, "memcpy key failed");
        return NSTACKX_EFAILED;
    }
    fileList->cryptPara.keylen = keyLen;

    aadLen = sizeof(fileList->cryptPara.aad);
    if (memset_s(fileList->cryptPara.aad, aadLen, GCM_AAD_CHAR, aadLen) != EOK) {
        DFILE_LOGE(TAG, "memset aad failed");
        return NSTACKX_EFAILED;
    }
    fileList->cryptPara.aadLen = aadLen;
    fileList->cryptPara.ctx = CreateCryptCtx();
    if (fileList->cryptPara.ctx == NULL) {
        DFILE_LOGE(TAG, "failed to create crypt ctx");
        return NSTACKX_EFAILED;
    }
    DFILE_LOGI(TAG, "set encrypt/decrypt type is %d", fileList->cryptPara.cipherType);
    return NSTACKX_EOK;
}

/*
 * Note that this interface is only called by dfile main thread now. If other thread wants to call it, must be very
 * careful about thread-safety.
 */
FileListTask *GetFileListById(MutexList *taskList, uint16_t transId, uint8_t *isErrorOccurred)
{
    List *list = NULL;
    FileListTask *fileList = NULL;
    uint8_t isFound = NSTACKX_FALSE;
    if (isErrorOccurred != NULL) {
        *isErrorOccurred = NSTACKX_FALSE;
    }
    if (taskList == NULL) {
        return NULL;
    }
    if (PthreadMutexLock(&taskList->lock) != 0) {
        DFILE_LOGE(TAG, "pthread mutex lock error");
        goto L_ERR_FILE_MANAGER;
    }
    LIST_FOR_EACH(list, &taskList->head) {
        fileList = (FileListTask *)list;
        /* If the target filelist has been stopped, it will not be accessible by other thread. */
        if (fileList->transId == transId && fileList->runStatus != FILE_LIST_STATUS_STOP) {
            isFound = NSTACKX_TRUE;
            break;
        }
    }
    if (PthreadMutexUnlock(&taskList->lock) != 0) {
        DFILE_LOGE(TAG, "pthread mutex unlock error");
        goto L_ERR_FILE_MANAGER;
    }
    if (isFound) {
        return fileList;
    }
    return NULL;
L_ERR_FILE_MANAGER:
    if (isErrorOccurred != NULL) {
        *isErrorOccurred = NSTACKX_TRUE;
    }
    return NULL;
}

int32_t GetFileBlockListSize(MutexList *taskList, uint32_t *recvListAllSize, uint32_t *recvInnerAllSize)
{
    List *list = NULL;
    FileListTask *fileList = NULL;
    uint32_t sum = 0;
    uint32_t innerSum = 0;

    if (taskList == NULL) {
        *recvListAllSize = 0;
        *recvInnerAllSize = 0;
        return NSTACKX_EOK;
    }
    if (PthreadMutexLock(&taskList->lock) != 0) {
        DFILE_LOGE(TAG, "pthread mutex lock error");
        goto L_ERR_FILE_MANAGER;
    }
    LIST_FOR_EACH(list, &taskList->head) {
        fileList = (FileListTask *)list;
        /* If the target filelist has been stopped, it will not be accessible by other thread. */
        if (fileList->runStatus != FILE_LIST_STATUS_STOP) {
            sum += fileList->recvBlockList.size;
            innerSum += fileList->innerRecvSize;
        }
    }
    if (PthreadMutexUnlock(&taskList->lock) != 0) {
        DFILE_LOGE(TAG, "pthread mutex unlock error");
        goto L_ERR_FILE_MANAGER;
    }
    *recvListAllSize = sum;
    *recvInnerAllSize = innerSum;
    return NSTACKX_EOK;
L_ERR_FILE_MANAGER:
    return NSTACKX_EFAILED;
}

void RefreshBytesTransFerred(FileManager *fileManager, BlockFrame *block)
{
    uint32_t len = 0;
    DFileFrameHeader *header = NULL;

    while (block) {
        header = (DFileFrameHeader *)(void *)block->fileDataFrame;
        len += ntohs(header->length) + sizeof(DFileFrameHeader);
        len -= sizeof(FileDataFrame);
        block = (BlockFrame *)(void *)(block->list.next);
    }
    if (len == 0) {
        return;
    }
    if (NSTACKX_ATOM_ADD_RETURN(&fileManager->bytesTransferredInCurPeriod, (int32_t)len) >=
        (NSTACKX_MEGA_BYTES * MEGA_BYTES_TRANSFER_NOTICE_THRESHOLD)) {
        NSTACKX_ATOM_SET(&(fileManager->bytesTransferredInCurPeriod), 0);
        NotifyFileManagerMsg(fileManager, FILE_MANAGER_IN_PROGRESS);
    }
}

int32_t FileManagerStopTask(FileManager *fileManager, uint16_t transId, TaskStopType stopType)
{
    FileListTask *fileList = NULL;
    List *list = NULL;
    uint8_t isFound = NSTACKX_FALSE;
    if (fileManager == NULL) {
        return NSTACKX_EINVAL;
    }
    if (PthreadMutexLock(&fileManager->taskList.lock) != 0) {
        DFILE_LOGE(TAG, "pthread mutex lock error");
        goto L_ERR_FILE_MANAGER;
    }
    LIST_FOR_EACH(list, &fileManager->taskList.head) {
        fileList = (FileListTask *)list;
        if (fileList != NULL && fileList->transId == transId) {
            isFound = NSTACKX_TRUE;
            break;
        }
    }
    if (isFound) {
        if (stopType == FILE_LIST_TRANSFER_FINISH) {
            fileManager->stoppedTasksBytesTransferred += fileList->totalBytes;
        } else {
            fileManager->stoppedTasksBytesTransferred += FileListGetBytesTransferred(fileList, fileManager->isSender);
        }
        if (fileManager->isSender && fileList->bindedSendBlockListIdx < NSTACKX_MAX_CLIENT_SEND_THREAD_NUM) {
            if (fileManager->sendBlockFrameListPara[fileList->bindedSendBlockListIdx].bandingTransNum > 0) {
                fileManager->sendBlockFrameListPara[fileList->bindedSendBlockListIdx].bandingTransNum--;
            }
        }
        fileList->stopType = stopType;
        fileList->runStatus = FILE_LIST_STATUS_STOP;
        SemPost(&fileList->semStop);
        SemPost(&fileManager->semTaskListNotEmpty);
    }

    if (PthreadMutexUnlock(&fileManager->taskList.lock) != 0) {
        DFILE_LOGE(TAG, "pthread mutex unlock error");
        goto L_ERR_FILE_MANAGER;
    }

    if (isFound) {
        return NSTACKX_EOK;
    }
    DFILE_LOGE(TAG, "can't find target trans %u to stop", transId);
    return NSTACKX_EFAILED;
L_ERR_FILE_MANAGER:
    fileManager->errCode = FILE_MANAGER_EMUTEX;
    NotifyFileManagerMsg(fileManager, FILE_MANAGER_INNER_ERROR);
    return NSTACKX_EFAILED;
}

int32_t FileManagerSetMaxFrameLength(FileManager *fileManager, uint16_t maxFrameLength)
{
    uint32_t standardDataLength;
    if (CheckManager(fileManager) != NSTACKX_EOK) {
        DFILE_LOGE(TAG, "Invalid input");
        return NSTACKX_EINVAL;
    }
    if (maxFrameLength <= offsetof(FileDataFrame, blockPayload) || maxFrameLength > NSTACKX_MAX_FRAME_SIZE) {
        DFILE_LOGE(TAG, "max frame length is illegal");
        return NSTACKX_EINVAL;
    }
    if (fileManager->keyLen > 0) {
        standardDataLength = maxFrameLength - offsetof(FileDataFrame, blockPayload);
        if (standardDataLength <= GCM_ADDED_LEN) {
            DFILE_LOGE(TAG, "max frame length is too small");
            return NSTACKX_EINVAL;
        }
    }

    /* different peerInfo->dataFrameSize in two connection, choose a small one for fileManager */
    if (fileManager->maxFrameLength == 0) {
        fileManager->maxFrameLength = maxFrameLength;
        return NSTACKX_EOK;
    }

    if (fileManager->maxFrameLength > maxFrameLength) {
        fileManager->maxFrameLength = maxFrameLength;
    }

    return NSTACKX_EOK;
}

int32_t FileManagerSetRecvParaWithConnType(FileManager *fileManager, uint16_t connectType)
{
    int32_t ret = NSTACKX_EOK;
    if (CheckReceiverManager(fileManager) != NSTACKX_EOK) {
        DFILE_LOGE(TAG, "Invalid input");
        return NSTACKX_EINVAL;
    }
    if (connectType == CONNECT_TYPE_WLAN) {
        fileManager->maxRecvBlockListSize = NSTACKX_WLAN_RECV_BLOCK_QUEUE_MAX_LEN * NSTACKX_FILE_MANAGER_THREAD_NUM;
    } else if (connectType == CONNECT_TYPE_P2P) {
        fileManager->maxRecvBlockListSize = NSTACKX_P2P_RECV_BLOCK_QUEUE_MAX_LEN * NSTACKX_FILE_MANAGER_THREAD_NUM;
    } else {
        DFILE_LOGE(TAG, "Invalid connect type");
        ret = NSTACKX_EFAILED;
    }
    DFILE_LOGI(TAG, "connect type is %u and max recv list size is %u", connectType, fileManager->maxRecvBlockListSize);
    return ret;
}

int32_t FileManagerSetWritePath(FileManager *fileManager, const char *storagePath)
{
    if (CheckReceiverManager(fileManager) != NSTACKX_EOK || storagePath == NULL) {
        DFILE_LOGE(TAG, "Invalid input");
        return NSTACKX_EINVAL;
    }

    if (fileManager->typedPathNum > 0) {
        DFILE_LOGE(TAG, "typed storage paths has been set and can't set the common storage path");
        return NSTACKX_EINVAL;
    }

    fileManager->commonStoragePath = realpath(storagePath, NULL);
    if (fileManager->commonStoragePath == NULL) {
        DFILE_LOGE(TAG, "can't get canonicalized absolute pathname, error(%d)", errno);
        return NSTACKX_EFAILED;
    }

    if (!IsAccessiblePath(storagePath, W_OK, S_IFDIR)) {
        DFILE_LOGE(TAG, "storage path is not a valid writable folder");
        free(fileManager->commonStoragePath);
        fileManager->commonStoragePath = NULL;
        return NSTACKX_EFAILED;
    }

    return NSTACKX_EOK;
}

int32_t FileManagerSetWritePathList(FileManager *fileManager, char *path[], uint16_t *pathType, uint16_t pathNum)
{
    if (CheckReceiverManager(fileManager) != NSTACKX_EOK || path == NULL || pathType == NULL || pathNum == 0 ||
        pathNum > NSTACKX_MAX_STORAGE_PATH_NUM) {
        DFILE_LOGE(TAG, "Invalid input");
        return NSTACKX_EINVAL;
    }

    if (fileManager->commonStoragePath != NULL) {
        DFILE_LOGE(TAG, "common storage paths has been set and can't set the typed storage path");
        return NSTACKX_EFAILED;
    }

    for (uint16_t i = 0; i < pathNum; i++) {
        fileManager->pathList[i].storagePath = path[i];
        fileManager->pathList[i].pathType = pathType[i];
        DFILE_LOGI(TAG, "the %uth path, type %u", i, fileManager->pathList[i].pathType);
    }
    fileManager->typedPathNum = pathNum;
    return NSTACKX_EOK;
}

static int32_t AtomicParameterInit(FileManager *fileManager)
{
    uint32_t i = 0;
    SendBlockFrameListPara *para = NULL;
    uint32_t sendListSize = fileManager->maxSendBlockListSize;

    if (SemInit(&fileManager->semTaskListNotEmpty, 0, 0) != 0) {
        DFILE_LOGE(TAG, "semTaskListNotEmpty SemInit error");
        return NSTACKX_EFAILED;
    }

    if (fileManager->isSender) {
        for (i = 0; i < fileManager->sendFrameListNum; i++) {
            para = &fileManager->sendBlockFrameListPara[i];
            if (SemInit(&para->semBlockListNotFull, 0, sendListSize) != 0) {
                DFILE_LOGE(TAG, "semTaskListNotEmpty SemInit error");
                goto L_ERR_FILE_MANAGER;
            }
        }
    }
    return NSTACKX_EOK;
L_ERR_FILE_MANAGER:
    SemDestroy(&fileManager->semTaskListNotEmpty);
    while (i > 0) {
        para = &fileManager->sendBlockFrameListPara[i - 1];
        SemDestroy(&para->semBlockListNotFull);
        i--;
    }
    return NSTACKX_EFAILED;
}

static void AtomicParameterDestory(FileManager *fileManager)
{
    SemDestroy(&fileManager->semTaskListNotEmpty);
    if (fileManager->isSender) {
        for (uint32_t i = 0; i < fileManager->sendFrameListNum; i++) {
            SemDestroy(&fileManager->sendBlockFrameListPara[i].semBlockListNotFull);
        }
    }
}

static int32_t InitAllCacheList(FileManager *fileManager)
{
    if (MutexListInit(&fileManager->taskList, NSTACKX_MAX_PROCESSING_TASK_NUM) != NSTACKX_EOK) {
        DFILE_LOGE(TAG, "taskList InitList error");
        return NSTACKX_EFAILED;
    }

    if (fileManager->isSender) {
        if (InitSendBlockLists(fileManager) != NSTACKX_EOK) {
            MutexListDestory(&fileManager->taskList);
            DFILE_LOGE(TAG, "sendBlockFrameList InitList error");
            return NSTACKX_EFAILED;
        }
    }
    return NSTACKX_EOK;
}

static int32_t FileManagerInit(FileManager *fileManager, FileManagerMsgPara *msgPara, const uint8_t *key,
                               uint32_t keyLen, uint16_t connType)
{
    fileManager->runStatus = FILE_MANAGE_RUN;
    fileManager->errCode = FILE_MANAGER_EOK;
    fileManager->transFlag = NSTACKX_FALSE;
    if (fileManager->isSender) {
        fileManager->sendFrameListNum = GetSendListNum();
        fileManager->maxSendBlockListSize = GetMaxSendListSize(connType);
        if (fileManager->maxSendBlockListSize == 0 || fileManager->sendFrameListNum == 0) {
            DFILE_LOGE(TAG, "can't get valid send frame list num or size");
            return NSTACKX_EFAILED;
        }
        DFILE_LOGI(TAG, "connect type is %u and send frame list number is %u max send list size is %u",
             connType, fileManager->sendFrameListNum, fileManager->maxSendBlockListSize);
    }
    if (IsEpollDescValid(msgPara->epollfd) && msgPara->msgReceiver != NULL) {
        fileManager->msgReceiver = msgPara->msgReceiver;
        fileManager->context = msgPara->context;
        fileManager->epollfd = msgPara->epollfd;
        fileManager->eventNodeChain = msgPara->eventNodeChain;
    }

    if (keyLen > 0) {
        if ((keyLen != AES_128_KEY_LENGTH && keyLen != CHACHA20_KEY_LENGTH) || key == NULL ||
            memcpy_s(fileManager->key, sizeof(fileManager->key), key, keyLen) != EOK) {
            DFILE_LOGE(TAG, "can't get valid key info.");
            return NSTACKX_EFAILED;
        }
        fileManager->keyLen = keyLen;
    }
    return NSTACKX_EOK;
}

FileManager *FileManagerCreate(uint8_t isSender, FileManagerMsgPara *msgPara, const uint8_t *key,
                               uint32_t keyLen, uint16_t connType)
{
    FileManager *fileManager = NULL;
    if (isSender && (connType != CONNECT_TYPE_P2P && connType != CONNECT_TYPE_WLAN)) {
        DFILE_LOGE(TAG, "connType for sender is illagal");
        return NULL;
    }
    fileManager = (FileManager *)calloc(1, sizeof(FileManager));
    if (fileManager == NULL) {
        DFILE_LOGE(TAG, "fileManager calloc error");
        return NULL;
    }
    fileManager->isSender = isSender;
    if (FileManagerInit(fileManager, msgPara, key, keyLen, connType) != NSTACKX_EOK) {
        (void)memset_s(fileManager, sizeof(FileManager), 0, sizeof(FileManager));
        free(fileManager);
        return NULL;
    }

    if (InitAllCacheList(fileManager) != NSTACKX_EOK) {
        (void)memset_s(fileManager, sizeof(FileManager), 0, sizeof(FileManager));
        free(fileManager);
        return NULL;
    }

    if (AtomicParameterInit(fileManager) != NSTACKX_EOK) {
        goto L_ERR_FILE_MANAGER;
    }

    if (CreateFMThread(fileManager) != NSTACKX_EOK) {
        AtomicParameterDestory(fileManager);
        goto L_ERR_FILE_MANAGER;
    }

    return fileManager;

L_ERR_FILE_MANAGER:
    MutexListDestory(&fileManager->taskList);
    if (fileManager->isSender) {
        for (uint32_t i = 0; i < fileManager->sendFrameListNum; i++) {
            MutexListDestory(&fileManager->sendBlockFrameListPara[i].sendBlockFrameList);
            fileManager->sendBlockFrameListPara[i].sendRetranListTail = NULL;
        }
    }
    (void)memset_s(fileManager, sizeof(FileManager), 0, sizeof(FileManager));
    free(fileManager);
    return NULL;
}

static int32_t AddRecvFileInfo(FileBaseInfo *fileBasicInfo, FileListTask *fmFileList, uint16_t standardBlockSize)
{
    uint32_t i;
    char *fileName = NULL;
    FileInfo *fileInfo = NULL;
    for (i = 0; i < fmFileList->fileNum; i++) {
        if (fileBasicInfo[i].fileName == NULL || !IsFileNameLegal(fileBasicInfo[i].fileName)) {
            DFILE_LOGE(TAG, "the %uth input fileName is NULL", i);
            goto L_ERR_FILE_MANAGER;
        }
        fileName = fileBasicInfo[i].fileName;
        fileInfo = &fmFileList->fileInfo[i];
        fileInfo->fileName = (char *)calloc(strlen(fileName) + 1, sizeof(char));
        if (fileInfo->fileName == NULL) {
            DFILE_LOGE(TAG, "fileName calloc error");
            goto L_ERR_FILE_MANAGER;
        }

        if (strcpy_s(fileInfo->fileName, strlen(fileName) + 1, fileName) != NSTACKX_EOK) {
            DFILE_LOGE(TAG, "%uth fileName copy failed", i);
            goto L_ERR_FILE_MANAGER;
        }

        fileInfo->fileSize = fileBasicInfo[i].fileSize;
        fileInfo->startOffset = fileBasicInfo[i].startOffset;
        fileInfo->fileId = fileBasicInfo[i].fileId;
        fileInfo->standardBlockSize = standardBlockSize;
        fileInfo->totalBlockNum = (uint32_t)(fileInfo->fileSize / standardBlockSize);
        if (fileInfo->fileSize % standardBlockSize != 0) {
            fileInfo->totalBlockNum++;
        }
        fmFileList->totalBytes += fileInfo->fileSize;
        fileInfo->receivedBlockNum = 0;
        fileInfo->fd = NSTACKX_INVALID_FD;
        fileInfo->errCode = FILE_MANAGER_EOK;
        fileInfo->fileOffset = 0;
    }
    return NSTACKX_EOK;
L_ERR_FILE_MANAGER:
    for (i = 0; i < fmFileList->fileNum; i++) {
        free(fmFileList->fileInfo[i].fileName);
        fmFileList->fileInfo[i].fileName = NULL;
    }
    return NSTACKX_EFAILED;
}

static FileListTask *CreateRecvFileList(RecvFileListInfo *fileListInfo, const char *storagePath,
    uint16_t standardBlockSize, FileListMsgPara *msgPara, uint32_t maxRecvBlockListSize)
{
    FileListTask *fmFileList = NULL;
    fmFileList = (FileListTask *)calloc(1, sizeof(FileListTask));
    if (fmFileList == NULL) {
        DFILE_LOGE(TAG, "file list calloc error");
        return NULL;
    }
    fmFileList->transId = fileListInfo->transId;
    fmFileList->fileNum = fileListInfo->fileNum;
    fmFileList->storagePath = storagePath;
    fmFileList->noSyncFlag = fileListInfo->noSyncFlag;
    if (SemInit(&fmFileList->semStop, 0, 0) != 0) {
        DFILE_LOGE(TAG, "SemInit error");
        free(fmFileList);
        return NULL;
    }
    fmFileList->runStatus = FILE_LIST_STATUS_IDLE;
    fmFileList->stopType = FILE_LIST_TRANSFER_FINISH;
    fmFileList->isOccupied = NSTACKX_FALSE;
    fmFileList->errCode = FILE_MANAGER_EOK;
    ListInitHead(&fmFileList->innerRecvBlockHead);
    if (MutexListInit(&fmFileList->recvBlockList, maxRecvBlockListSize) != NSTACKX_EOK) {
        DFILE_LOGE(TAG, "receive block list init error");
        goto L_ERR_FILE_MANAGER;
    }
    fmFileList->recvFileProcessed = 0;
    fmFileList->isRecvEmptyFilesCreated = NSTACKX_FALSE;
    if (AddRecvFileInfo(fileListInfo->fileBasicInfo, fmFileList, standardBlockSize) != NSTACKX_EOK) {
        MutexListDestory(&fmFileList->recvBlockList);
        goto L_ERR_FILE_MANAGER;
    }
    if (msgPara != NULL) {
        fmFileList->msgReceiver = msgPara->msgReceiver;
        fmFileList->context = msgPara->context;
    }
    return fmFileList;
L_ERR_FILE_MANAGER:
    SemDestroy(&fmFileList->semStop);
    (void)memset_s(fmFileList, sizeof(FileListTask), 0, sizeof(FileListTask));
    free(fmFileList);
    return NULL;
}

char *GetStoragePathByType(FileManager *fileManager, uint16_t pathType)
{
    if (pathType == 0) {
        return fileManager->commonStoragePath;
    }
    for (uint16_t i = 0; i < fileManager->typedPathNum; i++) {
        if (fileManager->pathList[i].pathType == pathType) {
            return fileManager->pathList[i].storagePath;
        }
    }
    return NULL;
}

int32_t FileManagerRecvFileTask(FileManager *fileManager, RecvFileListInfo *fileListInfo, FileListMsgPara *msgPara)
{
    FileListTask *fmFileList = NULL;
    uint16_t standardBlockSize;
    const char *storagePath = NULL;
    if (CheckReceiverManager(fileManager) != NSTACKX_EOK || fileManager->maxRecvBlockListSize == 0) {
        return NSTACKX_EINVAL;
    }

    if (fileManager->taskList.size == fileManager->taskList.maxSize) {
        DFILE_LOGE(TAG, "task list is full");
        return NSTACKX_EFAILED;
    }

    storagePath = GetStoragePathByType(fileManager, fileListInfo->pathType);
    if (storagePath == NULL) {
        DFILE_LOGE(TAG, "can't get storage path for pathType %u", fileListInfo->pathType);
        return NSTACKX_EFAILED;
    }

    standardBlockSize = GetStandardBlockSize(fileManager);
    if (standardBlockSize == 0) {
        DFILE_LOGE(TAG, "max frame length is too small");
        return NSTACKX_EFAILED;
    }
    fmFileList = CreateRecvFileList(fileListInfo, storagePath, standardBlockSize, msgPara,
                                    fileManager->maxRecvBlockListSize);
    if (fmFileList == NULL) {
        DFILE_LOGE(TAG, "Creat file list error");
        return NSTACKX_EFAILED;
    }
    fmFileList->epollfd = fileManager->epollfd;
    fmFileList->eventNodeChain = fileManager->eventNodeChain;
    fmFileList->maxFrameLength = fileManager->maxFrameLength;
    if (fileManager->keyLen > 0 && SetCryptPara(fmFileList, fileManager->key, fileManager->keyLen) != NSTACKX_EOK) {
        ClearRecvFileList(fmFileList);
        DFILE_LOGE(TAG, "fail to set crypto para");
        return NSTACKX_EFAILED;
    }

    if (MutexListAddNode(&fileManager->taskList, &fmFileList->list, NSTACKX_FALSE) != NSTACKX_EOK) {
        DFILE_LOGE(TAG, "Add task to list error");
        ClearRecvFileList(fmFileList);
        fileManager->errCode = FILE_MANAGER_EMUTEX;
        NotifyFileManagerMsg(fileManager, FILE_MANAGER_INNER_ERROR);
        return NSTACKX_EFAILED;
    }
    fileManager->totalBytes += fmFileList->totalBytes;
    SemPost(&fileManager->semTaskListNotEmpty);
    return NSTACKX_EOK;
}

static int32_t PushRecvBlockFrame(FileListTask *fileList, FileDataFrame *frame)
{
    BlockFrame *blockFrame = NULL;
    int32_t ret;
    uint8_t isRetran;

    blockFrame = (BlockFrame *)calloc(1, sizeof(BlockFrame));
    if (blockFrame == NULL) {
        DFILE_LOGE(TAG, "memory calloc failed");
        return FILE_MANAGER_ENOMEM;
    }
    blockFrame->fileDataFrame = frame;
    isRetran = frame->header.flag & NSTACKX_DFILE_DATA_FRAME_RETRAN_FLAG;
    if (isRetran) {
        ret = MutexListAddNode(&fileList->recvBlockList, &blockFrame->list, NSTACKX_TRUE);
    } else {
        ret = MutexListAddNode(&fileList->recvBlockList, &blockFrame->list, NSTACKX_FALSE);
    }
    if (ret != NSTACKX_EOK) {
        free(blockFrame);
        DFILE_LOGE(TAG, "add node to recv block list failed");
        return FILE_MANAGER_EMUTEX;
    }
    SemPost(&fileList->semStop);
    return FILE_MANAGER_EOK;
}

static int32_t CheckFileBlockListOverflow(FileManager *fileManager)
{
    uint32_t recvListAllSize;
    uint32_t recvInnerAllSize;

    if (GetFileBlockListSize(&fileManager->taskList, &recvListAllSize, &recvInnerAllSize) != NSTACKX_EOK) {
        fileManager->errCode = FILE_MANAGER_EMUTEX;
        NotifyFileManagerMsg(fileManager, FILE_MANAGER_INNER_ERROR);
        DFILE_LOGE(TAG, "failed to get GetFileBlockListSize");
        return NSTACKX_EFAILED;
    }
    if (recvListAllSize >= fileManager->maxRecvBlockListSize) {
        return NSTACKX_EFAILED;
    }

    return NSTACKX_EOK;
}

int32_t FileManagerFileWrite(FileManager *fileManager, FileDataFrame *frame)
{
    uint16_t transId;
    FileListTask *fileList = NULL;
    uint8_t isErrorOccurred = NSTACKX_FALSE;
    BlockFrame block = {
        .list = {NULL, NULL},
        .fileDataFrame = frame,
    };
    if (CheckReceiverManager(fileManager) != NSTACKX_EOK) {
        DFILE_LOGE(TAG, "invalid input");
        return NSTACKX_EINVAL;
    }
    transId = ntohs(frame->header.transId);
    fileList = GetFileListById(&fileManager->taskList, transId, &isErrorOccurred);
    if (isErrorOccurred || fileList == NULL) {
        fileManager->errCode = FILE_MANAGER_EMUTEX;
        NotifyFileManagerMsg(fileManager, FILE_MANAGER_INNER_ERROR);
        DFILE_LOGE(TAG, "failed to get target fileList %u", transId);
        return NSTACKX_EFAILED;
    }
    if (CheckFilelistNotStop(fileList) != NSTACKX_EOK) {
        DFILE_LOGE(TAG, "target file list %u is not available", transId);
        return NSTACKX_EFAILED;
    }

    if (CheckFileBlockListOverflow(fileManager) != NSTACKX_EOK) {
        return NSTACKX_EFAILED;
    }
    RefreshBytesTransFerred(fileManager, &block);
    fileList->errCode = PushRecvBlockFrame(fileList, frame);
    if (fileList->errCode != FILE_MANAGER_EOK) {
        DFILE_LOGE(TAG, "add frame to recv block list failed");
        NotifyFileListMsg(fileList, FILE_MANAGER_RECEIVE_FAIL);
        return NSTACKX_EFAILED;
    }
    return NSTACKX_EOK;
}

static void ClearTask(FileManager *fileManager)
{
    FileListTask *fileList = NULL;

    while (fileManager->taskList.size > 0) {
        if (PthreadMutexLock(&fileManager->taskList.lock) != 0) {
            DFILE_LOGE(TAG, "pthread mutex lock error");
            return;
        }
        fileList = (FileListTask *)ListPopFront(&fileManager->taskList.head);
        fileManager->taskList.size--;
        if (PthreadMutexUnlock(&fileManager->taskList.lock) != 0) {
            DFILE_LOGE(TAG, "pthread mutex unlock error");
        }
        if (fileList == NULL) {
            continue;
        }
        ClearFileList(fileManager, fileList);
        fileList = NULL;
    }
    MutexListDestory(&fileManager->taskList);
}

void FileManagerDestroy(FileManager *fileManager)
{
    if (fileManager == NULL) {
        return;
    }
    if (fileManager->isSender) {
        ClearSendFrameList(fileManager);
    }
    ClearTask(fileManager);
    AtomicParameterDestory(fileManager);
    free(fileManager->commonStoragePath);
    fileManager->commonStoragePath = NULL;
    for (uint16_t i = 0; i < fileManager->typedPathNum; i++) {
        free(fileManager->pathList[i].storagePath);
        fileManager->pathList[i].storagePath = NULL;
    }
    (void)memset_s(fileManager, sizeof(FileManager), 0, sizeof(FileManager));
    free(fileManager);
    fileManager = NULL;
    DFILE_LOGI(TAG, "Destroy successfully!");
}

uint8_t FileManagerIsRecvBlockWritable(FileManager *fileManager, uint16_t transId)
{
    if (fileManager == NULL || fileManager->isSender || transId == 0) {
        return NSTACKX_FALSE;
    }

    if (CheckFileBlockListOverflow(fileManager) != NSTACKX_EOK) {
        return NSTACKX_FALSE;
    }

    return NSTACKX_TRUE;
}

int32_t FileManagerGetTotalBytes(FileManager *fileManager, uint64_t *totalBytes)
{
    if (fileManager == NULL) {
        return NSTACKX_EFAILED;
    }
    *totalBytes = fileManager->totalBytes;
    return NSTACKX_EOK;
}

int32_t FileManagerGetBytesTransferred(FileManager *fileManager, uint64_t *bytesTransferred)
{
    FileListTask *fileList = NULL;
    uint64_t runningTaskBytesTransferred = 0;
    uint64_t ret;
    List *list = NULL;
    if (fileManager == NULL || bytesTransferred == NULL) {
        return 0;
    }
    if (PthreadMutexLock(&fileManager->taskList.lock) != 0) {
        DFILE_LOGE(TAG, "pthread mutex lock error");
        goto L_ERR_FILE_MANAGER;
    }
    LIST_FOR_EACH(list, &fileManager->taskList.head) {
        fileList = (FileListTask *)list;
        if (fileList == NULL || fileList->runStatus == FILE_LIST_STATUS_STOP) {
            continue;
        }
        runningTaskBytesTransferred += FileListGetBytesTransferred(fileList, fileManager->isSender);
    }
    if (PthreadMutexUnlock(&fileManager->taskList.lock) != 0) {
        DFILE_LOGE(TAG, "pthread mutex unlock error");
        goto L_ERR_FILE_MANAGER;
    }

    ret = runningTaskBytesTransferred + fileManager->stoppedTasksBytesTransferred;
    if (ret > fileManager->totalBytes) {
        DFILE_LOGE(TAG, "result is too large");
        return NSTACKX_EFAILED;
    }
    /* for sender, can't return all bytes before there is unstopped task. */
    if (ret == fileManager->totalBytes && fileManager->isSender && runningTaskBytesTransferred > 0) {
        if (ret > NSTACKX_DEFAULT_FRAME_SIZE) {
            ret -= NSTACKX_DEFAULT_FRAME_SIZE;
        } else {
            ret = 0;
        }
    }
    if (ret <= fileManager->bytesTransferredLastRecord) {
        ret = fileManager->bytesTransferredLastRecord;
    } else {
        fileManager->bytesTransferredLastRecord = ret;
    }
    *bytesTransferred = ret;
    return NSTACKX_EOK;
L_ERR_FILE_MANAGER:
    fileManager->errCode = FILE_MANAGER_EMUTEX;
    NotifyFileManagerMsg(fileManager, FILE_MANAGER_INNER_ERROR);
    return NSTACKX_EFAILED;
}

int32_t FileManagerGetTransUpdateInfo(FileManager *fileManager, uint16_t transId, uint64_t *totalBytes,
    uint64_t *bytesTransferred)
{
    FileListTask *fileList = NULL;
    uint8_t isFound = NSTACKX_FALSE;
    List *list = NULL;
    uint64_t totalBytesPtr, bytesTransPtr;
    if (fileManager == NULL || totalBytes == NULL || bytesTransferred == NULL) {
        return NSTACKX_EFAILED;
    }
    if (PthreadMutexLock(&fileManager->taskList.lock) != 0) {
        DFILE_LOGE(TAG, "pthread mutex lock error");
        goto L_ERR_FILE_MANAGER;
    }
    LIST_FOR_EACH(list, &fileManager->taskList.head) {
        fileList = (FileListTask *)list;
        if (fileList != NULL && fileList->transId == transId) {
            bytesTransPtr = FileListGetBytesTransferred(fileList, fileManager->isSender);
            totalBytesPtr = fileList->totalBytes;
            isFound = NSTACKX_TRUE;
            break;
        }
    }
    if (PthreadMutexUnlock(&fileManager->taskList.lock) != 0) {
        DFILE_LOGE(TAG, "pthread mutex unlock error");
        goto L_ERR_FILE_MANAGER;
    }

    if (!isFound || bytesTransPtr > totalBytesPtr) {
        DFILE_LOGE(TAG, "can't find target trans %u or the result is illegal", transId);
        return NSTACKX_EFAILED;
    }
    *totalBytes = totalBytesPtr;
    *bytesTransferred = bytesTransPtr;
    return NSTACKX_EOK;

L_ERR_FILE_MANAGER:
    fileManager->errCode = FILE_MANAGER_EMUTEX;
    NotifyFileManagerMsg(fileManager, FILE_MANAGER_INNER_ERROR);
    return NSTACKX_EFAILED;
}

uint8_t GetBlockHeadFlag(uint8_t isStartFrame, uint8_t isEndFrame)
{
    uint8_t headFlag;

    if (isEndFrame) {
        headFlag = NSTACKX_DFILE_DATA_FRAME_END_FLAG;
    } else if (isStartFrame) {
        headFlag = NSTACKX_DFILE_DATA_FRAME_START_FLAG;
    } else {
        headFlag = NSTACKX_DFILE_DATA_FRAME_CONTINUE_FLAG;
    }
    return headFlag;
}

void FileManagerCLearReadOutSet(FileListTask *fileList)
{
    if (PthreadMutexLock(&fileList->newReadOutSet.lock) != 0) {
        DFILE_LOGE(TAG, "pthread mutex lock error");
        return;
    }

    fileList->newReadOutSet.blockSequence = 0;
    fileList->newReadOutSet.fileId = 0;

    if (PthreadMutexUnlock(&fileList->newReadOutSet.lock) != 0) {
        DFILE_LOGE(TAG, "pthread mutex unlock error");
        return;
    }
}

static FileRecvState FileGetRecvStatus(FileInfo *fileInfo)
{
    if (fileInfo->errCode != FILE_MANAGER_EOK) {
        return STATE_RECEIVE_DONE_FAIL;
    } else {
        if (fileInfo->fileSize == 0 || fileInfo->receivedBlockNum == fileInfo->totalBlockNum) {
            return STATE_RECEIVE_DONE_SUCCESSFULLY;
        } else {
            return STATE_RECEIVE_ONGOING;
        }
    }
}

static int32_t TaskGetReceivedFiles(FileListTask *fileList, uint16_t fileIdList[],
                                    uint8_t fileIdSuccessFlag[], uint32_t *fileNum)
{
    uint32_t count = 0;
    FileRecvState state;

    if (fileNum == NULL || *fileNum == 0) {
        return NSTACKX_EFAILED;
    }

    if (fileList == NULL) {
        *fileNum = 0;
        return NSTACKX_EFAILED;
    }

    for (uint32_t i = 0; i < fileList->fileNum; i++) {
        state = FileGetRecvStatus(&fileList->fileInfo[i]);
        if (state == STATE_RECEIVE_ONGOING) {
            continue;
        }
        fileIdList[count] = fileList->fileInfo[i].fileId;
        if (state == STATE_RECEIVE_DONE_SUCCESSFULLY) {
            fileIdSuccessFlag[count] = NSTACKX_TRUE;
        } else {
            fileIdSuccessFlag[count] = NSTACKX_FALSE;
        }
        count++;
        if (count >= *fileNum) {
            return NSTACKX_EOK;
        }
    }
    *fileNum = count;
    return NSTACKX_EOK;
}

int32_t FileManagerGetReceivedFiles(FileManager *fileManager, uint16_t transId, uint16_t fileIdList[],
                                    uint8_t fileIdSuccessFlag[], uint32_t *fileNum)
{
    FileListTask *fileList = NULL;
    uint8_t isErrorOccurred;

    if (fileNum == NULL || *fileNum == 0) {
        return NSTACKX_EFAILED;
    }

    if (fileManager == NULL || fileManager->isSender) {
        *fileNum = 0;
        return NSTACKX_EFAILED;
    }

    fileList = GetFileListById(&fileManager->taskList, transId, &isErrorOccurred);
    if (isErrorOccurred) {
        fileManager->errCode = FILE_MANAGER_EMUTEX;
        NotifyFileManagerMsg(fileManager, FILE_MANAGER_INNER_ERROR);
        *fileNum = 0;
        return NSTACKX_EFAILED;
    }
    if (fileList == NULL) {
        *fileNum = 0;
        return NSTACKX_EFAILED;
    }
    return TaskGetReceivedFiles(fileList, fileIdList, fileIdSuccessFlag, fileNum);
}

int32_t FileManagerSetAllDataReceived(FileManager *fileManager, uint16_t transId)
{
    FileListTask *fileList = NULL;
    int32_t ret = NSTACKX_EFAILED;
    List *list = NULL;
    if (CheckReceiverManager(fileManager) != NSTACKX_EOK) {
        DFILE_LOGE(TAG, "invalid input");
        return NSTACKX_EINVAL;
    }
    if (PthreadMutexLock(&fileManager->taskList.lock) != 0) {
        DFILE_LOGE(TAG, "pthread mutex lock error");
        goto L_ERR_FILE_MANAGER;
    }
    LIST_FOR_EACH(list, &fileManager->taskList.head) {
        fileList = (FileListTask *)list;
        if (fileList->transId == transId) {
            fileList->allFileDataReceived = NSTACKX_TRUE;
            SemPost(&fileList->semStop);
            ret = NSTACKX_EOK;
            break;
        }
    }
    if (PthreadMutexUnlock(&fileManager->taskList.lock) != 0) {
        DFILE_LOGE(TAG, "pthread mutex unlock error");
        goto L_ERR_FILE_MANAGER;
    }
    return ret;
L_ERR_FILE_MANAGER:
    fileManager->errCode = FILE_MANAGER_EMUTEX;
    NotifyFileManagerMsg(fileManager, FILE_MANAGER_INNER_ERROR);
    return NSTACKX_EFAILED;
}

void ClearTransStateList(DFileSession *session)
{
    List *tmp = NULL;
    List *pos = NULL;
    if (session == NULL || ListIsEmpty(&session->tranIdStateList.head))
        return;

    if (PthreadMutexLock(&session->tranIdStateList.lock) != 0) {
        DFILE_LOGE(TAG, "pthread mutex lock error");
        return;
    }

    LIST_FOR_EACH_SAFE(pos, tmp, &session->tranIdStateList.head) {
        TransStateNode *node = (TransStateNode *)pos;
        ListRemoveNode(&node->list);
        free(node);
        session->tranIdStateList.size--;
    }

    if (PthreadMutexUnlock(&session->tranIdStateList.lock) != 0) {
        DFILE_LOGE(TAG, "pthread mutex unlock error");
        return;
    }

    return;
}

int32_t SetTransIdState(DFileSession *session, uint16_t transId, TransIdState state)
{
    List *curFront = NULL;
    uint8_t errorFlag = NSTACKX_FALSE;
    uint8_t isPoped;

    if (session == NULL)
        return NSTACKX_EFAILED;

    if (session->sessionType == DFILE_SESSION_TYPE_CLIENT) {
        return NSTACKX_EOK;
    }
    TransIdState curState = STATE_TRANS_INIT;
    TransStateNode *node = GetTransIdState(session, transId, &curState);
    if (node == NULL) {
        node = (TransStateNode *)calloc(1, sizeof(TransStateNode));
        if (node == NULL) {
            return NSTACKX_EFAILED;
        }
        node->transId = transId;
        node->transIdState = state;
        if (MutexListAddNode(&session->tranIdStateList, &node->list, 0) != NSTACKX_EOK) {
            free(node);
            return NSTACKX_EFAILED;
        }
        if (session->tranIdStateList.size == session->tranIdStateList.maxSize) {
            if (MutexListPopFront(&session->tranIdStateList, &curFront, &isPoped) != NSTACKX_EOK) {
                DFILE_LOGE(TAG, "Pop tranIdStateList head error");
                errorFlag = NSTACKX_TRUE;
            }
            if (isPoped) {
                TransStateNode *tmp = (TransStateNode *)curFront;
                free(tmp);
                tmp = NULL;
            }
        }
        return (errorFlag ? NSTACKX_EFAILED : NSTACKX_EOK);
    }

    if (curState == state) {
        return NSTACKX_EOK;
    }

    node->transIdState = state;
    return NSTACKX_EOK;
}

TransStateNode *GetTransIdState(DFileSession *session, uint16_t transId, TransIdState *state)
{
    List *pos = NULL;
    TransStateNode *node = NULL;
    uint8_t find = NSTACKX_FALSE;

    if (session == NULL || ListIsEmpty(&session->tranIdStateList.head))
        return NULL;

    if (PthreadMutexLock(&session->tranIdStateList.lock) != 0) {
        DFILE_LOGE(TAG, "pthread mutex lock error");
        return NULL;
    }
    LIST_FOR_EACH(pos, &session->tranIdStateList.head) {
        node = (TransStateNode *)pos;
        if (node->transId == transId) {
            *state = node->transIdState;
            find = NSTACKX_TRUE;
            break;
        }
    }

    if (PthreadMutexUnlock(&session->tranIdStateList.lock) != 0) {
        DFILE_LOGE(TAG, "pthread mutex unlock error");
        return NULL;
    }
    return (find ? node : NULL);
}

int32_t IsTransIdDone(DFileSession *session, uint16_t transId)
{
    TransIdState state = STATE_TRANS_INIT;
    TransStateNode *node = NULL;

    if (session != NULL && session->sessionType == DFILE_SESSION_TYPE_CLIENT) {
        return NSTACKX_EOK;
    }
    node = GetTransIdState(session, transId, &state);
    if (node == NULL) {
        return NSTACKX_EFAILED;
    }

    if (state == STATE_TRANS_DONE) {
        DFILE_LOGE(TAG, "trans %u is transfer done already", transId);
        return NSTACKX_EOK;
    }

    return NSTACKX_EFAILED;
}
