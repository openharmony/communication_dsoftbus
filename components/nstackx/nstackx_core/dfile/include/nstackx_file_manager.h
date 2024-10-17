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

#ifndef NSTACKX_FILE_MANAGER_H
#define NSTACKX_FILE_MANAGER_H

#include "nstackx_epoll.h"
#include "nstackx_list.h"
#include "nstackx_dfile_frame.h"
#ifdef MBEDTLS_INCLUDED
#include "nstackx_mbedtls.h"
#else
#include "nstackx_openssl.h"
#endif
#include "nstackx_dfile_config.h"
#include "nstackx_util.h"

#ifdef __cplusplus
extern "C" {
#endif

#define NSTACKX_FILE_MANAGER_THREAD_NUM 3
#define NSTACKX_MAX_DATA_FWRITE_TIMEOUT_COUNT 30
#define MAX_SEND_FILE_OPENED_PER_LIST 10 /* at least 1 */

#define FILE_MANAGER_EOK  0 /* OK */
#define FILE_MANAGER_EMUTEX (-1) /* mutex lock or unlock error */
#define FILE_MANAGER_ENOMEM (-2) /* Out of memory */
#define FILE_MANAGER_MANAGER_BLIST_EADDFULL (-3) /* try to add node to a full block frame list */
#define FILE_MANAGER_LIST_EBLOCK (-3) /* receive a illegal block */
#define FILE_MANAGER_FILE_ENOSPC (-3) /* device has no available storage space */
#define FILE_MANAGER_FILE_ENOMEM (-4) /* Insufficient kernel memory was available */
#define FILE_MANAGER_FILE_ENFILE (-5) /* the number of open file descriptors has been reached */
#define FILE_MANAGER_FILE_EACCES (-6) /* permission denied */
#define FILE_MANAGER_FILE_ENAMETOOLONG (-7) /* file pathname is too long */
#define FILE_MANAGER_FILE_ETXTBSY (-8) /* file is occupied */
#define FILE_MANAGER_FILE_EOTHER (-9) /* other error */
#define NSTACKX_MEGA_BYTES 1048576
#define MEGA_BYTES_TRANSFER_NOTICE_THRESHOLD 20
#define NSTACKX_KILO_BYTES 1024
#define KILO_BYTES_TRANSFER_NOTICE_THRESHOLD 20480
#define FILE_RECV_LIST_LEAST_SIZE 10
#define FILE_RECV_LIST_IO_WRITE_THRESHOLD 0.8
#define FILE_RECV_LIST_SLOW_START_RATE 2

#ifdef NSTACKX_WITH_LITEOS
#define FILE_RECV_LIST_MEM_THRESHOLD_WARNING (64 * 1024 * 1024)
#else
#define FILE_RECV_LIST_MEM_THRESHOLD_WARNING (800 * 1024 * 1024)
#endif

#ifdef BUILD_FOR_WINDOWS
#define NSTACKX_INVALID_FD NULL
#else
#define NSTACKX_INVALID_FD (-1)
#endif

typedef enum {
    FILE_MANAGER_INNER_ERROR = 1,
    FILE_MANAGER_SEND_FAIL,
    FILE_MANAGER_SEND_WAITING_END,
    FILE_MANAGER_RECEIVE_FAIL,
    FILE_MANAGER_RECEIVE_SUCCESS,
    FILE_MANAGER_IN_PROGRESS,
    FILE_MANAGER_TRANS_IN_PROGRESS
} FileManagerMsgType;

typedef struct {
    uint64_t fileSize;
    uint64_t startOffset;
    uint16_t fileId;
    char *fileName;
} FileBaseInfo;

typedef struct {
    FileBaseInfo *fileBasicInfo;
    uint16_t fileNum;
    uint16_t transId;
    uint16_t pathType;
    uint8_t noSyncFlag;
} RecvFileListInfo;

typedef struct {
    char *fileList[NSTACKX_DFILE_MAX_FILE_NUM + 1];
    uint64_t fileSize[NSTACKX_DFILE_MAX_FILE_NUM];
    uint64_t startOffset[NSTACKX_DFILE_MAX_FILE_NUM];
    uint16_t fileNum;
    uint16_t transId;
    uint8_t tarFlag;
    uint8_t smallFlag;
} SendFileListInfo;

typedef struct {
    uint16_t fileId;
    uint64_t fileSize;
    uint16_t standardBlockSize;
    uint32_t totalBlockNum;
    char *fileName;
#ifdef BUILD_FOR_WINDOWS
    FILE *fd;
#else
    int32_t fd;
#endif
    uint8_t *tarData;
    int32_t errCode;
    int64_t maxSequenceSend;
    uint32_t receivedBlockNum;
    uint64_t fileOffset;
    uint64_t writeOffset;
    uint8_t isEndBlockReceived;
    uint64_t startOffset;
} FileInfo;

typedef struct {
    List list;
    uint16_t fileId;
    uint32_t blockSequence;
    uint32_t linkSequence;
} SendRetranRequestNode;

typedef struct {
    List head;
    uint32_t maxSize;
    uint32_t size;
    pthread_mutex_t lock;
} MutexList;

typedef struct {
    List list;
    FileDataFrame *fileDataFrame;
    uint32_t sendLen;
    uint8_t socketIndex;
} BlockFrame;

/* Reuse DFileMsg for ease use */
typedef DFileMsg FileManagerMsg;
typedef void (*FileListMsgReceiver)(uint16_t fileId, FileManagerMsgType msgType, FileManagerMsg *msg, void *context,
                                    uint16_t transId);

typedef struct {
    FileListMsgReceiver msgReceiver;
    void *context;
} FileListMsgPara;

typedef enum {
    FILE_LIST_TRANSFER_FINISH = 1,
    FILE_LIST_TRANSFER_CANCEL,
} TaskStopType;

typedef struct {
    uint16_t fileId;
    uint32_t blockSequence;
    pthread_mutex_t lock;
} SendFilesOutSet;

typedef struct {
    List list;
    uint16_t transId;
    uint16_t fileNum;
    int32_t errCode;
    FileInfo fileInfo[NSTACKX_DFILE_MAX_FILE_NUM];
    sem_t semStop;
    TaskStopType stopType;
    uint32_t runStatus;
    uint32_t innerRecvSize;
    uint16_t sendFileProcessed;
    uint16_t recvFileProcessed;
    SendFilesOutSet newReadOutSet;
    MutexList sendRetranList; /* DATA:SendRetranBlock */
    MutexList recvBlockList; /* DATA:BlockFrame */
    List innerRecvBlockHead; /* DATA:BlockFrame */
    EpollDesc epollfd;
    List *eventNodeChain;
    FileListMsgReceiver msgReceiver;
    void *context;
    CryptPara cryptPara;
    uint64_t bytesTransferredLastRecord;
    uint64_t totalBytes;
    const char *storagePath; /* only useful for receiver */
    const char *tarFile;
    FILE *tarFd;
    FileDataFrame *tarFrame;
    FileInfo tarFileInfo;
    uint8_t isOccupied;
    uint8_t isRecvEmptyFilesCreated;
    uint8_t socketIndex;
    uint8_t allFileDataReceived;
    uint8_t hasUnInsetFrame;
    uint8_t tarFlag;
    uint8_t smallFlag;
    uint8_t noSyncFlag;
    uint8_t tarFinished;
    uint16_t blockOffset;
    uint16_t maxFrameLength;
    uint32_t bindedSendBlockListIdx;
    uint32_t dataWriteTimeoutCnt;
    uint64_t bytesTransferred; /* only useful for non-tar sender */
} FileListTask;

typedef void (*FileManagerMsgReceiver)(FileManagerMsgType msgType, int32_t errCode, void *context);

typedef struct {
    char *storagePath;
    uint16_t pathType;
} TypedStoragePath;

typedef struct {
    MutexList sendBlockFrameList; /* DATA:BlockFrame */
    List *sendRetranListTail;
    sem_t semBlockListNotFull;
    uint32_t bandingTransNum;
} SendBlockFrameListPara;

typedef struct {
    uint32_t runStatus;
    int32_t errCode;
    uint8_t isSender;
    uint8_t transFlag;
    uint8_t recvListOverIo;
    uint16_t maxFrameLength;
    uint16_t typedPathNum;
    sem_t semTaskListNotEmpty;
    char *commonStoragePath;
    TypedStoragePath pathList[NSTACKX_MAX_STORAGE_PATH_NUM];
    MutexList taskList; /* DATA:FileListTask */
    pthread_t fileManagerTid[NSTACKX_FILE_MANAGER_THREAD_NUM];
    EpollDesc epollfd;
    List *eventNodeChain;
    FileManagerMsgReceiver msgReceiver;
    void *context;
    uint8_t key[AES_256_KEY_LENGTH];
    uint32_t keyLen;
    uint64_t totalBytes;
    atomic_t totalPackInMemory;
    uint64_t stoppedTasksBytesTransferred;
    uint64_t bytesTransferredLastRecord;
    atomic_t bytesTransferredInCurPeriod;
    uint16_t sendFrameListNum;
    SendBlockFrameListPara sendBlockFrameListPara[NSTACKX_MAX_CLIENT_SEND_THREAD_NUM];
    uint32_t maxSendBlockListSize;
    uint32_t maxRecvBlockListSize;
    uint64_t iorBytes;
    uint64_t iowBytes;
    uint32_t iorRate;
    uint32_t iowRate;
    uint32_t iowMaxRate;
    uint32_t sendListFullTimes;
    uint64_t iowCount; /* io write count in NSTACKX_WLAN_MAX_CONTROL_FRAME_TIMEOUT second */
} FileManager;

typedef struct {
    EpollDesc epollfd;
    List *eventNodeChain;
    FileManagerMsgReceiver msgReceiver;
    void *context;
} FileManagerMsgPara;

typedef enum {
    STATE_RECEIVE_ONGOING = 0,
    STATE_RECEIVE_DONE_FAIL,
    STATE_RECEIVE_DONE_SUCCESSFULLY,
} FileRecvState;

typedef struct {
    List list;
    TransIdState transIdState;
    uint16_t transId;
} TransStateNode;

#define FILE_MANAGE_RUN 0
#define FILE_MANAGE_DESTROY 1

#define FILE_LIST_STATUS_IDLE 0
#define FILE_LIST_STATUS_RUN 1
#define FILE_LIST_STATUS_STOP 2

#define NSTACKX_MAX_RETRAN_BLOCK_NUM 50000
#define NSTACKX_MAX_PROCESSING_TASK_NUM 100

#define LIST_TAIL_BLOCK_REPEAT_TIMES 2
#define THREAD_QUIT_TRY_TIMES 3
#define GCM_AAD_CHAR 'A'

#define FILE_MANAGER_THREADS_BINDED_CPU_NUM NSTACKX_FILE_MANAGER_THREAD_NUM

static inline int32_t CheckManager(const FileManager *fileManager)
{
    if (fileManager == NULL || fileManager->runStatus != FILE_MANAGE_RUN || fileManager->errCode != FILE_MANAGER_EOK) {
        return NSTACKX_EINVAL;
    }
    return NSTACKX_EOK;
}

static inline int32_t CheckSenderManager(const FileManager *fileManager)
{
    if (CheckManager(fileManager) != NSTACKX_EOK || fileManager->isSender != NSTACKX_TRUE) {
        return NSTACKX_EINVAL;
    }
    return NSTACKX_EOK;
}

static inline int32_t CheckReceiverManager(FileManager *fileManager)
{
    if (CheckManager(fileManager) != NSTACKX_EOK || fileManager->isSender != NSTACKX_FALSE) {
        return NSTACKX_EINVAL;
    }
    return NSTACKX_EOK;
}

static inline int32_t CheckFilelist(FileListTask *fileList)
{
    if (fileList == NULL || fileList->runStatus != FILE_LIST_STATUS_RUN || fileList->errCode != FILE_MANAGER_EOK) {
        return NSTACKX_EFAILED;
    }
    return NSTACKX_EOK;
}

static inline int32_t CheckFilelistNotStop(FileListTask *fileList)
{
    if (fileList == NULL || fileList->runStatus == FILE_LIST_STATUS_STOP || fileList->errCode != FILE_MANAGER_EOK) {
        return NSTACKX_EFAILED;
    }
    return NSTACKX_EOK;
}

/* Not thread safe */
FileManager *FileManagerCreate(uint8_t isSender, FileManagerMsgPara *msgPara, const uint8_t *key,
                               uint32_t keyLen, uint16_t connType);

/* Not thread safe */
void StopFileManagerThreads(FileManager *fileManager);

/*
 * Destroy fileManager and free related resource.
 * Note: this is not thread safe, and you must call the interface StopFileManagerThreads to stop all related threads
 *       before call this interface.
 */
void FileManagerDestroy(FileManager *fileManager);

/* Not thread safe */
int32_t FileManagerSetMaxFrameLength(FileManager *fileManager, uint16_t maxFrameLength);

/* Not thread safe */
int32_t FileManagerSetRecvParaWithConnType(FileManager *fileManager, uint16_t connectType);

/* Not thread safe */
int32_t FileManagerSetWritePath(FileManager *fileManager, const char *storagePath);

/* Not thread safe */
int32_t FileManagerSetWritePathList(FileManager *fileManager, char *path[], uint16_t *pathType, uint16_t pathNum);

/* Not thread safe */
int32_t FileManagerSendFileTask(FileManager *fileManager, const SendFileListInfo *fileListInfo,
                                const FileListMsgPara *msgPara);
/* Not thread safe */
int32_t FileManagerResetSendOutSet(FileManager *fileManager, uint16_t fileId, uint32_t blockSequence, uint16_t transId);

/* Not thread safe */
int32_t FileManagerFileRead(FileManager *fileManager, uint32_t tid, BlockFrame **block, int32_t nr);

/* Not thread safe */
int32_t FileManagerRecvFileTask(FileManager *fileManager, RecvFileListInfo *fileListInfo, FileListMsgPara *msgPara);

/* Not thread safe */
int32_t FileManagerFileWrite(FileManager *fileManager, FileDataFrame *frame);

/*
 * Stop the transfer of file list specialized by the argument transId and clear related resource.
 * Para: stopType - this is only meaningful for receiver and is one of the follow integer:
 *       FILE_LIST_TRANSFER_FINISH, the receiver will remove all error and incompelte files received in this tranfer;
 *       FILE_LIST_TRANSFER_CANCEL, the receicer will remove all files in this transfer.
 * Note: this interface is not thread safe
 */
int32_t FileManagerStopTask(FileManager *fileManager, uint16_t transId, TaskStopType stopType);

/* Not thread safe */
uint8_t FileManagerIsLastBlockRead(FileManager *fileManager, uint16_t transId);

/* Not thread safe */
uint8_t FileManagerHasPendingData(FileManager *fileManager);

/* Not thread safe */
int32_t FileManagerGetLastSequence(FileManager *fileManager, uint16_t transId, uint16_t fileId, uint32_t *sequence);

/* Not thread safe */
uint8_t FileManagerIsRecvBlockWritable(FileManager *fileManager, uint16_t transId);

/* Not thread safe */
int32_t FileManagerGetTotalBytes(FileManager *fileManager, uint64_t *totalBytes);

/* Not thread safe */
int32_t FileManagerGetBytesTransferred(FileManager *fileManager, uint64_t *bytesTransferred);

/* Not thread safe */
int32_t FileManagerGetTransUpdateInfo(FileManager *fileManager, uint16_t transId, uint64_t *totalBytes,
                                      uint64_t *bytesTransferred);

int32_t GetEncryptedDataTarFrame(CryptPara *cryptPara, uint16_t fileId, FileListTask *fileList, uint16_t targetLenth);

int32_t GetNoEncryptedDataTarFrame(uint16_t fileId, FileListTask *fileList, uint16_t targetLenth);

int32_t FileManagerGetReceivedFiles(FileManager *fileManager, uint16_t transId, uint16_t fileIdList[],
                                    uint8_t fileIdSuccessFlag[], uint32_t *fileNum);

int32_t FileManagerSetAllDataReceived(FileManager *fileManager, uint16_t transId);

uint8_t PushSendBlockFrame(FileManager *fileManager, const FileListTask *fileList, const FileDataFrame *fileDataFrame);

void UpdateTarFileListSendStatus(FileListTask *fileList);

FileDataFrame *CreateRetranBlockFrame(FileManager *fileManager, FileListTask *fileList);

uint8_t PushRetranBlockFrame(FileManager *fileManager, const FileListTask *fileList,
                             const FileDataFrame *fileDataFrame);
void FileManagerCLearReadOutSet(FileListTask *fileList);

uint8_t GetBlockHeadFlag(uint8_t isStartFrame, uint8_t isEndFrame);

int32_t MutexListInit(MutexList *mutexList, uint32_t maxSize);

void MutexListDestory(MutexList *mutexList);

int32_t MutexListPopFront(MutexList *mutexList, List **curFront, uint8_t *isPoped);

int32_t MutexListAddNode(MutexList *mutexList, List *element, uint8_t isFront);

void NotifyFileManagerMsg(const FileManager *fileManager, FileManagerMsgType msgType);

void NotifyFileListMsg(const FileListTask *fileList, FileManagerMsgType msgType);

void NotifyFileMsg(const FileListTask *fileList, uint16_t fileId, FileManagerMsgType msgType);

int32_t ConvertErrCode(int32_t error);

int32_t SetFileOffset(FileInfo *fileInfo, uint64_t fileOffset);

void CloseFile(FileInfo *fileInfo);

uint64_t FileListGetBytesTransferred(const FileListTask *fileList, uint8_t isSender);

uint16_t GetStandardBlockSize(const FileManager *fileManager);

int32_t SetCryptPara(FileListTask *fileList, const uint8_t key[], uint32_t keyLen);

FileListTask *GetFileListById(MutexList *taskList, uint16_t transId, uint8_t *isErrorOccurred);

void RefreshBytesTransFerred(FileManager *fileManager, BlockFrame *frame);
int32_t GetFileBlockListSize(MutexList *taskList, uint32_t *recvListAllSize, uint32_t *recvInnerAllSize);
extern int32_t SetTransIdState(DFileSession *session, uint16_t transId, TransIdState state);
extern TransStateNode *GetTransIdState(DFileSession *session, uint16_t transId, TransIdState *state);
extern int32_t IsTransIdDone(DFileSession *session, uint16_t transId);
extern void ClearTransStateList(DFileSession *session);

void FileSync(const FileInfo *fileInfo);
char *GetStoragePathByType(FileManager *fileManager, uint16_t pathType);
char *GetFullFilePath(const char *path, const char *fileName);

#ifdef __cplusplus
}
#endif

#endif /* NSTACKX_FILE_MANAGER_H */
