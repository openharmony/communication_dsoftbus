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

#ifndef NSTACKX_DFILE_SESSION_H
#define NSTACKX_DFILE_SESSION_H
#include "nstackx_event.h"
#include "nstackx_socket.h"
#include "nstackx_file_manager.h"
#include "nstackx_dfile_transfer.h"
#include "nstackx_dfile_private.h"
#include "nstackx_timer.h"
#ifdef __cplusplus
extern "C" {
#endif

#define MAX_EPOLL_SIZE 128
#define MAX_PEERINFO_SIZE 10
#define MAX_SEND_TRANSFERDONE_ACK_FRAME_COUNT 14
#define MAX_TRANSFERDONE_ACK_NODE_COUNT 100
#define MAX_TRANSTATELISTSIZE           100

typedef enum {
    DFILE_SESSION_TYPE_CLIENT = 1,
    DFILE_SESSION_TYPE_SERVER,
} DFileSessionType;

typedef struct {
    List list;
    uint32_t sendLen;
    uint8_t *frame;
    size_t length;
    struct sockaddr_in peerAddr;
    uint8_t socketIndex;
} QueueNode;

typedef struct {
    pthread_t senderTid;
    sem_t sendWait;
    sem_t semNewCycle;
} SendThreadPara;

typedef struct {
    List entry;
    void *addr;
    size_t len;
} IovList;

typedef struct {
    List list;
    uint16_t transId;
    uint16_t sendNum;
} TransferDoneAckNode;

typedef struct {
    uint8_t isWorking;
    uint16_t transId;
    PeerInfo *peerInfo;
} TransSlot;

struct DFileSession {
    List list;
    uint16_t sessionId; /* reserve for multi session */
    DFileSessionType sessionType;
    SocketProtocol protocol;
    Socket *socket[NSTACKX_MULTI_PATH_NUM];
    Socket *acceptSocket;
    pthread_t tid;
    EpollDesc epollfd;
    List eventNodeChain;
    uint8_t closeFlag;
    uint32_t vtransDefaultSize;
    List vtransManagerList;
    pthread_mutex_t transIdLock;
    BindType bindType;
    DFileMsgReceiver msgReceiver;
    OnDFileRenameFile onRenameFile;
    uint16_t lastDFileTransId; /* for client, server will use client trans id */
    List dFileTransChain;
    List peerInfoChain;
    MutexList transferDoneAckList; /* DATA:FileListTask */
    uint32_t peerInfoCnt;
    FileManager *fileManager;
    pthread_t senderTid[NSTACKX_MULTI_PATH_NUM];
    SendThreadPara sendThreadPara[NSTACKX_MAX_CLIENT_SEND_THREAD_NUM];
    uint8_t addiSenderCloseFlag;
    pthread_t receiverTid;
    pthread_t controlTid;
    List outboundQueue;
    List inboundQueue;
    pthread_mutex_t outboundQueueLock;
    pthread_mutex_t inboundQueueLock;
    sem_t outboundQueueWait[NSTACKX_MULTI_PATH_NUM];
    uint64_t outboundQueueSize;
    uint64_t inboundQueueSize;
    List pendingFileLists;
#ifdef NSTACKX_SMALL_FILE_SUPPORT
    List smallFileLists;
#endif
    uint32_t fileListProcessingCnt;
    uint32_t fileListPendingCnt;
    uint32_t smallListProcessingCnt;
#ifdef NSTACKX_SMALL_FILE_SUPPORT
    uint32_t smallListPendingCnt;
#endif
    /*
     * Receiver thread is blocking at "select" most of time.
     * This "receiverPipe" is used to unblock "select" and terminate receiver thread during NSTACKX_DFileClose(),
     * decreasing the closing time.
     */
    struct timespec measureBefore;
    PipeDesc receiverPipe[PIPE_FD_NUM];
    uint64_t recvBlockNumDirect;
    uint64_t recvBlockNumInner;
    atomic_t totalSendBlocks;
    atomic_t totalRecvBlocks;
    uint8_t partReadFlag;
    atomic_t sendBlockListEmptyTimes;
    atomic_t noPendingDataTimes;
    uint32_t sleepTimes;
    uint16_t clientSendThreadNum;
    uint8_t cycleRunning[2];
    struct timespec startTs;
    uint64_t bytesTransferred;
    uint32_t transCount;
    atomic_t unprocessedReadEventCount;
    uint8_t mainLoopActiveReadFlag;
    List freeIovList[NSTACKX_MAX_CLIENT_SEND_THREAD_NUM];
    uint8_t transFlag;
    uint32_t capability;
    uint32_t internalCaps;
    uint32_t capsCheck;
    MutexList tranIdStateList;
    uint32_t wlanCatagory;
    TransSlot transSlot[NSTACKX_FILE_MANAGER_THREAD_NUM];
    uint8_t *recvBuffer;
    uint32_t recvLen;
    uint8_t acceptFlag;
    uint8_t sendRemain;
    int32_t allTaskCount;
    pthread_mutex_t backPressLock;
    uint32_t stopSendCnt[NSTACKX_MAX_CLIENT_SEND_THREAD_NUM];
    uint32_t cipherCapability;
};

PeerInfo *CreatePeerInfo(DFileSession *session, const struct sockaddr_in *peerAddr,
    uint16_t mtu, uint16_t connType, uint8_t socketIndex);
int32_t DFileWriteHandle(const uint8_t *frame, size_t len, void *context);
void NotifyMsgRecver(const DFileSession *session, DFileMsgType msgType, const DFileMsg *msg);
void TerminateMainThreadInner(void *arg);
void *DFileMainLoop(void *arg);
void *DFileSenderHandle(void *arg);
void *DFileReceiverHandle(void *arg);
void NotifyPipeEvent(const DFileSession *session);
int32_t CreateReceiverPipe(DFileSession *session);
int32_t CreateFileManager(DFileSession *session, const uint8_t *key, uint32_t keyLen, uint8_t isSender,
    uint16_t connType);
int32_t DFileStartTrans(DFileSession *session, FileListInfo *fileListInfo);
int32_t StartDFileThreadsInner(DFileSession *session);
void DFileSessionSendSetting(PeerInfo *peerInfo);
void UpdateAllTransRetryCount(DFileSession *session, PeerInfo *peerInfo);
void CalculateSessionTransferRatePrepare(DFileSession *session);

void DestroyQueueNode(QueueNode *queueNode);
PeerInfo *ClientGetPeerInfoBySocketIndex(uint8_t socketIndex, const DFileSession *session);
void NoticeSessionProgress(DFileSession *session);
int32_t DFileSessionHandleReadBuffer(DFileSession *session, const uint8_t *buf, size_t bufLen,
                                     struct sockaddr_in *peerAddr, uint8_t socketIndex);
int32_t DFileAcceptSocket(DFileSession *session);

int32_t WaitSocketEvent(const DFileSession *session, SocketDesc fd, uint32_t timeoutMs,
    uint8_t *canRead, uint8_t *canWrite);

int32_t CheckFdSetSize(SocketDesc sock);
void DestroyReceiverPipe(DFileSession *session);

#define DFILE_SESSION_TERMINATE_FLAG 0x01
#define DFILE_SESSION_FATAL_FLAG     0x02

static inline void DFileSessionSetFatalFlag(struct DFileSession *session)
{
    session->closeFlag |= DFILE_SESSION_FATAL_FLAG;
}

static inline void DFileSessionSetTerminateFlag(struct DFileSession *session)
{
    session->closeFlag |= DFILE_SESSION_TERMINATE_FLAG;
}

static inline int32_t DFileSessionCheckFatalFlag(const struct DFileSession *session)
{
    return session->closeFlag & DFILE_SESSION_FATAL_FLAG;
}

static inline void ClearSessionStats(struct DFileSession *session)
{
    session->sleepTimes = 0;
    NSTACKX_ATOM_SET(&(session->sendBlockListEmptyTimes), 0);
    NSTACKX_ATOM_SET(&(session->noPendingDataTimes), 0);
    session->fileManager->sendListFullTimes = 0;
    session->fileManager->iorBytes = 0;
}

static inline bool CapsGSO(const struct DFileSession *session)
{
    return session->capability & NSTACKX_CAPS_UDP_GSO;
}

static inline bool CapsLinkSeq(const struct DFileSession *session)
{
    return session->capability & NSTACKX_CAPS_LINK_SEQUENCE;
}

static inline bool CapsNoRW(const struct DFileSession *session)
{
    return session->internalCaps & NSTACKX_INTERNAL_CAPS_NORW;
}

static inline bool CapsTcp(const struct DFileSession *session)
{
    return ((session->capability & NSTACKX_CAPS_WLAN_CATAGORY) && (session->wlanCatagory == NSTACKX_WLAN_CAT_TCP));
}

static inline bool CapsRecvFeedback(const struct DFileSession *session)
{
    return session->capsCheck & NSTACKX_INTERNAL_CAPS_RECV_FEEDBACK;
}

static inline bool CapsChaCha(const struct DFileSession *session)
{
    return (session->fileManager->keyLen == CHACHA20_KEY_LENGTH) &&
        (session->cipherCapability & NSTACKX_CIPHER_CHACHA);
}

void NSTACKX_DFileAssembleFunc(void *softObj, const DFileEvent *info);
void DFileSetEvent(void *softObj, DFileEventFunc func);

#ifdef __cplusplus
}
#endif
#endif // NSTACKX_DFILE_SESSION_H
