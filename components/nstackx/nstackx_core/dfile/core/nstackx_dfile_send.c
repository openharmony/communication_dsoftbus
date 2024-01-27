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

#include "nstackx_dfile_session.h"

#include "nstackx_dfile_log.h"
#include "nstackx_socket.h"

#define TAG "nStackXDFile"

#define WAIT_DATA_FRAME_WAIT_US            5 /* Spend 5us to read one file data frame. */

#define MAX_NR_IOVCNT       20
#define MAX_UDP_PAYLOAD     65507
#define MAX_SEND_COUNT      1

static inline uint32_t GetIovListSize(void)
{
    // updated this value from 40 to 20 now
    return  MAX_NR_IOVCNT;
}

static int32_t AllocIovList(List *head)
{
    uint32_t size = GetIovListSize();
    IovList *ptr = malloc(sizeof(IovList) * size);
    if (ptr == NULL) {
        return NSTACKX_ENOMEM;
    }
    for (uint32_t i = 0; i < size; i++) {
        ptr[i].addr = NULL;
        ptr[i].len = 0;
        ListInsertTail(head, &ptr[i].entry);
    }
    return NSTACKX_EOK;
}

#ifndef BUILD_FOR_WINDOWS
__attribute__((unused))
#endif
static IovList *GetFreeIovList(DFileSession *s, int32_t tid)
{
    List *p = &s->freeIovList[tid];
    List *q = NULL;

    if (ListIsEmpty(p)) {
        int32_t err = AllocIovList(p);
        if (err != NSTACKX_EOK) {
            return NULL;
        }
    }

    q = ListPopFront(p);
    return (IovList *)q;
}

void DestroyIovList(const List *head, DFileSession *s, uint32_t tid)
{
    List *p = NULL;
    List *n = NULL;
    BlockFrame *block = NULL;

    (void)s;
    (void)tid;
    LIST_FOR_EACH_SAFE(p, n, head) {
        block = (BlockFrame *)p;
        ListRemoveNode(p);
        free(block->fileDataFrame);
        free(block);
    }
}

static int32_t TcpSendFileDataFrame(Socket *socket, PeerInfo *peerInfo, List *p, BlockFrame *block, uint16_t len)
{
    int32_t ret;
    DFileSession *session = peerInfo->session;

    ret = SocketSend(socket, (uint8_t *)block->fileDataFrame + block->sendLen, len - block->sendLen);
    if (ret > 0 && ret == (int32_t)(len - block->sendLen)) {
        block->sendLen = 0;
        ListRemoveNode(p);
        free(block->fileDataFrame);
        free(block);
        NSTACKX_ATOM_FETCH_INC(&peerInfo->sendCount);
        NSTACKX_ATOM_FETCH_INC(&peerInfo->intervalSendCount);
        NSTACKX_ATOM_FETCH_INC(&session->totalSendBlocks);
    } else if (ret > 0) {
        NSTACKX_ATOM_FETCH_INC(&peerInfo->eAgainCount);
        block->sendLen = block->sendLen + (uint32_t)ret;
        ret = NSTACKX_EAGAIN;
    } else if (errno == EAGAIN) {
        NSTACKX_ATOM_FETCH_INC(&peerInfo->eAgainCount);
        ret = NSTACKX_EAGAIN;
    } else {
        DFILE_LOGE(TAG, "socket send failed ret is %d errno is %d", ret, errno);
        ret = NSTACKX_EFAILED;
    }

    return ret;
}

static void UdpSendFileDataSuccess(DFileSession *session, PeerInfo *peerInfo, List *p, FileDataFrameZS *f,
    BlockFrame *block)
{
    ListRemoveNode(p);
    free(f);
    free(block);
    NSTACKX_ATOM_FETCH_INC(&peerInfo->sendCount);
    NSTACKX_ATOM_FETCH_INC(&peerInfo->intervalSendCount);
    NSTACKX_ATOM_FETCH_INC(&session->totalSendBlocks);
}

static int32_t SendFileDataFrame(DFileSession *session, PeerInfo *peerInfo, List *head, uint32_t tid)
{
    List *p = NULL;
    List *n = NULL;
    BlockFrame *block = NULL;
    FileDataFrameZS *f = NULL;
    int32_t ret;
    uint16_t len;
    Socket *socket = session->socket[0];

    if (CapsTcp(session) && (session->sessionType == DFILE_SESSION_TYPE_SERVER)) {
        socket = session->acceptSocket;
    }

    LIST_FOR_EACH_SAFE(p, n, head) {
        block = (BlockFrame *)p;
        f = (FileDataFrameZS *)(void *)block->fileDataFrame;
        len = ntohs(f->header.length) + DFILE_FRAME_HEADER_LEN;
        if (CapsTcp(session)) {
            ret = TcpSendFileDataFrame(socket, peerInfo, p, block, len);
            if (ret == NSTACKX_EFAILED) {
                break;
            } else if (ret == NSTACKX_EAGAIN) {
                return ret;
            }
        } else {
            ret = SocketSend(session->socket[peerInfo->socketIndex], (void *)f, len);
            if (ret > 0) {
                UdpSendFileDataSuccess(session, peerInfo, p, f, block);
            } else if (ret == NSTACKX_EAGAIN) {
                NSTACKX_ATOM_FETCH_INC(&peerInfo->eAgainCount);
                return ret;
            } else {
                DFILE_LOGE(TAG, "socket sendto failed");
                break;
            }
        }
    }

    DestroyIovList(head, session, tid);

    return ret;
}

static int32_t SendFileDataFrameEx(DFileSession *session, PeerInfo *peerInfo, List *head, uint32_t tid)
{
    return SendFileDataFrame(session, peerInfo, head, tid);
}

static int32_t CheckUnsentList(List *unsent, List *head, int32_t maxCount)
{
    int32_t cnt = 0;

    ListInitHead(head);
    while (cnt < maxCount && !ListIsEmpty(unsent)) {
        List *p = ListPopFront(unsent);
        if (p == NULL) {
            break;
        }
        ListInsertTail(head, p);
        cnt++;
    }

    return cnt;
}

static int32_t GetMaxSendCount(void)
{
    return MAX_SEND_COUNT;
}

static int32_t DoSendDataFrame(DFileSession *session, List *head, int32_t count, uint32_t tid, uint8_t socketIndex)
{
    BlockFrame *block = NULL;
    int32_t ret;
    PeerInfo *peerInfo = ClientGetPeerInfoBySocketIndex(socketIndex, session);
    if (!peerInfo) {
        return NSTACKX_EFAILED;
    }
    int32_t maxCount = GetMaxSendCount();
    int32_t flag;
    do {
        while (count < maxCount && FileManagerHasPendingData(session->fileManager)) {
            ret = FileManagerFileRead(session->fileManager, tid, &block, maxCount - count);
            if (ret < 0) {
                DFILE_LOGE(TAG, "FileManagerFileRead failed %d", ret);
                break;
            }
            if (ret == 0) {
                NSTACKX_ATOM_FETCH_INC(&session->sendBlockListEmptyTimes);
                (void)usleep(WAIT_DATA_FRAME_WAIT_US);
                continue;
            }
            while (block) {
                List *next = block->list.next;
                ListInsertTail(head, &block->list);
                block = (BlockFrame *)(void *)next;
            }
            count += ret;
        }

        if (count == 0) {
            NSTACKX_ATOM_FETCH_INC(&session->noPendingDataTimes);
            ret = NSTACKX_EOK;
            break;
        }
        ret = SendFileDataFrameEx(session, peerInfo, head, tid);
        if (ret <= 0) {
            break;
        }

        count = 0;
        maxCount = GetMaxSendCount();
        flag = CapsTcp(session) ? (session->sendRemain ? 0 : 1) :
            (peerInfo->intervalSendCount < (uint16_t)peerInfo->amendSendRate && !session->closeFlag);
    } while (flag && (session->stopSendCnt[tid] == 0));
    return ret;
}


/*
 *  * if backpress frame count is not zero then sleep one ack interval and update stopSendCnt
 *   * if backpress frame count is zero then send packet normally
 *    */
static void CheckSendByBackPress(DFileSession *session, uint32_t tid, uint8_t socketIndex)
{
    uint32_t fileProcessCnt;
    uint32_t sleepTime;
    uint32_t stopCnt;
    PeerInfo *peerInfo = ClientGetPeerInfoBySocketIndex(socketIndex, session);
    if (peerInfo == NULL) {
        return;
    }

    if (session->stopSendCnt[tid] != 0) {
        if (PthreadMutexLock(&session->backPressLock) != 0) {
            DFILE_LOGE(TAG, "pthread backPressLock mutex lock failed");
            return;
        }

        stopCnt = session->stopSendCnt[tid];
        if (stopCnt == 0) {
            if (PthreadMutexUnlock(&session->backPressLock) != 0) {
                DFILE_LOGE(TAG, "pthread backPressLock mutex unlock failed");
            }
            return;
        }

        /* fileProcessCnt corresponds to trans one-to-one, one ack interval recv fileProcessCnt backpress frame */
        fileProcessCnt = session->fileListProcessingCnt + session->smallListProcessingCnt;

        session->stopSendCnt[tid] = (session->stopSendCnt[tid] > fileProcessCnt) ? (session->stopSendCnt[tid] -
            fileProcessCnt) : 0;

        if (PthreadMutexUnlock(&session->backPressLock) != 0) {
            DFILE_LOGE(TAG, "pthread backPressLock mutex unlock failed");
            return;
        }

        sleepTime = CapsTcp(session) ? NSTACKX_INIT_RATE_STAT_INTERVAL : peerInfo->rateStateInterval;

#ifndef NSTACKX_WITH_LITEOS
        DFILE_LOGI(TAG, "tid %u sleep %u us fileProCnt %u Interval %u lastStopCnt %u stopSendCnt %u", tid, sleepTime,
             fileProcessCnt, peerInfo->rateStateInterval, stopCnt, session->stopSendCnt[tid]);
#endif
        (void)usleep(sleepTime);
    }
}

int32_t SendDataFrame(DFileSession *session, List *unsent, uint32_t tid, uint8_t socketIndex)
{
    int32_t ret = NSTACKX_EOK;
    PeerInfo *peerInfo = ClientGetPeerInfoBySocketIndex(socketIndex, session);
    List tmpq;

    if (peerInfo == NULL) {
        return NSTACKX_EFAILED;
    }
    if (peerInfo->amendSendRate == 0) {
        return ret;
    }

    CheckSendByBackPress(session, tid, socketIndex);

    int32_t maxCount = GetMaxSendCount();
    int32_t count = CheckUnsentList(unsent, &tmpq, maxCount);
    ret = DoSendDataFrame(session, &tmpq, count, tid, socketIndex);
    if (ret == NSTACKX_EAGAIN) {
        ListMove(&tmpq, unsent);
    }
    return ret;
}

int32_t SendControlFrame(DFileSession *session, QueueNode *queueNode)
{
    int32_t ret;
    Socket *socket = NULL;

    if (CapsTcp(session)) {
        socket = (session->sessionType == DFILE_SESSION_TYPE_SERVER) ? session->acceptSocket : session->socket[0];
        ret = SocketSend(socket, queueNode->frame + queueNode->sendLen, queueNode->length - queueNode->sendLen);
        if (ret > 0 && ret == (int32_t)(queueNode->length - queueNode->sendLen)) {
            queueNode->sendLen = 0;
        } else if (ret > 0) {
            queueNode->sendLen = queueNode->sendLen + (uint32_t)ret;
            ret = NSTACKX_EAGAIN;
        } else if (errno == EAGAIN) {
            ret = NSTACKX_EAGAIN;
        } else {
            DFILE_LOGE(TAG, "socket send failed ret is %d errno is %d", ret, errno);
            ret = NSTACKX_EFAILED;
        }
        return ret;
    }

    uint8_t socketIndex = queueNode->socketIndex;
    ret = SocketSend(session->socket[socketIndex], queueNode->frame, queueNode->length);
    if (ret <= 0) {
        if (ret != NSTACKX_EAGAIN) {
            DFILE_LOGE(TAG, "MpEscape. socket:%u send failed. Errno:%d", socketIndex, errno);
            ret = NSTACKX_EFAILED;
        }
    }

    return ret;
}

int32_t SendOutboundFrame(DFileSession *session, QueueNode **preQueueNode)
{
    QueueNode *queueNode = *preQueueNode;
    int32_t ret;

    do {
        if (PthreadMutexLock(&session->outboundQueueLock) != 0) {
            DFILE_LOGE(TAG, "Pthread mutex lock failed");
            ret = NSTACKX_EFAILED;
            break;
        }
        if (queueNode == NULL && session->outboundQueueSize) {
            queueNode = (QueueNode *)ListPopFront(&session->outboundQueue);
            session->outboundQueueSize--;
        }
        if (PthreadMutexUnlock(&session->outboundQueueLock) != 0) {
            DFILE_LOGE(TAG, "Pthread mutex unlock failed");
            ret = NSTACKX_EFAILED;
            break;
        }
        if (queueNode == NULL) {
            ret = NSTACKX_EOK;
            break;
        }

        uint32_t socketIndex = queueNode->socketIndex;
        if (session->socket[socketIndex]->protocol == NSTACKX_PROTOCOL_UDP &&
            session->socket[socketIndex]->isServer == NSTACKX_TRUE) {
            session->socket[socketIndex]->dstAddr = queueNode->peerAddr;
        }

        ret = SendControlFrame(session, queueNode);
        if (ret <= 0) {
            break;
        }
        /* Send ok, try to get next frame. */
        DestroyQueueNode(queueNode);
        queueNode = NULL;
        NSTACKX_ATOM_FETCH_INC(&session->totalSendBlocks);
    } while (!session->closeFlag);

    if (ret == NSTACKX_EAGAIN) {
        *preQueueNode = queueNode;
    } else {
        *preQueueNode = NULL;
        DestroyQueueNode(queueNode);
        queueNode = NULL;
    }
    return ret;
}

int32_t TcpSocketRecv(DFileSession *session, uint8_t *buffer, size_t length, struct sockaddr_in *srcAddr,
    const socklen_t *addrLen)
{
    int32_t ret;
    int recvLen = 0;

    Socket *socket = session->socket[0];

    if (session->sessionType == DFILE_SESSION_TYPE_SERVER) {
        socket = session->acceptSocket;
    }

    while (recvLen < (int32_t)length) {
        ret = SocketRecv(socket, buffer + session->recvLen, length - (size_t)recvLen, srcAddr, addrLen);
        if (ret == 0) {
            return NSTACKX_PEER_CLOSE;
        }
        if (ret < 0) {
            if (errno != EAGAIN) {
                ret = NSTACKX_EFAILED;
                return ret;
            } else {
                return NSTACKX_EAGAIN;
            }
        }
        recvLen = recvLen + ret;
        session->recvLen = session->recvLen + (uint32_t)ret;
    }

    return recvLen;
}

int32_t SocketRecvForTcp(DFileSession *session, uint8_t *buffer, struct sockaddr_in *srcAddr,
    const socklen_t *addrLen)
{
    int32_t ret;
    uint16_t payloadLen;
    DFileFrameHeader *frameHeader = NULL;
    size_t length = sizeof(DFileFrameHeader);
    if (session->recvLen < length) {
        ret = TcpSocketRecv(session, buffer, length - session->recvLen, srcAddr, addrLen);
        if (ret <= 0) {
            return ret;
        }
    }

    frameHeader = (DFileFrameHeader *)(session->recvBuffer);
    payloadLen = ntohs(frameHeader->length);
    if (payloadLen >= NSTACKX_RECV_BUFFER_LEN) {
        DFILE_LOGI(TAG, "header length is %u recv length is %u payloadLen is %u type %u", length,
             session->recvLen, payloadLen, frameHeader->type);
        return NSTACKX_EFAILED;
    }

    if ((session->recvLen - length) < payloadLen) {
        ret = TcpSocketRecv(session, buffer, payloadLen - (session->recvLen - length), srcAddr, addrLen);
        if (ret <= 0) {
            return ret;
        }
    }

    return (int32_t)(session->recvLen);
}
