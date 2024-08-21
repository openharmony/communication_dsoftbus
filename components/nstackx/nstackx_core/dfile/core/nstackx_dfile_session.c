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

#include "nstackx_congestion.h"
#include "nstackx_dfile.h"
#include "nstackx_dfile_config.h"
#include "nstackx_dfile_frame.h"
#include "nstackx_dfile_send.h"
#include "nstackx_epoll.h"
#include "nstackx_error.h"
#include "nstackx_event.h"
#include "nstackx_dfile_log.h"
#ifdef MBEDTLS_INCLUDED
#include "nstackx_mbedtls.h"
#else
#include "nstackx_openssl.h"
#endif
#include "nstackx_timer.h"
#include "nstackx_dfile_control.h"
#include "nstackx_dfile_mp.h"
#include "securec.h"
#include "nstackx_util.h"
#include "nstackx_dfile_dfx.h"

#define TAG "nStackXDFile"

#define DEFAULT_WAIT_TIME_MS               1000
#define MULTI_THREADS_SOCKET_WAIT_TIME_MS  1
#define DEFAULT_NEGOTIATE_TIMEOUT          1000
#define TCP_NEGOTIATE_TIMEOUT              10000
#define MAX_SERVER_NEGOTIATE_VALID_TIMEOUT (600 * DEFAULT_NEGOTIATE_TIMEOUT)
#define MAX_NEGOTIATE_TIMEOUT_COUNT        3
#define MAX_UNPROCESSED_READ_EVENT_COUNT   3
#define MAX_RECVBUF_COUNT                  130000
#define MAX_NOMEM_PRINT                    10000

static void ReadEventHandle(void *arg);
static void ProcessSessionTrans(const DFileSession *session, uint16_t exceptTransId);
DFileEventFunc g_dfileEventFunc;

static QueueNode *CreateQueueNode(const uint8_t *frame, size_t length,
    const struct sockaddr_in *peerAddr, uint8_t socketIndex)
{
    QueueNode *queueNode = NULL;

    if (frame == NULL || length == 0 || length > NSTACKX_MAX_FRAME_SIZE) {
        return NULL;
    }

    queueNode = calloc(1, sizeof(QueueNode));
    if (queueNode == NULL) {
        return NULL;
    }

    queueNode->frame = calloc(1, length);
    if (queueNode->frame == NULL) {
        free(queueNode);
        return NULL;
    }
    queueNode->length = length;
    queueNode->sendLen = 0;

    if (memcpy_s(queueNode->frame, length, frame, length) != EOK) {
        DestroyQueueNode(queueNode);
        return NULL;
    }
    if (peerAddr != NULL) {
        if (memcpy_s(&queueNode->peerAddr, sizeof(struct sockaddr_in), peerAddr, sizeof(struct sockaddr_in)) != EOK) {
            DestroyQueueNode(queueNode);
            return NULL;
        }
    }
    queueNode->socketIndex = socketIndex;

    return queueNode;
}

void DestroyQueueNode(QueueNode *queueNode)
{
    if (queueNode != NULL) {
        free(queueNode->frame);
        free(queueNode);
    }
}

void NotifyMsgRecver(const DFileSession *session, DFileMsgType msgType, const DFileMsg *msg)
{
    if (session == NULL) {
        DFILE_LOGI(TAG, "session is NULL");
        return;
    }

    if (session->msgReceiver == NULL) {
        DFILE_LOGI(TAG, "msgReceiver is NULL");
        return;
    }

    session->msgReceiver(session->sessionId, msgType, msg);
}

void CalculateSessionTransferRatePrepare(DFileSession *session)
{
#ifdef NSTACKX_SMALL_FILE_SUPPORT
    if (session->sessionType == DFILE_SESSION_TYPE_CLIENT && (!ListIsEmpty(&session->pendingFileLists)
        || !ListIsEmpty(&session->smallFileLists))) {
        return;
    }
#else
    if (session->sessionType == DFILE_SESSION_TYPE_CLIENT && !ListIsEmpty(&session->pendingFileLists)) {
        return;
    }
#endif
    if (!ListIsEmpty(&session->dFileTransChain)) {
        return;
    }
    DFILE_LOGI(TAG, "begin to calculate transfer rate");
    session->bytesTransferred = 0;
    session->transCount = 0;
    ClockGetTime(CLOCK_MONOTONIC, &session->startTs);
}

#ifdef NSTACKX_SMALL_FILE_SUPPORT
static int32_t SendSmallList(DFileSession *session)
{
    FileListInfo *fileListInfo = NULL;
    DFileMsg data;
    if (session->fileListProcessingCnt > 0 || session->fileListPendingCnt == 0) {
        while (!ListIsEmpty(&session->smallFileLists)) {
            fileListInfo = (FileListInfo *)ListPopFront(&session->smallFileLists);
            session->smallListPendingCnt--;
            if (fileListInfo == NULL) {
                continue;
            }
            int32_t ret = DFileStartTrans(session, fileListInfo);
            if (ret == NSTACKX_EOK) {
                return NSTACKX_TRUE;
            }
            DFILE_LOGE(TAG, "DFileStartTrans fail, error: %d", ret);
            (void)memset_s(&data, sizeof(data), 0, sizeof(data));
            data.errorCode = ret;
            data.fileList.files = (const char **)fileListInfo->files;
            data.fileList.fileNum = fileListInfo->fileNum;
            data.fileList.userData = fileListInfo->userData;
            NotifyMsgRecver(session, DFILE_ON_FILE_SEND_FAIL, &data);
            DestroyFileListInfo(fileListInfo);
        }
    }
    return NSTACKX_FALSE;
}
#endif

static void SendPendingList(DFileSession *session)
{
    FileListInfo *fileListInfo = NULL;
    DFileMsg data;
    while (!ListIsEmpty(&session->pendingFileLists)) {
        fileListInfo = (FileListInfo *)ListPopFront(&session->pendingFileLists);
        session->fileListPendingCnt--;
        if (fileListInfo == NULL) {
            continue;
        }
        int32_t ret = DFileStartTrans(session, fileListInfo);
        if (ret == NSTACKX_EOK) {
            break;
        }
        DFILE_LOGE(TAG, "DFileStartTrans fail, error: %d", ret);
        (void)memset_s(&data, sizeof(data), 0, sizeof(data));
        data.errorCode = ret;
        data.fileList.files = (const char **)fileListInfo->files;
        data.fileList.fileNum = fileListInfo->fileNum;
        data.fileList.userData = fileListInfo->userData;
        NotifyMsgRecver(session, DFILE_ON_FILE_SEND_FAIL, &data);
        DestroyFileListInfo(fileListInfo);
    }
}

static void SendSmallAndPendingList(DFileSession *session)
{
#ifdef NSTACKX_SMALL_FILE_SUPPORT
    DFILE_LOGI(TAG, "fileListPendingCnt %u fileListProcessingCnt %u smallListPendingCnt %u smallListProcessingCnt %u",
        session->fileListPendingCnt, session->fileListProcessingCnt, session->smallListPendingCnt,
        session->smallListProcessingCnt);
    if (SendSmallList(session) != NSTACKX_TRUE) {
        SendPendingList(session);
    }
#else
    DFILE_LOGI(TAG, "fileListPendingCnt %u fileListProcessingCnt %u",
        session->fileListPendingCnt, session->fileListProcessingCnt);
    SendPendingList(session);
#endif
}

void NoticeSessionProgress(DFileSession *session)
{
    DFileMsg data;
    (void)memset_s(&data, sizeof(data), 0, sizeof(data));
    if ((FileManagerGetTotalBytes(session->fileManager, &data.transferUpdate.totalBytes) == NSTACKX_EOK) &&
        (FileManagerGetBytesTransferred(session->fileManager, &data.transferUpdate.bytesTransferred) == NSTACKX_EOK) &&
        (data.transferUpdate.bytesTransferred <= data.transferUpdate.totalBytes) &&
        (data.transferUpdate.bytesTransferred > 0)) {
        NotifyMsgRecver(session, DFILE_ON_SESSION_IN_PROGRESS, &data);
    }
}

static void UpdateMsgProcessInfo(const DFileSession *session, struct DFileTrans *dFileTrans,
                                 DFileTransMsgType msgType, DFileTransMsg *msg)
{
    uint64_t totalBytes = 0;
    uint64_t bytesTrans = 0;

    if (session == NULL || dFileTrans == NULL || msg == NULL ||
        (msgType != DFILE_TRANS_MSG_FILE_RECEIVED && msgType != DFILE_TRANS_MSG_FILE_RECEIVE_FAIL &&
        msgType != DFILE_TRANS_MSG_FILE_SEND_FAIL && msgType != DFILE_TRANS_MSG_FILE_SENT)) {
        return;
    }

    msg->transferUpdate.transId = dFileTrans->transId;

    if (msgType == DFILE_TRANS_MSG_FILE_RECEIVED ||  msgType == DFILE_TRANS_MSG_FILE_SENT) {
        totalBytes = DFileTransGetTotalBytes(dFileTrans);
        if (totalBytes > 0) {
            bytesTrans = totalBytes;
            goto L_END;
        }
    }

    if (FileManagerGetTransUpdateInfo(session->fileManager, dFileTrans->transId, &totalBytes, &bytesTrans) !=
        NSTACKX_EOK) {
        return;
    }

L_END:
    msg->transferUpdate.totalBytes = totalBytes;
    msg->transferUpdate.bytesTransferred = bytesTrans;
    if (msgType == DFILE_TRANS_MSG_FILE_SENT) {
        if (dFileTrans->fileList->vtransFlag) {
            msg->fileList.transId = dFileTrans->fileList->vtransRealTransId;
            msg->transferUpdate.transId = dFileTrans->fileList->vtransRealTransId;
        }
        NotifyMsgRecver(session, DFILE_ON_TRANS_IN_PROGRESS, msg);
    }
}

static void WakeSendThread(DFileSession *session, uint8_t isSender, uint8_t socketIndex)
{
    SemPost(&session->outboundQueueWait[socketIndex]);
    if (isSender && session->clientSendThreadNum > 1) {
        for (uint16_t i = 0; i < session->clientSendThreadNum - 1; i++) {
            SemPost(&session->sendThreadPara[i].sendWait);
        }
    }
}

static void CalculateSessionTransferRate(DFileSession *session, uint64_t totalBytes, DFileTransMsgType msgType)
{
    if (msgType != DFILE_TRANS_MSG_FILE_SENT && msgType != DFILE_TRANS_MSG_END) {
        return;
    }
    if (totalBytes <= UINT64_MAX - session->bytesTransferred) {
        session->bytesTransferred += totalBytes;
    } else {
        session->bytesTransferred = UINT64_MAX;
    }
    session->transCount++;
    if (!ListIsEmpty(&session->dFileTransChain)) {
        return;
    }
#ifdef NSTACKX_SMALL_FILE_SUPPORT
    if (session->sessionType == DFILE_SESSION_TYPE_CLIENT && (!ListIsEmpty(&session->pendingFileLists)
        || !ListIsEmpty(&session->smallFileLists))) {
        return;
    }
#else
    if (session->sessionType == DFILE_SESSION_TYPE_CLIENT && !ListIsEmpty(&session->pendingFileLists)) {
        return;
    }
#endif
    struct timespec endTs;
    ClockGetTime(CLOCK_MONOTONIC, &endTs);

    uint32_t spendTime = GetTimeDiffMs(&endTs, &session->startTs);
    if (spendTime == 0) {
        return;
    }
    const double rate = 1.0 * session->bytesTransferred / DFILE_MEGABYTES * MSEC_TICKS_PER_SEC / spendTime;
    DFILE_LOGI(TAG, "Total %u trans, %llu bytes, used %u ms. rate %.2f MB/s",
         session->transCount, session->bytesTransferred, spendTime, rate);
    DFileMsg msgData;
    (void)memset_s(&msgData, sizeof(msgData), 0, sizeof(msgData));
    msgData.rate = (uint32_t)rate;
    NotifyMsgRecver(session, DFILE_ON_SESSION_TRANSFER_RATE, &msgData);

    TransferCompleteEvent(rate);
}

static void CheckTransDone(DFileSession *session, struct DFileTrans *dFileTrans, DFileTransMsgType msgType)
{
    if (msgType == DFILE_TRANS_MSG_FILE_RECEIVE_FAIL || msgType == DFILE_TRANS_MSG_FILE_SENT ||
        msgType == DFILE_TRANS_MSG_FILE_SEND_FAIL || msgType == DFILE_TRANS_MSG_END) {
        uint8_t flag = dFileTrans->fileList->smallFlag;
        if (SetTransIdState(session, dFileTrans->transId, STATE_TRANS_DONE) != NSTACKX_EOK) {
            DFILE_LOGE(TAG, "set trans id state fail");
        }
        if (((PeerInfo *)dFileTrans->context)->currentTransCount > 0) {
            ((PeerInfo *)dFileTrans->context)->currentTransCount--;
        }
        ListRemoveNode(&dFileTrans->list);
        uint64_t totalBytes = DFileTransGetTotalBytes(dFileTrans);
        DFileTransDestroy(dFileTrans);
        if (session->sessionType == DFILE_SESSION_TYPE_CLIENT) {
            if (flag == NSTACKX_TRUE && session->smallListProcessingCnt > 0) {
                session->smallListProcessingCnt--;
            } else if (session->fileListProcessingCnt > 0) {
                session->fileListProcessingCnt--;
            }
            SendSmallAndPendingList(session);
        }
        CalculateSessionTransferRate(session, totalBytes, msgType);
    }
}

static void DTransMsgReceiver(struct DFileTrans *dFileTrans, DFileTransMsgType msgType,
                              DFileTransMsg *msg)
{
    PeerInfo *peerInfo = dFileTrans->context;
    DFileSession *session = peerInfo->session;

    UpdateMsgProcessInfo(session, dFileTrans, msgType, msg);

    switch (msgType) {
        case DFILE_TRANS_MSG_FILE_SEND_DATA:
            WakeSendThread(session, dFileTrans->isSender, peerInfo->socketIndex);
            break;
        case DFILE_TRANS_MSG_FILE_LIST_RECEIVED:
            NotifyMsgRecver(session, DFILE_ON_FILE_LIST_RECEIVED, msg);
            break;
        case DFILE_TRANS_MSG_FILE_RECEIVED: /* Receiver receive all the file data */
            NotifyMsgRecver(session, DFILE_ON_FILE_RECEIVE_SUCCESS, msg);
            break;
        case DFILE_TRANS_MSG_FILE_RECEIVED_TO_FAIL:
        case DFILE_TRANS_MSG_FILE_RECEIVE_FAIL:
            NotifyMsgRecver(session, DFILE_ON_FILE_RECEIVE_FAIL, msg);
            break;
        case DFILE_TRANS_MSG_FILE_SENT: /* Sender send TRANSFER DONE ACK frame and come to end */
            NoticeSessionProgress(session);
            NotifyMsgRecver(session, DFILE_ON_FILE_SEND_SUCCESS, msg);
            break;
        case DFILE_TRANS_MSG_FILE_SEND_FAIL:
            NotifyMsgRecver(session, DFILE_ON_FILE_SEND_FAIL, msg);
            break;
        case DFILE_TRANS_MSG_IN_PROGRESS:
            NotifyMsgRecver(session, DFILE_ON_TRANS_IN_PROGRESS, msg);
            break;
        case DFILE_TRANS_MSG_FILE_SEND_ACK:
            ProcessSessionTrans(session, dFileTrans->transId);
            break;
        default:
            DFILE_LOGI(TAG, "transId %u, recv DFileTrans event %d", dFileTrans->transId, msgType);
    }

    CheckTransDone(session, dFileTrans, msgType);
}

static void ServerSettingTimeoutHandle(void *data)
{
    PeerInfo *peerInfo = data;
    ListRemoveNode(&peerInfo->list);
    TimerDelete(peerInfo->settingTimer);
    peerInfo->session->peerInfoCnt--;
    free(peerInfo);
    DFILE_LOGI(TAG, "DFileServer Setting Negotationion timeout");
}

static void ClientSettingTimeoutHandle(void *data)
{
    PeerInfo *peerInfo = data;
    uint8_t cnt = peerInfo->settingTimeoutCnt++;
    DFileMsg msgData;
    uint32_t timeout = CapsTcp(peerInfo->session) ? TCP_NEGOTIATE_TIMEOUT : DEFAULT_NEGOTIATE_TIMEOUT;
    (void)memset_s(&msgData, sizeof(msgData), 0, sizeof(msgData));
    if (cnt >= MAX_NEGOTIATE_TIMEOUT_COUNT) {
        TimerDelete(peerInfo->settingTimer);
        peerInfo->settingTimer = NULL;
        peerInfo->settingTimeoutCnt = 0;
        msgData.errorCode = NSTACKX_EFAILED;
        DFILE_LOGI(TAG, "DFileClient Setting Negotationion timeout");
        NotifyMsgRecver(peerInfo->session, DFILE_ON_CONNECT_FAIL, &msgData);
    } else {
        DFileSessionSendSetting(peerInfo);
        DFILE_LOGI(TAG, "Client Setting Negotationion timeout %u times", peerInfo->settingTimeoutCnt);
        if (TimerSetTimeout(peerInfo->settingTimer, timeout, NSTACKX_FALSE) != NSTACKX_EOK) {
            msgData.errorCode = NSTACKX_EFAILED;
            NotifyMsgRecver(peerInfo->session, DFILE_ON_CONNECT_FAIL, &msgData);
            DFILE_LOGE(TAG, "Timer setting timer fail");
        }
    }
}

static DFileTrans *SearchDFileTransNode(List *dFileTransChain, uint16_t transId)
{
    List *pos = NULL;
    DFileTrans *trans = NULL;

    if (dFileTransChain == NULL || transId == 0) {
        return NULL;
    }

    LIST_FOR_EACH(pos, dFileTransChain) {
        trans = (DFileTrans *)pos;
        if (trans->transId == transId) {
            return trans;
        }
    }
    return NULL;
}

static PeerInfo *SearchPeerInfoNode(const DFileSession *session, const struct sockaddr_in *peerAddr)
{
    List *pos = NULL;
    PeerInfo *peerInfo = NULL;
    LIST_FOR_EACH(pos, &session->peerInfoChain) {
        peerInfo = (PeerInfo *)pos;
        if (memcmp(&peerInfo->dstAddr, peerAddr, sizeof(struct sockaddr_in)) == 0 &&
            peerInfo->session->sessionId == session->sessionId) {
            return peerInfo;
        }
    }
    return NULL;
}

void DFileSessionSendSetting(PeerInfo *peerInfo)
{
    uint32_t timeout = CapsTcp(peerInfo->session) ? TCP_NEGOTIATE_TIMEOUT : DEFAULT_NEGOTIATE_TIMEOUT;
    uint8_t buf[NSTACKX_DEFAULT_FRAME_SIZE];
    size_t frameLen = 0;
    DFileMsg data;
    (void)memset_s(&data, sizeof(data), 0, sizeof(data));
    SettingFrame settingFramePara;
    settingFramePara.connType = peerInfo->connType;
    settingFramePara.mtu = peerInfo->localMtu;
    settingFramePara.capability = peerInfo->session->capability & NSTACKX_CAPS_LINK_SEQUENCE;
    settingFramePara.dataFrameSize = 0;
    settingFramePara.capsCheck = NSTACKX_INTERNAL_CAPS_RECV_FEEDBACK;
    if (peerInfo->session->fileManager->keyLen) {
        DFileGetCipherCaps(peerInfo->session, &settingFramePara);
    }
    EncodeSettingFrame(buf, NSTACKX_DEFAULT_FRAME_SIZE, &frameLen, &settingFramePara);

    if (peerInfo->settingTimer != NULL) {
        int32_t ret = DFileWriteHandle(buf, frameLen, peerInfo);
        if (ret != (int32_t)frameLen && ret != NSTACKX_EAGAIN) {
            data.errorCode = NSTACKX_EFAILED;
            NotifyMsgRecver(peerInfo->session, DFILE_ON_CONNECT_FAIL, &data);
        }
        return;
    }

    if (peerInfo->session->sessionType == DFILE_SESSION_TYPE_CLIENT) {
        peerInfo->settingTimer = TimerStart(peerInfo->session->epollfd, timeout,
                                            NSTACKX_FALSE, ClientSettingTimeoutHandle, peerInfo);
        if (peerInfo->settingTimer == NULL) {
            DFILE_LOGE(TAG, "setting timmer creat fail");
            data.errorCode = NSTACKX_EFAILED;
            NotifyMsgRecver(peerInfo->session, DFILE_ON_CONNECT_FAIL, &data);
            return;
        }
    } else {
        peerInfo->settingTimer = TimerStart(peerInfo->session->epollfd, MAX_SERVER_NEGOTIATE_VALID_TIMEOUT,
                                            NSTACKX_FALSE, ServerSettingTimeoutHandle, peerInfo);
        if (peerInfo->settingTimer == NULL) {
            return;
        }
    }

    int32_t ret = DFileWriteHandle(buf, frameLen, peerInfo);
    if (ret != (int32_t)frameLen && ret != NSTACKX_EAGAIN) {
        data.errorCode = NSTACKX_EFAILED;
        NotifyMsgRecver(peerInfo->session, DFILE_ON_CONNECT_FAIL, &data);
    }
}

static void SetDFileSessionConfig(DFileSession *session, DFileConfig *dFileConfig, uint16_t connType,
    PeerInfo *peerInfo)
{
    peerInfo->maxSendRate = dFileConfig->sendRate;
    (void)memset_s(peerInfo->integralLossRate, INTEGRAL_TIME * sizeof(double), 0, INTEGRAL_TIME * sizeof(double));
    peerInfo->fastStartCounter = 0;
    ClockGetTime(CLOCK_MONOTONIC, &peerInfo->measureBefore);
    peerInfo->dataFrameSize = dFileConfig->dataFrameSize;
    if (connType == CONNECT_TYPE_WLAN) {
        peerInfo->sendRate = dFileConfig->sendRate / NSTACKX_WLAN_INIT_SPEED_DIVISOR;
    } else {
        peerInfo->sendRate = dFileConfig->sendRate / NSTACKX_P2P_INIT_SPEED_DIVISOR;
    }

#ifndef NSTACKX_WITH_LITEOS
    if ((!peerInfo->gotWifiRate) && (connType == CONNECT_TYPE_WLAN)) {
        peerInfo->sendRate = (uint16_t)(NSTACKX_WLAN_INIT_RATE / MSEC_TICKS_PER_SEC * DATA_FRAME_SEND_INTERVAL_MS
            / dFileConfig->dataFrameSize + NSTACKX_WLAN_COMPENSATION_RATE);
    }
#endif
    if (peerInfo->sendRate < NSTACKX_MIN_SENDRATE) {
        peerInfo->sendRate = NSTACKX_MIN_SENDRATE;
    }

    if (FileManagerSetMaxFrameLength(session->fileManager, peerInfo->dataFrameSize) != NSTACKX_EOK) {
        DFILE_LOGE(TAG, "failed to set max frame length");
    }

    DFILE_LOGI(TAG, "connType is %u set sendrate is %u maxSendRate is %u peerInfo->dataFrameSize is %u",
         connType, peerInfo->sendRate, peerInfo->maxSendRate, peerInfo->dataFrameSize);
    if (session->sessionType == DFILE_SESSION_TYPE_SERVER) {
        if (FileManagerSetRecvParaWithConnType(session->fileManager, connType) != NSTACKX_EOK) {
            DFILE_LOGE(TAG, "failed to set recv para");
        }
    }
}

static void DFileSessionSetPeerInfo(PeerInfo *peerInfo, SettingState state, SettingFrame *settingFrame)
{
    peerInfo->state = state;
    peerInfo->mtu = settingFrame->mtu;
    peerInfo->connType = settingFrame->connType;
    uint16_t localMtu = peerInfo->localMtu;
    peerInfo->mtuInuse = (localMtu < peerInfo->mtu) ? localMtu : peerInfo->mtu;
    peerInfo->remoteSessionId = settingFrame->header.sessionId;
}

static void DFileSessionHandleClientSetting(DFileSession *session, DFileFrame *dFileFrame, struct sockaddr_in *peerAddr)
{
    List *pos = NULL;
    SettingFrame hostSettingFrame;
    (void)memset_s(&hostSettingFrame, sizeof(hostSettingFrame), 0, sizeof(hostSettingFrame));
    DFILE_LOGI(TAG, "handle Setting Frame, DFileSessionType %u", session->sessionType);
    /* unsupport version */
    if (DecodeSettingFrame((SettingFrame *)dFileFrame, &hostSettingFrame) != NSTACKX_EOK || hostSettingFrame.mtu == 0) {
        return;
    }
    PeerInfo *peerInfo = SearchPeerInfoNode(session, peerAddr);
    if (peerInfo == NULL) {
        DFILE_LOGE(TAG, "recv unknown peer setting, maybe be attacked");
        return;
    }
    peerInfo->remoteDFileVersion = hostSettingFrame.dFileVersion;
    TimerDelete(peerInfo->settingTimer);
    peerInfo->settingTimer = NULL;
    DFileSessionSetPeerInfo(peerInfo, SETTING_NEGOTIATED, &hostSettingFrame);
    LIST_FOR_EACH(pos, &session->dFileTransChain) {
        DFileTrans *trans = (DFileTrans *)pos;
        if (DFileTransSetMtu(trans, peerInfo->mtuInuse) != NSTACKX_EOK) {
            DFILE_LOGE(TAG, "set trans mtu failed");
        }
    }
    DFileMsg data;
    (void)memset_s(&data, sizeof(data), 0, sizeof(data));
    data.errorCode = NSTACKX_EOK;
    NotifyMsgRecver(peerInfo->session, DFILE_ON_CONNECT_SUCCESS, &data);

    DFileConfig dFileConfig;
    (void)memset_s(&dFileConfig, sizeof(dFileConfig), 0, sizeof(dFileConfig));
    if (GetDFileConfig(&dFileConfig, peerInfo->mtuInuse, hostSettingFrame.connType) == NSTACKX_EOK) {
        SetDFileSessionConfig(session, &dFileConfig, hostSettingFrame.connType, peerInfo);
    }
    if (hostSettingFrame.capability & NSTACKX_CAPS_LINK_SEQUENCE) {
        DFILE_LOGI(TAG, "server replies not support Link Sequence");
    } else {
        DFILE_LOGI(TAG, "server replies using normal ACK");
        session->capability &= ~NSTACKX_CAPS_LINK_SEQUENCE;
    }
    DFileChooseCipherType(&hostSettingFrame, session);
}

static uint16_t DFileGetMTU(SocketProtocol protocol)
{
    /* for udp, return NSTACKX_DEFAULT_FRAME_SIZE, for D2D, need call D2D MTU interface */
    uint16_t mtu = 0;
    if (protocol == NSTACKX_PROTOCOL_UDP) {
        mtu = NSTACKX_DEFAULT_FRAME_SIZE;
    } else if (protocol == NSTACKX_PROTOCOL_D2D) {
        DFILE_LOGE(TAG, "d2d not support");
    } else if (protocol == NSTACKX_PROTOCOL_TCP) {
        mtu = NSTACKX_DEFAULT_FRAME_SIZE;
    }

    return mtu;
}

PeerInfo *CreatePeerInfo(DFileSession *session, const struct sockaddr_in *dstAddr, uint16_t peerMtu,
    uint16_t connType, uint8_t socketIndex)
{
    if (session->peerInfoCnt >= MAX_PEERINFO_SIZE) {
        return NULL;
    }
    PeerInfo *peerInfo = calloc(1, sizeof(PeerInfo));
    if (peerInfo == NULL) {
        return NULL;
    }
    peerInfo->session = session;
    peerInfo->dstAddr = *dstAddr;
    peerInfo->connType = connType;
    peerInfo->socketIndex = socketIndex;
    peerInfo->localMtu = DFileGetMTU(session->protocol);
    session->peerInfoCnt++;
    peerInfo->gotWifiRate = 0;
    peerInfo->ackInterval = NSTACKX_INIT_ACK_INTERVAL;
    peerInfo->rateStateInterval = NSTACKX_INIT_RATE_STAT_INTERVAL;

    if (GetInterfaceNameByIP(session->socket[socketIndex]->srcAddr.sin_addr.s_addr,
        peerInfo->localInterfaceName, sizeof(peerInfo->localInterfaceName)) != NSTACKX_EOK) {
        DFILE_LOGE(TAG, "GetInterfaceNameByIP failed %d", errno);
    }

    if (peerMtu == 0) {
        return peerInfo;
    }
    peerInfo->mtu = peerMtu;
    peerInfo->mtuInuse = (peerInfo->localMtu < peerInfo->mtu) ? peerInfo->localMtu : peerInfo->mtu;
    return peerInfo;
}

static void HandleLinkSeqCap(DFileSession *session, SettingFrame *hostSettingFrame)
{
    if (hostSettingFrame->capability & NSTACKX_CAPS_LINK_SEQUENCE) {
        DFILE_LOGI(TAG, "client wants to enable Link Sequence");
    } else {
        DFILE_LOGI(TAG, "client wants to use normal ACK");
        session->capability &= ~NSTACKX_CAPS_LINK_SEQUENCE;
    }

    if (hostSettingFrame->capability & NSTACKX_INTERNAL_CAPS_RECV_FEEDBACK) {
        DFILE_LOGI(TAG, "client support recv feedback");
        session->capsCheck |= NSTACKX_INTERNAL_CAPS_RECV_FEEDBACK;
    } else {
        DFILE_LOGI(TAG, "client do not support recv feedback");
        session->capsCheck &= ~NSTACKX_INTERNAL_CAPS_RECV_FEEDBACK;
    }
}

static PeerInfo *AllocPeerInfo(DFileSession *session, const struct sockaddr_in *peerAddr, const SettingFrame *frame,
    uint8_t socketIndex)
{
    PeerInfo *peerInfo = NULL;

    peerInfo = CreatePeerInfo(session, peerAddr, frame->mtu, frame->connType, socketIndex);
    if (peerInfo == NULL) {
        return NULL;
    }

    peerInfo->remoteSessionId = frame->header.sessionId;
    peerInfo->state = SETTING_NEGOTIATING;
    DFileSessionSendSetting(peerInfo);
    if (peerInfo->settingTimer == NULL) {
        free(peerInfo);
        session->peerInfoCnt--;
        return NULL;
    }
    ListInsertTail(&peerInfo->session->peerInfoChain, &peerInfo->list);
    return peerInfo;
}

static void DFileSessionHandleServerSetting(DFileSession *session, DFileFrame *dFileFrame,
    struct sockaddr_in *peerAddr, uint8_t socketIndex)
{
    SettingFrame hostSettingFrame;
    DFileConfig dFileConfig;
    (void)memset_s(&hostSettingFrame, sizeof(hostSettingFrame), 0, sizeof(hostSettingFrame));
    (void)memset_s(&dFileConfig, sizeof(dFileConfig), 0, sizeof(dFileConfig));
    DFILE_LOGI(TAG, "handle Setting Frame, DFileSessionType %u", session->sessionType);
    if (DecodeSettingFrame((SettingFrame *)dFileFrame, &hostSettingFrame) != NSTACKX_EOK || hostSettingFrame.mtu == 0) {
        return;
    }

    PeerInfo *peerInfo = SearchPeerInfoNode(session, peerAddr);
    if (peerInfo != NULL) {
        if (peerInfo->settingTimeoutCnt >= MAX_NEGOTIATE_TIMEOUT_COUNT) {
            DFILE_LOGE(TAG, "receive more than %d Setting for one peer, drop", MAX_NEGOTIATE_TIMEOUT_COUNT);
            return;
        } else {
            DFileSessionSetPeerInfo(peerInfo, SETTING_NEGOTIATING, &hostSettingFrame);
            DFileSessionSendSetting(peerInfo);
            goto L_END;
        }
    }

    peerInfo = AllocPeerInfo(session, peerAddr, &hostSettingFrame, socketIndex);
    if (peerInfo == NULL) {
        return;
    }

L_END:
    peerInfo->settingTimeoutCnt++;
    DFILE_LOGI(TAG, "DFileServer response Setting Frame. count %u", peerInfo->settingTimeoutCnt);
    peerInfo->remoteDFileVersion = hostSettingFrame.dFileVersion;
    if (GetDFileConfig(&dFileConfig, peerInfo->mtuInuse, hostSettingFrame.connType) == NSTACKX_EOK) {
        SetDFileSessionConfig(session, &dFileConfig, hostSettingFrame.connType, peerInfo);
    }
    HandleLinkSeqCap(session, &hostSettingFrame);
    DFileChooseCipherType(&hostSettingFrame, session);
}

static void DFileSessionHandleSetting(DFileSession *session, DFileFrame *dFileFrame,
    struct sockaddr_in *peerAddr, uint8_t socketIndex)
{
    if (session->sessionType == DFILE_SESSION_TYPE_SERVER) {
        DFileSessionHandleServerSetting(session, dFileFrame, peerAddr, socketIndex);
    } else if (session->sessionType == DFILE_SESSION_TYPE_CLIENT) {
        DFileSessionHandleClientSetting(session, dFileFrame, peerAddr);
    } else {
        return;
    }
}

static void HandleWithoutSettingError(DFileSession *session, const struct sockaddr_in *peerAddr)
{
    List *pos = NULL;
    DFileTrans *trans = NULL;

    PeerInfo *peerInfo = SearchPeerInfoNode(session, peerAddr);
    if (peerInfo == NULL) {
        DFILE_LOGE(TAG, "recv unknown peer rst, maybe be attacked");
        return;
    }

    LIST_FOR_EACH(pos, &session->dFileTransChain) {
        trans = (DFileTrans *)pos;
        /*
             * when client recv peer RST NSTACKX_DFILE_WITHOUT_SETTING_ERROR, Set Trans MTU 0,
             * and will reset after new setting negotion.
             */
        if (DFileTransSetMtu(trans, 0) != NSTACKX_EOK) {
            DFILE_LOGE(TAG, "DFileTransSetMtu(trans, 0) failed %d", errno);
        }
    }

    LIST_FOR_EACH(pos, &session->peerInfoChain) {
        peerInfo = (PeerInfo *)pos;
        if (memcmp(&peerInfo->dstAddr, peerAddr, sizeof(struct sockaddr_in)) == 0 &&
            peerInfo->session->sessionId == session->sessionId) {
            TimerDelete(peerInfo->settingTimer);
            peerInfo->settingTimer = NULL;
            peerInfo->state = SETTING_NEGOTIATING;
            DFILE_LOGD(TAG, "Send Setting Frame");
            DFileSessionSendSetting(peerInfo);
            break;
        }
    }
}

static void DFileSessionHandleRst(DFileSession *session, DFileFrame *dFileFrame, struct sockaddr_in *peerAddr)
{
    uint16_t errCode = 0;
    if (DecodeRstFrame((RstFrame *)dFileFrame, &errCode, NULL, NULL) != NSTACKX_EOK) {
        return;
    }

    uint16_t transId = ntohs(dFileFrame->header.transId);
    DFILE_LOGD(TAG, "handle RST (%hu) frame, transId %hu", errCode, transId);

    switch (errCode) {
        case NSTACKX_DFILE_WITHOUT_SETTING_ERROR:
            HandleWithoutSettingError(session, peerAddr);
            break;
        default:
            DFILE_LOGE(TAG, "Unspported error code %hu", errCode);
            break;
    }
}

static void DFileSessionResolveBackPress(DFileSession *session, DataBackPressure backPress, uint32_t count)
{
    uint32_t index;

    if (PthreadMutexLock(&session->backPressLock) != 0) {
        DFILE_LOGE(TAG, "pthread backPressLock mutex lock failed");
        return;
    }

    if (backPress.recvListOverIo == 1) {
        for (index = 0; index < count; index++) {
            session->stopSendCnt[index]++;
        }
    } else {
        for (index = 0; index < count; index++) {
            session->stopSendCnt[index] = 0;
        }
    }

    if (PthreadMutexUnlock(&session->backPressLock) != 0) {
        DFILE_LOGE(TAG, "pthread backPressLock mutex unlock failed");
        return;
    }

    return;
}

static void DFileSessionHandleBackPressure(DFileSession *session, const DFileFrame *dFileFrame,
    const struct sockaddr_in *peerAddr)
{
    DataBackPressure backPress;
    PeerInfo *peerInfo = SearchPeerInfoNode(session, peerAddr);
    if (peerInfo == NULL) {
        DFILE_LOGE(TAG, "can't get valid peerinfo");
        return;
    }

    if (DecodeBackPressFrame((BackPressureFrame *)dFileFrame, &backPress) != NSTACKX_EOK) {
        return;
    }

    DFileSessionResolveBackPress(session, backPress, session->clientSendThreadNum);

    DFILE_LOGI(TAG, "handle back pressure recvListOverIo %u recvBufThreshold %u stopSendPeriod %u",
         backPress.recvListOverIo, backPress.recvBufThreshold,
         backPress.stopSendPeriod);

    return;
}

static DFileTrans *CreateTrans(uint16_t transId, DFileSession *session, PeerInfo *peerInfo, uint8_t isSender)
{
    DFileTransPara transPara;

    if (peerInfo == NULL) {
        return NULL;
    }
    (void)memset_s(&transPara, sizeof(transPara), 0, sizeof(transPara));
    transPara.isSender = isSender;
    transPara.transId = transId; /* for receiver, use transId of sender */
    transPara.fileManager = session->fileManager;
    transPara.writeHandle = DFileWriteHandle;
    transPara.msgReceiver = DTransMsgReceiver;
    transPara.connType = peerInfo->connType;
    transPara.context = peerInfo;
    transPara.session = session;
    transPara.onRenameFile = session->onRenameFile;

    ClockGetTime(CLOCK_MONOTONIC, &peerInfo->startTime);
    return DFileTransCreate(&transPara);
}

static int32_t DFileSessionHandleFrame(DFileSession *session, DFileFrame *dFileFrame, struct sockaddr_in *peerAddr)
{
    PeerInfo *peerInfo = SearchPeerInfoNode(session, peerAddr);
    if (peerInfo == NULL) {
        DFILE_LOGI(TAG, "can't find peerInfo");
        return NSTACKX_EFAILED;
    }

    if (peerInfo->session->sessionType == DFILE_SESSION_TYPE_SERVER && peerInfo->state == SETTING_NEGOTIATING) {
        peerInfo->state = SETTING_NEGOTIATED;
        TimerDelete(peerInfo->settingTimer);
        peerInfo->settingTimer = NULL;
    }

    uint16_t transId = ntohs(dFileFrame->header.transId);
    if (transId == 0) {
        DFILE_LOGE(TAG, "transId is 0");
        return NSTACKX_EFAILED;
    }

    DFileTrans *trans = SearchDFileTransNode(&(session->dFileTransChain), transId);
    if (trans == NULL) {
        if (dFileFrame->header.type != NSTACKX_DFILE_FILE_HEADER_FRAME) {
            /* Only HEADER frame can start dfile transfer (receiver) */
            DFILE_LOGE(TAG, "trans %u is NULL && type is %u", transId, dFileFrame->header.type);
            return NSTACKX_EFAILED;
        }
        if (IsTransIdDone(session, transId) == NSTACKX_EOK) {
            return NSTACKX_EFAILED;
        }
        trans = CreateTrans(transId, session, peerInfo, NSTACKX_FALSE);
        if (trans == NULL) {
            DFileMsg data;
            (void)memset_s(&data, sizeof(data), 0, sizeof(data));
            data.errorCode = NSTACKX_ENOMEM;
            NotifyMsgRecver(session, DFILE_ON_FATAL_ERROR, &data);
            DFILE_LOGE(TAG, "trans is NULL");
            return NSTACKX_EFAILED;
        }
        if (DFileTransSetMtu(trans, peerInfo->mtuInuse) != NSTACKX_EOK) {
            DFILE_LOGE(TAG, "set trans mtu failed");
        }
        CalculateSessionTransferRatePrepare(session);
        ListInsertTail(&(session->dFileTransChain), &(trans->list));
        peerInfo->currentTransCount++;
    }

    return HandleDFileFrame(trans, dFileFrame);
}

int32_t DFileWriteHandle(const uint8_t *frame, size_t len, void *context)
{
    PeerInfo *peerInfo = context;
    DFileSession *session = peerInfo->session;
    QueueNode *queueNode = NULL;
    struct sockaddr_in peerAddr;

    peerAddr = peerInfo->dstAddr;
    queueNode = CreateQueueNode(frame, len, &peerAddr, peerInfo->socketIndex);
    if (queueNode == NULL) {
        return NSTACKX_ENOMEM;
    }

    if (PthreadMutexLock(&session->outboundQueueLock) != 0) {
        DFILE_LOGE(TAG, "pthread mutex lock failed");
        DestroyQueueNode(queueNode);
        return NSTACKX_EFAILED;
    }
    ListInsertTail(&session->outboundQueue, &queueNode->list);
    session->outboundQueueSize++;
    if (PthreadMutexUnlock(&session->outboundQueueLock) != 0) {
        /* Don't need to free node, as it's mount to outboundQueue */
        DFILE_LOGE(TAG, "pthread mutex unlock failed");
        return NSTACKX_EFAILED;
    }
    SemPost(&session->outboundQueueWait[peerInfo->socketIndex]);
    return (int32_t)len;
}

static void BindMainLoopToTargetCpu(void)
{
    int32_t cpu;
    int32_t cpus = GetCpuNum();
    if (cpus >= FIRST_CPU_NUM_LEVEL) {
        return;
    } else if (cpus >= THIRD_CPU_NUM_LEVEL) {
        cpu = CPU_IDX_0;
    } else {
        return;
    }
    StartThreadBindCore(cpu);
}

static int64_t GetEpollWaitTimeOut(DFileSession *session)
{
    int64_t minTimeout = DEFAULT_WAIT_TIME_MS;
    if (session->mainLoopActiveReadFlag && session->inboundQueueSize) {
        minTimeout = 0;
        return minTimeout;
    }
    List *pos = NULL;
    DFileTrans *trans = NULL;
    int64_t timeout;
    LIST_FOR_EACH(pos, &session->dFileTransChain) {
        trans = (DFileTrans *)pos;
        timeout = DFileTransGetTimeout(trans);
        if (timeout >= 0 && timeout < minTimeout) {
            minTimeout = timeout;
        }
    }
    if (minTimeout > DEFAULT_WAIT_TIME_MS) {
        minTimeout = DEFAULT_WAIT_TIME_MS;
    }
    return minTimeout;
}

static void ProcessSessionTrans(const DFileSession *session, uint16_t exceptTransId)
{
    List *tmp = NULL;
    List *pos = NULL;
    LIST_FOR_EACH_SAFE(pos, tmp, &session->dFileTransChain) {
        DFileTrans *trans = (DFileTrans *)pos;
        if (trans->transId != exceptTransId) {
            DFileTransProcess(trans);
        }
    }
}

static void NotifyBindPort(const DFileSession *session)
{
    DFileMsg data;
    int32_t socketNum;
    (void)memset_s(&data, sizeof(data), 0, sizeof(data));
    socketNum = 1;

    for (int i = 0; i < socketNum; i++) {
        data.sockAddr[i].sin_port = ntohs(session->socket[i]->srcAddr.sin_port);
        data.sockAddr[i].sin_addr.s_addr = ntohl(session->socket[i]->srcAddr.sin_addr.s_addr);
    }
    NotifyMsgRecver(session, DFILE_ON_BIND, &data);
}

void *DFileMainLoop(void *arg)
{
    DFileSession *session = arg;
    int32_t ret = NSTACKX_EOK;
    DFileMsg msgData;
    (void)memset_s(&msgData, sizeof(msgData), 0, sizeof(msgData));
    uint8_t isBind = NSTACKX_FALSE;
    DFILE_LOGI(TAG, "main thread start");
    SetThreadName(DFFILE_MAIN_THREAD_NAME);
    SetMaximumPriorityForThread();
    SetTidToBindInfo(session, POS_MAIN_THERD_START);
    NotifyBindPort(session);
    while (!session->closeFlag) {
        int64_t minTimeout = GetEpollWaitTimeOut(session);
        ret = EpollLoop(session->epollfd, (int32_t)minTimeout);
        if (ret == NSTACKX_EFAILED) {
            DFILE_LOGE(TAG, "epoll wait failed");
            break;
        }
        if (isBind == NSTACKX_FALSE && session->transFlag == NSTACKX_TRUE) {
            BindMainLoopToTargetCpu();
            isBind = NSTACKX_TRUE;
        }
        ProcessSessionTrans(session, 0);
        if (session->mainLoopActiveReadFlag && session->inboundQueueSize) {
            session->partReadFlag = NSTACKX_TRUE;
            ReadEventHandle(session);
            session->partReadFlag = NSTACKX_FALSE;
        }
    }

    if (ret == NSTACKX_EFAILED || DFileSessionCheckFatalFlag(session)) {
        msgData.errorCode = NSTACKX_EFAILED;
        NotifyMsgRecver(session, DFILE_ON_FATAL_ERROR, &msgData);
    }

    /* Notify sender thread to terminate */
    PostOutboundQueueWait(session);

    /* Unblock "select" and notify receiver thread to terminate */
    NotifyPipeEvent(session);
    return NULL;
}

static void AmendPeerInfoSendRate(PeerInfo *peerInfo)
{
    peerInfo->amendSendRate = peerInfo->sendRate;
    DFILE_LOGI(TAG, "current: sendrate %u, realsendframerate %u---new amendSendRate %d",
         peerInfo->sendRate, peerInfo->sendFrameRate, peerInfo->amendSendRate);
}

static void DFileSendCalculateRate(DFileSession *session, PeerInfo *peerInfo)
{
    uint64_t sendCount;

    if (session->sessionType != DFILE_SESSION_TYPE_CLIENT) {
        return;
    }

    struct timespec nowTime;
    ClockGetTime(CLOCK_MONOTONIC, &nowTime);
    uint64_t measureElapse = GetTimeDiffUs(&nowTime, &peerInfo->startTime);
    /* just calculate io rate */
    if (measureElapse > peerInfo->rateStateInterval) {
        /* ONLY PEER 0 calculate io rate */
        sendCount = (uint64_t)peerInfo->sendCount;
        if (peerInfo->socketIndex == 0) {
            session->fileManager->iorRate = (uint32_t)(session->fileManager->iorBytes *
                NSTACKX_MICRO_TICKS / measureElapse / DFILE_MEGABYTES);
            DFILE_LOGI(TAG, "IO read rate: %u MB/s send list full times %u", session->fileManager->iorRate,
                session->fileManager->sendListFullTimes);
            session->fileManager->sendListFullTimes = 0;
            session->fileManager->iorBytes = 0;
        }

        peerInfo->sendFrameRate = (uint32_t)(sendCount  * DATA_FRAME_SEND_INTERVAL_US / measureElapse);
        peerInfo->sendCountRateMB = (uint32_t)(sendCount * peerInfo->dataFrameSize *
            NSTACKX_MICRO_TICKS / measureElapse / DFILE_MEGABYTES);
        if (peerInfo->qdiscSearchNum != 0) {
            peerInfo->qdiscAveLeft = peerInfo->qdiscAveLeft / peerInfo->qdiscSearchNum;
        }

        DFILE_LOGI(TAG, "framesize %u maxsendrate %u sendRate %u, amendSendRate %d sendCount %llu,"
                  "measureElapse %llu sendFrameRate %u %uMB/s,"
                  "total send block num %llu eAgainCount %u send list empty times %u sleep times %u, noPendingData %u,"
                  "min qdisc %u max qdisc %u search num %u ave qdisc %u"
                  "totalRecvBlocks %llu socket:%u "
                  "overRun %llu maxRetryCountPerSec %u maxRetryCountLastSec %u wlanCatagory %u",
             peerInfo->dataFrameSize, peerInfo->maxSendRate, peerInfo->sendRate, peerInfo->amendSendRate,
             peerInfo->sendCount, measureElapse, peerInfo->sendFrameRate, peerInfo->sendCountRateMB,
             NSTACKX_ATOM_FETCH(&(session->totalSendBlocks)), peerInfo->eAgainCount,
             NSTACKX_ATOM_FETCH(&(session->sendBlockListEmptyTimes)), session->sleepTimes,
             NSTACKX_ATOM_FETCH(&(session->noPendingDataTimes)), peerInfo->qdiscMinLeft,
             peerInfo->qdiscMaxLeft, peerInfo->qdiscSearchNum, peerInfo->qdiscAveLeft,
             NSTACKX_ATOM_FETCH(&(session->totalRecvBlocks)), peerInfo->socketIndex,
             peerInfo->overRun, peerInfo->maxRetryCountPerSec, peerInfo->maxRetryCountLastSec, session->wlanCatagory);
        AmendPeerInfoSendRate(peerInfo);
        ClearSessionStats(session);
        ClearPeerinfoStats(peerInfo);
        ClockGetTime(CLOCK_MONOTONIC, &peerInfo->startTime);
    }
}

void UpdateAllTransRetryCount(DFileSession *session, PeerInfo *peerInfo)
{
    List *pos = NULL;
    DFileTrans *trans = NULL;
    uint32_t allRetryCount = 0;
    LIST_FOR_EACH(pos, &session->dFileTransChain) { /* for client , only one peer */
        trans = (DFileTrans *)pos;
        allRetryCount += trans->retryCount;
    }
    peerInfo->allDtransRetryCount = allRetryCount;
}

static void DFileRecvCalculateRate(DFileSession *session, DFileFrame *dFileFrame, struct sockaddr_in *peerAddr)
{
    struct timespec nowTime;
    uint64_t recvCount;
    uint32_t timeOut;

    if (session->sessionType != DFILE_SESSION_TYPE_SERVER ||
        dFileFrame->header.type != NSTACKX_DFILE_FILE_DATA_FRAME) {
        return;
    }

    PeerInfo *peerInfo = SearchPeerInfoNode(session, peerAddr);
    if (peerInfo == NULL) {
        return;
    }

    timeOut = (peerInfo->connType == CONNECT_TYPE_P2P) ? NSTACKX_P2P_MAX_CONTROL_FRAME_TIMEOUT :
        NSTACKX_WLAN_MAX_CONTROL_FRAME_TIMEOUT;

    peerInfo->recvCount++;
    ClockGetTime(CLOCK_MONOTONIC, &nowTime);
    uint64_t measureElapse = GetTimeDiffUs(&nowTime, &session->measureBefore);
    if (measureElapse > peerInfo->rateStateInterval) {
        session->fileManager->iowRate = (uint32_t)(session->fileManager->iowBytes *
            NSTACKX_MICRO_TICKS / measureElapse / DFILE_KILOBYTES);
        session->fileManager->iowCount = session->fileManager->iowBytes / peerInfo->dataFrameSize *
            (NSTACKX_MILLI_TICKS * timeOut - peerInfo->rateStateInterval) / measureElapse;
        if (session->fileManager->iowRate > session->fileManager->iowMaxRate) {
            session->fileManager->iowMaxRate = session->fileManager->iowRate;
        }
        DFILE_LOGI(TAG, "measureElapse %llu iowBytes %llu iowCount %llu IO write rate : %u KB/s", measureElapse,
             session->fileManager->iowBytes, session->fileManager->iowCount, session->fileManager->iowRate);
        session->fileManager->iowBytes = 0;
        ClockGetTime(CLOCK_MONOTONIC, &session->measureBefore);
    }

    measureElapse = GetTimeDiffUs(&nowTime, &peerInfo->startTime);
    if (measureElapse > peerInfo->rateStateInterval) {
        recvCount = (uint64_t)peerInfo->recvCount;
        peerInfo->recvFrameRate = (uint32_t)(recvCount * DATA_FRAME_SEND_INTERVAL_US / measureElapse);
        peerInfo->recvCountRateMB = (uint32_t)(recvCount * peerInfo->dataFrameSize *
            NSTACKX_MICRO_TICKS / measureElapse / DFILE_MEGABYTES);
        peerInfo->recvCount = 0;
        ClockGetTime(CLOCK_MONOTONIC, &peerInfo->startTime);
    }
}

static uint64_t CheckElapseTime(const struct timespec *before, uint64_t overRun)
{
    struct timespec now;
    ClockGetTime(CLOCK_MONOTONIC, &now);
    uint64_t elapseUs = GetTimeDiffUs(&now, before);
    elapseUs += overRun;
    if (elapseUs < DATA_FRAME_SEND_INTERVAL_US) {
        if (usleep((useconds_t)((uint64_t)DATA_FRAME_SEND_INTERVAL_US - elapseUs)) != NSTACKX_EOK) {
            DFILE_LOGE(TAG, "usleep(DATA_FRAME_SEND_INTERVAL_US - elapseUs) failed %d", errno);
        }
        return 0;
    } else {
        uint64_t delta = (elapseUs - DATA_FRAME_SEND_INTERVAL_US);
        return delta;
    }
}

static void BindClientSendThreadToTargetCpu(uint32_t idx)
{
    int32_t cpu;
    int32_t cpus = GetCpuNum();
    if (cpus >= FIRST_CPU_NUM_LEVEL) {
        return;
    } else if (cpus >= SECOND_CPU_NUM_LEVEL) {
        cpu = CPU_IDX_1 + (int32_t)idx;
    } else if (cpus >= THIRD_CPU_NUM_LEVEL) {
        cpu = CPU_IDX_1;
    } else {
        return;
    }
    if (cpu > cpus) {
        cpu = cpus - 1;
    }
    StartThreadBindCore(cpu);
}

static void DFileSenderUpdateMeasureTime(DFileSession *session, uint8_t socketIndex)
{
    if (session->sessionType == DFILE_SESSION_TYPE_CLIENT) {
        PeerInfo *peerInfo = ClientGetPeerInfoBySocketIndex(socketIndex, session);
        if (peerInfo == NULL) {
            return;
        }
        ClockGetTime(CLOCK_MONOTONIC, &peerInfo->startTime);
        BindClientSendThreadToTargetCpu(0);
    }
}

static void TerminateMainThreadFatalInner(void *arg)
{
    DFileSession *session = (DFileSession *)arg;
    DFileSessionSetFatalFlag(session);
}

static void PostFatalEvent(DFileSession *session)
{
    if (PostEvent(&session->eventNodeChain, session->epollfd, TerminateMainThreadFatalInner, session) != NSTACKX_EOK) {
        DFILE_LOGE(TAG, "PostEvent TerminateMainThreadFatalInner failed");
        DFileSessionSetFatalFlag(session);
    }
}

static uint32_t GetSocketWaitMs(uint32_t threadNum)
{
    if (threadNum > 1) {
        return MULTI_THREADS_SOCKET_WAIT_TIME_MS;
    }
    return DEFAULT_WAIT_TIME_MS;
}

static void SetSendThreadName(uint32_t threadIdx)
{
    char name[MAX_THREAD_NAME_LEN] = {0};
    if (sprintf_s(name, sizeof(name), "%s%u", DFFILE_SEND_THREAD_NAME_PREFIX, threadIdx) < 0) {
        DFILE_LOGE(TAG, "sprintf send thead name failed");
    }
    SetThreadName(name);
}

typedef struct {
    struct DFileSession *session;
    uint32_t threadIdx;
}SendThreadCtx;

static void *DFileAddiSenderHandle(void *arg)
{
    SendThreadCtx *sendThreadCtx = (SendThreadCtx *)arg;
    struct DFileSession *session = sendThreadCtx->session;
    uint32_t threadIdx = sendThreadCtx->threadIdx;
    free(sendThreadCtx);
    int32_t ret = NSTACKX_EOK;
    DFILE_LOGI(TAG, "send thread %u start", threadIdx);
    SetSendThreadName(threadIdx);
    SetTidToBindInfo(session, threadIdx + POS_SEND_THERD_START);
    List unsent;
    uint8_t canWrite = NSTACKX_FALSE;
    uint32_t socketWaitMs = GetSocketWaitMs(session->clientSendThreadNum);
    BindClientSendThreadToTargetCpu(threadIdx + 1);
    ListInitHead(&unsent);
    while (!session->addiSenderCloseFlag) {
        if (ListIsEmpty(&unsent) && !FileManagerHasPendingData(session->fileManager)) {
            NSTACKX_ATOM_FETCH_INC(&session->noPendingDataTimes);
            SemWait(&session->sendThreadPara[threadIdx].sendWait);
            if (session->addiSenderCloseFlag) {
                break;
            }
        }
        if (ret == NSTACKX_EAGAIN) {
            ret = WaitSocketEvent(NULL, session->socket[0]->sockfd, socketWaitMs, NULL, &canWrite);
            if (ret != NSTACKX_EOK || session->closeFlag) {
                break;
            }
            if (!canWrite) {
                ret = NSTACKX_EAGAIN;
                continue;
            }
        }
        ret = SendDataFrame(session, &unsent, threadIdx, 0);
        if ((ret < 0 && ret != NSTACKX_EAGAIN) || session->closeFlag) {
            break;
        }
        if (ret == NSTACKX_EAGAIN) {
            continue;
        }
        SemWait(&session->sendThreadPara[threadIdx].semNewCycle);
    }
    if (ret < 0 && ret != NSTACKX_EAGAIN) {
        PostFatalEvent(session);
    }
    DestroyIovList(&unsent, session, threadIdx);
    return NULL;
}

static void CloseAddiSendThread(struct DFileSession *session)
{
    if (session->sessionType == DFILE_SESSION_TYPE_SERVER || session->clientSendThreadNum <= 1) {
        return;
    }
    session->addiSenderCloseFlag = NSTACKX_TRUE;
    for (uint16_t i = 0; i < session->clientSendThreadNum - 1; i++) {
        SemPost(&session->sendThreadPara[i].sendWait);
        SemPost(&session->sendThreadPara[i].semNewCycle);
        PthreadJoin(session->sendThreadPara[i].senderTid, NULL);
        SemDestroy(&session->sendThreadPara[i].sendWait);
        SemDestroy(&session->sendThreadPara[i].semNewCycle);
    }
}

static void ErrorHandle(struct DFileSession *session, uint16_t cnt)
{
    while (cnt > 0) {
        SemPost(&session->sendThreadPara[cnt - 1].sendWait);
        SemPost(&session->sendThreadPara[cnt - 1].semNewCycle);
        PthreadJoin(session->sendThreadPara[cnt - 1].senderTid, NULL);
        SemDestroy(&session->sendThreadPara[cnt - 1].sendWait);
        SemDestroy(&session->sendThreadPara[cnt - 1].semNewCycle);
        cnt--;
    }
}

static int32_t CreateAddiSendThread(struct DFileSession *session)
{
    uint16_t i;
    if (session->sessionType == DFILE_SESSION_TYPE_SERVER || session->clientSendThreadNum <= 1) {
        return NSTACKX_EOK;
    }
    session->addiSenderCloseFlag = NSTACKX_FALSE;
    for (i = 0; i < session->clientSendThreadNum - 1; i++) {
        SendThreadCtx *sendThreadCtx = (SendThreadCtx *)calloc(1, sizeof(SendThreadCtx));
        if (sendThreadCtx == NULL) {
            goto L_ERR_SENDER_THREAD;
        }

        if (SemInit(&session->sendThreadPara[i].sendWait, 0, 0) != 0) {
            free(sendThreadCtx);
            goto L_ERR_SENDER_THREAD;
        }

        if (SemInit(&session->sendThreadPara[i].semNewCycle, 0, 0) != 0) {
            SemDestroy(&session->sendThreadPara[i].sendWait);
            free(sendThreadCtx);
            goto L_ERR_SENDER_THREAD;
        }

        sendThreadCtx->session = session;
        sendThreadCtx->threadIdx = i;
        if (PthreadCreate(&(session->sendThreadPara[i].senderTid), NULL, DFileAddiSenderHandle, sendThreadCtx)) {
            DFILE_LOGE(TAG, "Create sender thread failed");
            SemDestroy(&session->sendThreadPara[i].sendWait);
            SemDestroy(&session->sendThreadPara[i].semNewCycle);
            free(sendThreadCtx);
            goto L_ERR_SENDER_THREAD;
        }
    }
    return NSTACKX_EOK;

L_ERR_SENDER_THREAD:
    session->addiSenderCloseFlag = NSTACKX_TRUE;
    ErrorHandle(session, i);
    return NSTACKX_EFAILED;
}

static void UpdatePeerinfoQdiscInfo(PeerInfo *peerInfo, uint32_t qDiscLeft)
{
    if (peerInfo->qdiscMinLeft == 0) {
        peerInfo->qdiscMinLeft = (uint16_t)qDiscLeft;
    } else if (peerInfo->qdiscMinLeft > qDiscLeft) {
        peerInfo->qdiscMinLeft = (uint16_t)qDiscLeft;
    }
    if (peerInfo->qdiscMaxLeft < qDiscLeft) {
        peerInfo->qdiscMaxLeft = (uint16_t)qDiscLeft;
    }
    peerInfo->qdiscSearchNum++;
    peerInfo->qdiscAveLeft += qDiscLeft;
}

static void UpdatePeerinfoAmendSendrateByQdisc(PeerInfo *peerInfo)
{
    uint32_t qDiscLeft;
    uint32_t qDiscLeftSendRate;

    if (GetQdiscLen(peerInfo->localInterfaceName, ROOT_QUEUE, &qDiscLeft) == NSTACKX_EOK) {
        if (peerInfo->mtuInuse == 0) {
            return;
        }
        uint32_t mtuNumInOneFrame = peerInfo->dataFrameSize / peerInfo->mtuInuse;
        if (mtuNumInOneFrame == 0) {
            mtuNumInOneFrame = 1;
        }
        UpdatePeerinfoQdiscInfo(peerInfo, qDiscLeft);
        qDiscLeftSendRate = qDiscLeft / mtuNumInOneFrame;
        if (peerInfo->sendRate >= qDiscLeftSendRate) {
            peerInfo->amendSendRate = (int32_t)qDiscLeftSendRate;
        } else {
            peerInfo->amendSendRate = peerInfo->sendRate;
        }
    }
    return;
}

static void UpdateInfoAfterSend(DFileSession *session, PeerInfo *peerInfo, int32_t curAmendSendRate,
    struct timespec *before, uint8_t socketIndex)
{
    session->cycleRunning[socketIndex] = NSTACKX_FALSE;
    if (curAmendSendRate > 0 && peerInfo->intervalSendCount >= (uint32_t)curAmendSendRate) {
        if (peerInfo->decreaseStatus == 1) {
            peerInfo->overRun = 0;
            peerInfo->decreaseStatus = 0;
        }
        peerInfo->overRun = CheckElapseTime(before, peerInfo->overRun);
        if (peerInfo->overRun == 0) {
            session->sleepTimes++;
        }
    }
    peerInfo->intervalSendCount = 0;

    UpdatePeerinfoAmendSendrateByQdisc(peerInfo);
}

static int32_t DFileSessionSendFrame(DFileSession *session, QueueNode **preQueueNode, List *unsent,
                                     struct timespec *before, uint8_t socketIndex)
{
    int32_t ret;

    if (CapsTcp(session) && !ListIsEmpty(unsent)) {
        session->sendRemain = 1;
        ret = SendDataFrame(session, unsent, (uint32_t)(session->clientSendThreadNum - 1), socketIndex);
        session->sendRemain = 0;
        if ((ret == NSTACKX_EFAILED || ret == NSTACKX_EAGAIN) || session->closeFlag) {
            DFILE_LOGI(TAG, "ret is %d", ret);
            return ret;
        }
    }

    ret = SendOutboundFrame(session, preQueueNode);
    if (session->sessionType != DFILE_SESSION_TYPE_CLIENT) {
        return ret;
    }
    PeerInfo *peerInfo = ClientGetPeerInfoBySocketIndex(socketIndex, session);
    if (peerInfo == NULL) {
        DFILE_LOGE(TAG, "can't get valid peerinfo");
        return NSTACKX_EFAILED;
    }
    if (peerInfo->mtuInuse == 0) {
        return ret;
    }

    if (ret == NSTACKX_EOK) {
        if (!session->cycleRunning[socketIndex]) {
            session->cycleRunning[socketIndex] = NSTACKX_TRUE;
        }
        ret = SendDataFrame(session, unsent, (uint32_t)(session->clientSendThreadNum - 1), socketIndex);
    }
    int32_t curAmendSendRate = peerInfo->amendSendRate;
    DFileSendCalculateRate(session, peerInfo);

    if ((ret == NSTACKX_EFAILED || ret == NSTACKX_EAGAIN) || session->closeFlag) {
        DFILE_LOGI(TAG, "ret is %d and peerInfo->intervalSendCount is %u", ret, peerInfo->intervalSendCount);
        return ret;
    }

    UpdateInfoAfterSend(session, peerInfo, curAmendSendRate, before, socketIndex);

    for (uint16_t i = 0; i < session->clientSendThreadNum - 1; i++) {
        SemPost(&session->sendThreadPara[i].semNewCycle);
    }
    return ret;
}

static void WaitNewSendData(const QueueNode *queueNode, const List *unsent, DFileSession *session, uint8_t socketIndex)
{
    if (queueNode == NULL && ListIsEmpty(unsent) && !FileManagerHasPendingData(session->fileManager) &&
        !session->outboundQueueSize) {
        NSTACKX_ATOM_FETCH_INC(&session->noPendingDataTimes);
        SemWait(&session->outboundQueueWait[socketIndex]);
    }
}

static void DFileSenderPre(DFileSession *session, uint8_t socketIndex)
{
    SetSendThreadName((uint32_t)(session->clientSendThreadNum + socketIndex - 1));
    DFileSenderUpdateMeasureTime(session, socketIndex);
    SetMaximumPriorityForThread();
    uint32_t pos = (uint32_t)(session->clientSendThreadNum - 1 + socketIndex + POS_SEND_THERD_START);
    if (pos >= POS_SEND_THERD_START + NSTACKX_MAX_CLIENT_SEND_THREAD_NUM) {
        return;
    }

    SetTidToBindInfo(session, pos);
}

void DFileSenderClose(DFileSession *session, QueueNode *queueNode, List *unsent, void *arg)
{
    DFILE_LOGI(TAG, "DFileSendCalculateRate: total send block num %llu.", session->totalSendBlocks);
    CloseAddiSendThread(session);
    DestroyIovList(unsent, session, session->clientSendThreadNum - 1U);
    DestroyQueueNode(queueNode);
    free(arg);
    return;
}

void *DFileSenderHandle(void *arg)
{
    DFileSession *session = ((SenderThreadPara*)arg)->session;
    uint8_t socketIndex = ((SenderThreadPara*)arg)->socketIndex;
    QueueNode *queueNode = NULL;
    List unsent;
    int32_t ret = NSTACKX_EOK;
    struct timespec before;
    uint8_t canWrite = NSTACKX_FALSE;
    uint32_t socketWaitMs = GetSocketWaitMs(session->clientSendThreadNum);
    uint8_t isBind = NSTACKX_FALSE;

    if (CreateAddiSendThread(session) != NSTACKX_EOK) {
        PostFatalEvent(session);
        return NULL;
    }
    ListInitHead(&unsent);
    DFileSenderPre(session, socketIndex);
    while (!session->closeFlag) {
        WaitNewSendData(queueNode, &unsent, session, socketIndex);
        if (session->closeFlag) {
            break;
        }
        if (!session->cycleRunning[socketIndex]) {
            ClockGetTime(CLOCK_MONOTONIC, &before);
        }
        if (ret == NSTACKX_EAGAIN) {
            ret = WaitSocketEvent(NULL, session->socket[socketIndex]->sockfd, socketWaitMs, NULL, &canWrite);
            if (ret != NSTACKX_EOK || session->closeFlag) {
                break;
            }
            if (!canWrite) {
                ret = NSTACKX_EAGAIN;
                continue;
            }
        }
        if (session->sessionType == DFILE_SESSION_TYPE_CLIENT && isBind == NSTACKX_FALSE &&
            session->transFlag == NSTACKX_TRUE) {
            BindClientSendThreadToTargetCpu(0);
            isBind = NSTACKX_TRUE;
        }
        ret = DFileSessionSendFrame(session, &queueNode, &unsent, &before, socketIndex);
        if (ret < 0 && ret != NSTACKX_EAGAIN) {
            PeerShuttedEvent();
            PostFatalEvent(session);
            break;
        }
    }
    DFileSenderClose(session, queueNode, &unsent, arg);
    return NULL;
}

static void ClearDFileFrameList(List *head)
{
    if (head == NULL || ListIsEmpty(head)) {
        return;
    }
    List *tmp = NULL;
    List *pos = NULL;
    LIST_FOR_EACH_SAFE(pos, tmp, head) {
        QueueNode *node = (QueueNode *)pos;
        ListRemoveNode(&node->list);
        DestroyQueueNode(node);
    }
}

static inline int32_t CheckDfileType(uint8_t type)
{
    if (type >= NSTACKX_DFILE_TYPE_MAX || type < NSTACKX_DFILE_FILE_HEADER_FRAME) {
        return NSTACKX_EFAILED;
    }
    return NSTACKX_EOK;
}

static inline int32_t CheckSessionType(DFileSessionType type)
{
    if (type < DFILE_SESSION_TYPE_CLIENT || type > DFILE_SESSION_TYPE_SERVER) {
        return NSTACKX_EFAILED;
    }
    return NSTACKX_EOK;
}

static void ProcessDFileFrameList(DFileSession *session, List *head)
{
    QueueNode *queueNode = NULL;
    DFileFrame *dFileFrame = NULL;
    struct sockaddr_in *peerAddr = NULL;
    int32_t handleFrameRet = NSTACKX_EOK;
    while (!ListIsEmpty(head) && !session->closeFlag) {
        queueNode = (QueueNode *)ListPopFront(head);
        if (queueNode == NULL) {
            continue;
        }
        dFileFrame = (DFileFrame *)(queueNode->frame);
        peerAddr = &queueNode->peerAddr;
        uint8_t type = dFileFrame->header.type;

        if (ntohs(dFileFrame->header.length) > NSTACKX_MAX_FRAME_SIZE - sizeof(DFileFrameHeader)) {
            DFILE_LOGE(TAG, "header length %u is too big", ntohs(dFileFrame->header.length));
            DestroyQueueNode(queueNode);
            continue;
        }
        if (CheckDfileType(dFileFrame->header.type) != NSTACKX_EOK ||
            CheckSessionType(session->sessionType) != NSTACKX_EOK) {
            handleFrameRet = NSTACKX_EFAILED;
        } else if (dFileFrame->header.type == NSTACKX_DFILE_SETTING_FRAME) {
            DFileSessionHandleSetting(session, dFileFrame, peerAddr, queueNode->socketIndex);
        } else if (dFileFrame->header.type == NSTACKX_DFILE_RST_FRAME &&
                   dFileFrame->header.transId == 0) {
            DFileSessionHandleRst(session, dFileFrame, peerAddr);
        } else if (dFileFrame->header.type == NSTACKX_DFILE_FILE_BACK_PRESSURE_FRAME) {
            DFileSessionHandleBackPressure(session, dFileFrame, peerAddr);
        } else {
            /*
             * For NSTACKX_DFILE_FILE_DATA_FRAME, "dFileFrame" may be free when handling failed, and become invalid.
             */
            handleFrameRet = DFileSessionHandleFrame(session, dFileFrame, peerAddr);
        }

        if (handleFrameRet != NSTACKX_EOK || type != NSTACKX_DFILE_FILE_DATA_FRAME) {
            /* For FILE_DATA frame, the memory is passed to file manager. */
            free(queueNode->frame);
            queueNode->frame = NULL;
        }
        free(queueNode);
    }
    ClearDFileFrameList(head);
}

static void ReadEventHandle(void *arg)
{
    DFileSession *session = arg;
    List newHead;
    ListInitHead(&newHead);
    struct timespec before, now;
    if (!session->partReadFlag) {
        NSTACKX_ATOM_FETCH_DEC(&session->unprocessedReadEventCount);
    } else {
        ClockGetTime(CLOCK_MONOTONIC, &before);
    }
    while (session->inboundQueueSize && !session->closeFlag) {
        if (session->partReadFlag) {
            ClockGetTime(CLOCK_MONOTONIC, &now);
            if (GetTimeDiffMs(&now, &before) >= DEFAULT_WAIT_TIME_MS) {
                break;
            }
        }
        if (PthreadMutexLock(&session->inboundQueueLock) != 0) {
            DFILE_LOGE(TAG, "PthreadMutexLock error");
            return;
        }
        ListMove(&session->inboundQueue, &newHead);
        session->recvBlockNumInner += session->inboundQueueSize;
        session->inboundQueueSize = 0;
        if (PthreadMutexUnlock(&session->inboundQueueLock) != 0) {
            DFILE_LOGE(TAG, "PthreadMutexUnlock error");
            break;
        }
        ProcessDFileFrameList(session, &newHead);
    }
    ClearDFileFrameList(&newHead);
}

static int32_t DFileAddInboundQueue(DFileSession *session, const uint8_t *frame, size_t frameLength,
                                    struct sockaddr_in *peerAddr, uint8_t socketIndex)
{
    if (session->inboundQueueSize > MAX_RECVBUF_COUNT) {
        if (session->inboundQueueSize % MAX_NOMEM_PRINT == 0) {
            DFILE_LOGI(TAG, "no mem inboundQueueSize:%llu", session->inboundQueueSize);
        }
        return NSTACKX_ENOMEM;
    }
    QueueNode *queueNode = CreateQueueNode(frame, frameLength, peerAddr, socketIndex);
    if (queueNode == NULL) {
        return NSTACKX_ENOMEM;
    }

    if (PthreadMutexLock(&session->inboundQueueLock) != 0) {
        DestroyQueueNode(queueNode);
        return NSTACKX_EFAILED;
    }
    ListInsertTail(&session->inboundQueue, &queueNode->list);
    session->inboundQueueSize++;
    session->recvBlockNumDirect++;

    if (PthreadMutexUnlock(&session->inboundQueueLock) != 0) {
        /* queue node is pushed to list, don't need destroy here. */
        return NSTACKX_EFAILED;
    }

    return NSTACKX_EOK;
}

static void DFileReceiverUpdateSessionMeasureTime(DFileSession *session)
{
    if (session->sessionType == DFILE_SESSION_TYPE_SERVER) {
        ClockGetTime(CLOCK_MONOTONIC, &session->measureBefore);
    }
}

static void BindServerRecvThreadToTargetCpu(DFileSession *session)
{
    int32_t cpu;
    int32_t cpus = GetCpuNum();
    if (session->sessionType != DFILE_SESSION_TYPE_SERVER) {
        cpu = CPU_IDX_2;
        StartThreadBindCore(cpu);
        return;
    }
    if (cpus >= FIRST_CPU_NUM_LEVEL) {
        return;
    } else if (cpus >= SECOND_CPU_NUM_LEVEL) {
        cpu = CPU_IDX_1;
    } else if (cpus >= THIRD_CPU_NUM_LEVEL) {
        cpu = CPU_IDX_0;
    } else {
        return;
    }
    StartThreadBindCore(cpu);
}

static void PostReadEventToMainLoop(DFileSession *session)
{
    if (NSTACKX_ATOM_FETCH(&(session->unprocessedReadEventCount)) >= MAX_UNPROCESSED_READ_EVENT_COUNT) {
        return;
    }
    NSTACKX_ATOM_FETCH_INC(&session->unprocessedReadEventCount);
    if (PostEvent(&session->eventNodeChain, session->epollfd, ReadEventHandle, session) != NSTACKX_EOK) {
        DFILE_LOGE(TAG, "post read event failed");
        NSTACKX_ATOM_FETCH_DEC(&session->unprocessedReadEventCount);
        session->mainLoopActiveReadFlag = NSTACKX_TRUE;
    } else {
        session->mainLoopActiveReadFlag = NSTACKX_FALSE;
    }
}

int32_t DFileSessionHandleReadBuffer(DFileSession *session, const uint8_t *buf, size_t bufLen,
                                     struct sockaddr_in *peerAddr, uint8_t socketIndex)
{
    DFileFrame *dFileFrame = NULL;
    if (DecodeDFileFrame(buf, bufLen, &dFileFrame) != NSTACKX_EOK) {
        /* discard packet with non-zero trans id during cancel stage */
        DFILE_LOGE(TAG, "drop malformed frame");
        return NSTACKX_EOK;
    }

    int32_t ret = DFileAddInboundQueue(session, buf, bufLen, peerAddr, socketIndex);
    if (ret == NSTACKX_ENOMEM) {
        return NSTACKX_EOK;
    }
    if (ret != NSTACKX_EOK) {
        DFILE_LOGE(TAG, "frame add in bound queue failed :%d", ret);
        return NSTACKX_EFAILED;
    }
    PostReadEventToMainLoop(session);
    DFileRecvCalculateRate(session, dFileFrame, peerAddr);
    return NSTACKX_EOK;
}

static void DFileRecverPre(DFileSession *session)
{
    SetThreadName(DFFILE_RECV_THREAD_NAME);
    DFileReceiverUpdateSessionMeasureTime(session);
    SetMaximumPriorityForThread();
    SetTidToBindInfo(session, POS_RECV_THERD_START);
}

int32_t RcverWaitSocket(DFileSession *session, uint8_t *canRead)
{
    if (session->acceptFlag == 0) {
        return WaitSocketEvent(session, session->socket[0]->sockfd, DEFAULT_WAIT_TIME_MS, canRead, NULL);
    } else {
        return WaitSocketEvent(session, session->acceptSocket->sockfd, DEFAULT_WAIT_TIME_MS, canRead, NULL);
    }
}

int32_t DFileSocketRecv(DFileSession *session)
{
    return DFileSocketRecvSP(session);
}

int32_t DFileAcceptSocket(DFileSession *session)
{
    session->acceptSocket = AcceptSocket(session->socket[0]);
    if (session->acceptSocket == NULL) {
        DFILE_LOGI(TAG, "accept socket failed");
        return NSTACKX_EFAILED;
    } else {
        DFILE_LOGI(TAG, "accept socket success");
        session->acceptFlag = 1;
        SetTcpKeepAlive(session->acceptSocket->sockfd);
    }

    AcceptSocketEvent();

    return NSTACKX_EOK;
}

void *DFileReceiverHandle(void *arg)
{
    DFileSession *session = arg;
    uint8_t canRead = NSTACKX_FALSE;
    int32_t ret = NSTACKX_EAGAIN;
    uint8_t isBind = NSTACKX_FALSE;

    DFILE_LOGI(TAG, "recv thread start");
    DFileRecverPre(session);
    while (!session->closeFlag) {
        if (ret == NSTACKX_EAGAIN || !canRead) {
            ret = RcverWaitSocket(session, &canRead);
            if (ret != NSTACKX_EOK || session->closeFlag) {
                break;
            }
        }
        if (!canRead) {
            continue;
        }
        if (isBind == NSTACKX_FALSE && session->transFlag == NSTACKX_TRUE) {
            BindServerRecvThreadToTargetCpu(session);
            isBind = NSTACKX_TRUE;
        }

        ret = DFileSocketRecv(session);
        if (ret != NSTACKX_EAGAIN && ret != NSTACKX_EOK) {
            PeerShuttedEvent();
            break;
        }
    }
    DFILE_LOGI(TAG, "Total recv blocks: direct %llu inner %llu", session->recvBlockNumDirect,
            session->recvBlockNumInner);
    if (ret < 0 && ret != NSTACKX_EAGAIN && ret != NSTACKX_PEER_CLOSE) {
        PostFatalEvent(session);
    }

    DFILE_LOGI(TAG, "session %u Exit receiver thread ret %d", session->sessionId, ret);
    return NULL;
}

void *DFileControlHandle(void *arg)
{
    SetThreadName(DFFILE_CONTROL_THREAD_NAME);
    DFileSession *session = arg;
    if (session->sessionType == DFILE_SESSION_TYPE_CLIENT) {
        DFileSenderControlHandle(session);
    } else {
        DFileReceiverControlHandle(session);
    }
    return NULL;
}

static int32_t RealPathFileName(FileListInfo *fileListInfo)
{
    uint32_t i;
    int32_t ret = NSTACKX_EOK;
    for (i = 0; i < fileListInfo->fileNum; i++) {
        char *tmpFileName = fileListInfo->files[i];
        char *tmpFileNameRes = realpath(tmpFileName, NULL);
        if (tmpFileNameRes == NULL) {
            ret = NSTACKX_EFAILED;
            break;
        }
        fileListInfo->files[i] = tmpFileNameRes;
        free(tmpFileName);
    }
    if (ret != NSTACKX_EOK) {
        DFILE_LOGE(TAG, "realpath failed");
    }
    return ret;
}

static void FreeTransFileListInfo(FileListInfo *fileListInfo)
{
    free(fileListInfo->files);
    fileListInfo->files = NULL;
    if (fileListInfo->remotePath != NULL) {
        free(fileListInfo->remotePath);
        fileListInfo->remotePath = NULL;
    }
    free(fileListInfo);
}

static int32_t DFileStartTransInner(DFileSession *session, FileListInfo *fileListInfo)
{
    uint16_t transId = session->lastDFileTransId + 1;
    if (transId == 0) { /* overflow */
        transId = 1;
    }

    PeerInfo *peerInfo = TransSelectPeerInfo(session);
    DFileTrans *trans = CreateTrans(transId, session, peerInfo, NSTACKX_TRUE);
    if (trans == NULL) {
        DFILE_LOGE(TAG, "CreateTrans error");
        return NSTACKX_ENOMEM;
    }

    if (DFileTransSetMtu(trans, peerInfo->mtuInuse) != NSTACKX_EOK) {
        DFILE_LOGE(TAG, "set trans mtu failed");
    }
    if (RealPathFileName(fileListInfo) != NSTACKX_EOK) {
        DFileTransDestroy(trans);
        return NSTACKX_EFAILED;
    }
    int32_t ret = DFileTransSendFiles(trans, fileListInfo);
    if (ret != NSTACKX_EOK) {
        DFileTransDestroy(trans);
        DFILE_LOGE(TAG, "DFileTransSendFiles fail, error: %d", ret);
        return ret;
    }
    ret = DFileTransAddExtraInfo(trans, fileListInfo->pathType, fileListInfo->noticeFileNameType,
                                 fileListInfo->userData);
    if (ret != NSTACKX_EOK) {
        DFILE_LOGE(TAG, "DFileTransAddExtraInfo fail");
        DFileTransDestroy(trans);
        return NSTACKX_EFAILED;
    }
    trans->fileList->tarFlag = fileListInfo->tarFlag;
    trans->fileList->smallFlag = fileListInfo->smallFlag;
    trans->fileList->tarFile = fileListInfo->tarFile;
    trans->fileList->noSyncFlag = fileListInfo->noSyncFlag;

    fileListInfo->userData = NULL;
    ListInsertTail(&(session->dFileTransChain), &(trans->list));
    session->lastDFileTransId = transId;
    if (fileListInfo->smallFlag == NSTACKX_TRUE) {
        session->smallListProcessingCnt++;
    } else {
        session->fileListProcessingCnt++;
    }
    /* Elements in ctx->fileListInfo->files[] are reused by dFileTranns, so don't need to free. */
    FreeTransFileListInfo(fileListInfo);
    return NSTACKX_EOK;
}

int32_t DFileStartTrans(DFileSession *session, FileListInfo *fileListInfo)
{
    if (PthreadMutexLock(&session->transIdLock) != 0) {
        DFILE_LOGE(TAG, "pthread mutex lock error");
        return NSTACKX_EFAILED;
    }
    int32_t ret = DFileStartTransInner(session, fileListInfo);
    if (PthreadMutexUnlock(&session->transIdLock) != 0) {
        DFILE_LOGE(TAG, "pthread mutex unlock error");
    }
    return ret;
}

void TerminateMainThreadInner(void *arg)
{
    DFileSession *session = (DFileSession *)arg;
    DFileSessionSetTerminateFlag(session);
}

int32_t StartDFileThreadsInner(DFileSession *session)
{
    if (PthreadCreate(&(session->tid), NULL, DFileMainLoop, session)) {
        DFILE_LOGE(TAG, "Create mainloop thread failed");
        goto L_ERR_MAIN_LOOP_THREAD;
    }

    if (CreateSenderThread(session) != NSTACKX_EOK) {
        goto L_ERR_SENDER_THREAD;
    }

    if (PthreadCreate(&(session->receiverTid), NULL, DFileReceiverHandle, session)) {
        DFILE_LOGE(TAG, "Create receiver thread failed");
        goto L_ERR_RECEIVER_THREAD;
    }

    if (PthreadCreate(&(session->controlTid), NULL, DFileControlHandle, session)) {
        DFILE_LOGE(TAG, "Create control thread failed");
        goto L_ERR_CONTROL_THREAD;
    }
    return NSTACKX_EOK;
L_ERR_CONTROL_THREAD:
    DFileSessionSetTerminateFlag(session);
    PthreadJoin(session->controlTid, NULL);
    session->receiverTid = INVALID_TID;
L_ERR_RECEIVER_THREAD:
    DFileSessionSetTerminateFlag(session);
    PthreadJoin(session->senderTid[0], NULL);
    session->senderTid[0] = INVALID_TID;
    PostOutboundQueueWait(session);
L_ERR_SENDER_THREAD:
    DFileSessionSetTerminateFlag(session);
    if (PostEvent(&session->eventNodeChain, session->epollfd, TerminateMainThreadInner, session) != NSTACKX_EOK) {
        DFILE_LOGE(TAG, "post terminate thread failed");
    }
    PthreadJoin(session->tid, NULL);
    session->tid = INVALID_TID;
L_ERR_MAIN_LOOP_THREAD:
    return NSTACKX_EFAILED;
}

static void FileManagerMsgHandle(FileManagerMsgType msgType, int32_t errCode, void *context)
{
    DFileSession *session = context;
    if (msgType == FILE_MANAGER_INNER_ERROR) {
        DFILE_LOGE(TAG, "Session (%u) fatal error -- File Manager error: %d", session->sessionId, errCode);
        PostFatalEvent(session);
    }

    if (msgType == FILE_MANAGER_IN_PROGRESS) {
        NoticeSessionProgress(session);
    }
}

int32_t CreateFileManager(DFileSession *session, const uint8_t *key, uint32_t keyLen, uint8_t isSender,
    uint16_t connType)
{
    FileManagerMsgPara msgPara;
    if (session == NULL) {
        DFILE_LOGE(TAG, "invalid input");
        return NSTACKX_EINVAL;
    }
    if (isSender && (connType != CONNECT_TYPE_P2P && connType != CONNECT_TYPE_WLAN)) {
        DFILE_LOGE(TAG, "connType for sender is illagal");
        return NSTACKX_EINVAL;
    }
    if (keyLen > 0) {
        if ((keyLen != AES_128_KEY_LENGTH && keyLen != CHACHA20_KEY_LENGTH) || key == NULL) {
            DFILE_LOGE(TAG, "error key or key len");
            return NSTACKX_EFAILED;
        }
        if (!IsCryptoIncluded()) {
            DFILE_LOGE(TAG, "crypto is not opened");
            return NSTACKX_EFAILED;
        }
    }
    msgPara.epollfd = session->epollfd;
    msgPara.eventNodeChain = &session->eventNodeChain;
    msgPara.msgReceiver = FileManagerMsgHandle;
    msgPara.context = session;
    session->fileManager = FileManagerCreate(isSender, &msgPara, key, keyLen, connType);
    if (session->fileManager == NULL) {
        DFILE_LOGE(TAG, "create filemanager failed");
        return NSTACKX_EFAILED;
    }
    return NSTACKX_EOK;
}

void DestroyReceiverPipe(DFileSession *session)
{
    if (session->receiverPipe[PIPE_OUT] != INVALID_PIPE_DESC) {
        CloseDesc(session->receiverPipe[PIPE_OUT]);
        session->receiverPipe[PIPE_OUT] = INVALID_PIPE_DESC;
    }
    if (session->receiverPipe[PIPE_IN] != INVALID_PIPE_DESC) {
        CloseDesc(session->receiverPipe[PIPE_IN]);
        session->receiverPipe[PIPE_IN] = INVALID_PIPE_DESC;
    }
}

void DFileSetEvent(void *softObj, DFileEventFunc func)
{
    g_dfileEventFunc = func;
    (void)softObj;
}

void NSTACKX_DFileAssembleFunc(void *softObj, const DFileEvent *info)
{
    if (g_dfileEventFunc != NULL) {
        g_dfileEventFunc(softObj, info);
    }
}
