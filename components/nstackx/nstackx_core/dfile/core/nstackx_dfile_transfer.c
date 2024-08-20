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

#include "nstackx_dfile_transfer.h"

#include "nstackx_dfile_retransmission.h"
#include "nstackx_congestion.h"
#include "nstackx_dfile.h"
#include "nstackx_dfile_frame.h"
#include "nstackx_dfile_session.h"
#include "nstackx_error.h"
#include "nstackx_file_manager.h"
#include "nstackx_list.h"
#include "nstackx_dfile_log.h"
#include "nstackx_timer.h"
#include "nstackx_util.h"
#include "nstackx_dfile_dfx.h"
#include "securec.h"

#define TAG "nStackXDFile"

#define NSTACKX_DFILE_BACKOFF_FACTOR 2
#define TRANSFER_DONE_ACK_REPEATED_TIMES 3
#define RADIO_DIVISOR 95
#define RADIO_DIVIDEND 100

static uint64_t GetTotalFrameCount(DFileTrans *dFileTrans);

static inline uint64_t NstackAdjustAckIntervalRatio(uint64_t num)
{
    return num * RADIO_DIVISOR / RADIO_DIVIDEND; /* (num) * 9 / 10 means ratio is 0.9 times */
}

static void ReceiverFsm(DFileTrans *dFileTrans);
static void SetSendState(DFileTrans *dFileTrans, DFileSendState nextState);
static void SetReceiveState(DFileTrans *dFileTrans, DFileReceiveState nextState);

int32_t DFileTransSendFiles(DFileTrans *trans, FileListInfo *fileListInfo)
{
    DFILE_LOGI(TAG, "transId %hu, fileNum %u", trans->transId, fileListInfo->fileNum);
    return FileListSetSendFileList(trans->fileList, fileListInfo);
}

int32_t DFileTransAddExtraInfo(DFileTrans *trans, uint16_t pathType, uint8_t noticeFileNameType, char *userData)
{
    DFILE_LOGI(TAG, "transId %hu, pathType %hu", trans->transId, pathType);
    return FileListAddExtraInfo(trans->fileList, pathType, noticeFileNameType, userData);
}

static const char *GetSendStateMessage(DFileSendState state)
{
    static const char *message[] = {
        [STATE_SEND_FILE_INIT] = "send file init",
        [STATE_SEND_FILE_HEADER_ONGOING] = "send file header ongoing",
        [STATE_WAIT_FOR_FILE_HEADER_CONFIRM] = "wait for file header confirm",
        [STATE_SEND_FILE_DATA_ONGOING] = "send file data ongoing",
        [STATE_WAIT_FOR_FILE_TRANSFER_DONE_FRAME] = "wait for file transfer done frame",
        [STATE_SEND_FILE_TRANSFER_DONE_ACK] = "send file transfer done ack",
        [STATE_SEND_FILE_DONE] = "send file done",
        [STATE_SEND_FILE_FAIL] = "send file fail",
    };

    uint32_t msgLen = sizeof(message) / sizeof(message[0]);
    for (uint32_t i = 0; i < msgLen; i++) {
        if (state == i) {
            return message[i];
        }
    }
    return "unknown";
}

static const char *GetReceiveStateMessage(DFileReceiveState state)
{
    static const char *message[] = {
        [STATE_RECEIVE_FILE_INIT] = "receive file init",
        [STATE_RECEIVE_FILE_HEADER_ONGOING] = "receive file header ongoing",
        [STATE_SEND_FILE_HEADER_CONFIRM] = "send file header confirm",
        [STATE_RECEIVE_FILE_DATA_ONGOING] = "receive file data ongoing",
        [STATE_SEND_FILE_DATA_ACK] = "send file data ack",
        [STATE_SEND_FILE_TRANSFER_DONE] = "send file transfer done",
        [STATE_WAIT_FOR_FILE_TRANSFER_DONE_ACK] = "wait for file transfer done ack",
        [STATE_RECEIVE_FILE_DONE] = "receive file done",
        [STATE_RECEIVE_FILE_FAIL] = "receive file fail",
    };

    uint32_t msgLen = sizeof(message) / sizeof(message[0]);
    for (uint32_t i = 0; i < msgLen; i++) {
        if (state == i) {
            return message[i];
        }
    }
    return "unknown";
}

static const char *GetErrorMessage(DFileTransErrorCode errorCode)
{
    static const char *message[] = {
        [DFILE_TRANS_NO_ERROR] = "No error",
        [DFILE_TRANS_SOCKET_ERROR] = "Socket IO error",
        [DFILE_TRANS_INTERNAL_ERROR] = "Internal error",
        [DFILE_TRANS_FILE_HEADER_CONFIRM_TIMEOUT] = "Sender wait for HEADER CONFIRM frame timeout",
        [DFILE_TRANS_FILE_DATA_ACK_TIMEOUT] = "Sender wait for heart beat (DATA ACK frame) timeout",
        [DFILE_TRANS_TRANSFER_DONE_TIMEOUT] = "Sender wait for TRANSFER DONE frame timeout",
        [DFILE_TRANS_FILE_HEADER_TIMEOUT] = "Receiver wait for HEADER frame timeout (partially received)",
        [DFILE_TRANS_FILE_DATA_TIMEOUT] = "Receive file data timeout (partially received)",
        [DFILE_TRANS_TRANSFER_DONE_ACK_TIMEOUT] = "Receiver wait for TRANSFER DONE ACK frame timeout",
        [DFILE_TRANS_FILE_SEND_TASK_ERROR] = "Send task error",
        [DFILE_TRANS_FILE_RECEIVE_TASK_ERROR] = "Receive task error",
        [DFILE_TRANS_FILE_WRITE_FAIL] = "Write file list fail",
        [DFILE_TRANS_FILE_RENAME_FAIL] = "Rename file failed",
    };

    for (uint32_t i = 0; i < sizeof(message) / sizeof(message[0]); i++) {
        if (errorCode == i) {
            return message[i];
        }
    }
    return "unknown";
}

static inline uint32_t GetElapseTime(const struct timespec *ts)
{
    struct timespec now;
    ClockGetTime(CLOCK_MONOTONIC, &now);
    return GetTimeDiffMs(&now, ts);
}

static int32_t ConvertTransError(DFileTransErrorCode errorCode)
{
    switch (errorCode) {
        case DFILE_TRANS_NO_ERROR:
            return NSTACKX_EOK;
        case DFILE_TRANS_SOCKET_ERROR:
        case DFILE_TRANS_INTERNAL_ERROR:
        case DFILE_TRANS_FILE_SEND_TASK_ERROR:
        case DFILE_TRANS_FILE_RECEIVE_TASK_ERROR:
        case DFILE_TRANS_FILE_WRITE_FAIL:
        case DFILE_TRANS_FILE_RENAME_FAIL:
            return NSTACKX_EFAILED;
        case DFILE_TRANS_FILE_HEADER_CONFIRM_TIMEOUT:
        case DFILE_TRANS_FILE_DATA_ACK_TIMEOUT:
        case DFILE_TRANS_TRANSFER_DONE_TIMEOUT:
        case DFILE_TRANS_FILE_HEADER_TIMEOUT:
        case DFILE_TRANS_FILE_DATA_TIMEOUT:
        case DFILE_TRANS_TRANSFER_DONE_ACK_TIMEOUT:
            return NSTACKX_ETIMEOUT;
        default:
            break;
    }

    return NSTACKX_EFAILED;
}


void ReviewSuccessMsg(const DFileTrans *dFileTrans, DFileTransMsgType *msgType,
    DFileTransMsg *msg, char *files[])
{
    if (*msgType != DFILE_TRANS_MSG_FILE_SENT && *msgType != DFILE_TRANS_MSG_FILE_RECEIVED) {
        return;
    }
    if (*msgType == DFILE_TRANS_MSG_FILE_SENT) {
        if (msg->fileList.fileNum == 0) {
            msg->fileList.fileNum = NSTACKX_DFILE_MAX_FILE_NUM;
            FileListGetNames(dFileTrans->fileList, files, &msg->fileList.fileNum,
                             dFileTrans->fileList->noticeFileNameType);
            msg->fileList.files = (const char **)files;
            msg->errorCode = NSTACKX_EFAILED;
            /*
             * Both DFILE_TRANS_MSG_FILE_SENT and DFILE_TRANS_MSG_FILE_SEND_FAIL are ending status, which means that
             * the trans will be destroyed in DTransMsgReceiver(). So DFILE_TRANS_MSG_FILE_SENT can be changed to
             * DFILE_TRANS_MSG_FILE_SEND_FAIL directly.
             */
            *msgType = DFILE_TRANS_MSG_FILE_SEND_FAIL;
            DFILE_LOGI(TAG, "transId %u: no success file", dFileTrans->transId);
        }
    }
    if (*msgType == DFILE_TRANS_MSG_FILE_RECEIVED) {
        if (msg->fileList.fileNum == 0) {
            msg->fileList.fileNum = NSTACKX_DFILE_MAX_FILE_NUM;
            FileListGetNames(dFileTrans->fileList, files, &msg->fileList.fileNum, NOTICE_FILE_NAME_TYPE);
            msg->fileList.files = (const char **)files;
            msg->errorCode = NSTACKX_EFAILED;
            /*
             * DFILE_TRANS_MSG_FILE_RECEIVED isn't an ending status, so it can't be changed to the ending status
             * DFILE_TRANS_MSG_FILE_RECEIVE_FAIL directly.
             */
            *msgType = DFILE_TRANS_MSG_FILE_RECEIVED_TO_FAIL;
            DFILE_LOGI(TAG, "transId %u: no success file", dFileTrans->transId);
        }
    }
}

static void NotifyTransProgress(DFileTrans *dFileTrans, uint64_t bytesTransferred)
{
    DFileTransMsg transMsg;
    char *files[NSTACKX_DFILE_MAX_FILE_NUM] = {0};
    (void)memset_s(&transMsg, sizeof(transMsg), 0, sizeof(transMsg));
    transMsg.transferUpdate.transId = dFileTrans->transId;
    transMsg.transferUpdate.totalBytes = dFileTrans->totalBytes;
    transMsg.transferUpdate.bytesTransferred = bytesTransferred;
    transMsg.fileList.fileNum = NSTACKX_DFILE_MAX_FILE_NUM;
    transMsg.fileList.userData = dFileTrans->fileList->userData;
    transMsg.fileList.transId = dFileTrans->transId;
    FileListGetNames(dFileTrans->fileList, files, &transMsg.fileList.fileNum, NOTICE_FILE_NAME_TYPE);
    transMsg.fileList.files = (const char **)files;
    dFileTrans->msgReceiver(dFileTrans, DFILE_TRANS_MSG_IN_PROGRESS, &transMsg);
}

static void NotifyTransMsg(DFileTrans *dFileTrans, DFileTransMsgType msgType)
{
    if (dFileTrans->msgReceiver == NULL) {
        return;
    }

    DFileTransMsg transMsg;
    char *files[NSTACKX_DFILE_MAX_FILE_NUM] = {0};
    (void)memset_s(&transMsg, sizeof(transMsg), 0, sizeof(transMsg));
    transMsg.fileList.fileNum = NSTACKX_DFILE_MAX_FILE_NUM;
    transMsg.fileList.userData = dFileTrans->fileList->userData;
    transMsg.fileList.transId = dFileTrans->transId;

    switch (msgType) {
        case DFILE_TRANS_MSG_FILE_LIST_RECEIVED:
            FileListGetNames(dFileTrans->fileList, files, &transMsg.fileList.fileNum, NOTICE_FILE_NAME_TYPE);
            transMsg.fileList.files = (const char **)files;
            break;
        case DFILE_TRANS_MSG_FILE_RECEIVED:
            FileListGetReceivedFiles(dFileTrans->fileList, files, &transMsg.fileList.fileNum);
            transMsg.fileList.files = (const char **)files;
            if (transMsg.fileList.fileNum == dFileTrans->fileList->num) {
                NotifyTransProgress(dFileTrans, dFileTrans->totalBytes);
            }
            break;
        case DFILE_TRANS_MSG_FILE_SENT:
            FileListGetSentFiles(dFileTrans->fileList, files, &transMsg.fileList.fileNum);
            transMsg.fileList.files = (const char **)files;
            break;
        case DFILE_TRANS_MSG_FILE_RECEIVE_FAIL:
            /*
             * May encounter failure durinng HEADER stage, and not all the file names are received. In this case, we
             * don't provide the file list.
             */
            transMsg.fileList.fileNum = 0;
            if (FileListAllFileNameReceived(dFileTrans->fileList)) {
                transMsg.fileList.fileNum = NSTACKX_DFILE_MAX_FILE_NUM;
                FileListGetNames(dFileTrans->fileList, files, &transMsg.fileList.fileNum, NOTICE_FILE_NAME_TYPE);
                transMsg.fileList.files = (const char **)files;
            }
            transMsg.errorCode = ConvertTransError(dFileTrans->errorCode);
            break;
        case DFILE_TRANS_MSG_FILE_SEND_FAIL:
            FileListGetNames(dFileTrans->fileList, files, &transMsg.fileList.fileNum,
                             dFileTrans->fileList->noticeFileNameType);
            transMsg.fileList.files = (const char **)files;
            transMsg.errorCode = ConvertTransError(dFileTrans->errorCode);
            break;
        default:
            break;
    }
    ReviewSuccessMsg(dFileTrans, &msgType, &transMsg, files);
    dFileTrans->msgReceiver(dFileTrans, msgType, &transMsg);
}

/* To post message when come to end */
static void DFileTransNotifyEndMsg(DFileTrans *dFileTrans)
{
    if (dFileTrans->isSender) {
        if (dFileTrans->sendState == STATE_SEND_FILE_FAIL) {
            NotifyTransMsg(dFileTrans, DFILE_TRANS_MSG_FILE_SEND_FAIL);
        } else if (dFileTrans->sendState == STATE_SEND_FILE_DONE) {
            NotifyTransMsg(dFileTrans, DFILE_TRANS_MSG_FILE_SENT);
        }
    } else {
        if (dFileTrans->recvState == STATE_RECEIVE_FILE_FAIL) {
            NotifyTransMsg(dFileTrans, DFILE_TRANS_MSG_FILE_RECEIVE_FAIL);
        } else if (dFileTrans->recvState == STATE_RECEIVE_FILE_DONE) {
            NotifyTransMsg(dFileTrans, DFILE_TRANS_MSG_END);
        }
    }
}

static uint8_t DFileTransStateFinished(DFileTrans *dFileTrans)
{
    if ((dFileTrans->isSender &&
        (dFileTrans->sendState == STATE_SEND_FILE_FAIL || dFileTrans->sendState == STATE_SEND_FILE_DONE)) ||
        (!dFileTrans->isSender &&
        (dFileTrans->recvState == STATE_RECEIVE_FILE_FAIL || dFileTrans->recvState == STATE_RECEIVE_FILE_DONE))) {
        return NSTACKX_TRUE;
    }

    return NSTACKX_FALSE;
}

int32_t SendFrame(DFileTrans *dFileTrans, uint8_t *frame, size_t frameLength, DFileSendState *nextSend,
    DFileReceiveState *nextRecv)
{
    SetDfileFrameTransID((DFileFrame *)frame, dFileTrans->transId);
    int32_t ret = dFileTrans->writeHandle(frame, frameLength, dFileTrans->context);
    if (ret != (int32_t)frameLength) {
        /* Data was not sent. */
        if (ret != NSTACKX_EAGAIN) {
            if (dFileTrans->isSender && nextSend != NULL) {
                *nextSend = STATE_SEND_FILE_FAIL;
            }
            if (!dFileTrans->isSender && nextRecv != NULL) {
                *nextRecv = STATE_RECEIVE_FILE_FAIL;
            }
            ret = NSTACKX_EFAILED;
            dFileTrans->errorCode = DFILE_TRANS_SOCKET_ERROR;
        }
        return ret;
    }
    return NSTACKX_EOK;
}

static inline void ExtendTimeout(uint32_t *timeout, uint32_t maxTimeout)
{
    if (*timeout < maxTimeout) {
        *timeout *= NSTACKX_DFILE_BACKOFF_FACTOR;
        if (*timeout > maxTimeout) {
            *timeout = maxTimeout;
        }
    }
}

static void SendFileHeader(DFileTrans *dFileTrans, DFileSendState *nextState)
{
    uint32_t fileNum;
    if (dFileTrans->fileList->tarFlag == NSTACKX_TRUE) {
        fileNum = 1;
    } else {
        fileNum = FileListGetNum(dFileTrans->fileList);
    }
    do {
        (void)memset_s(dFileTrans->sendBuffer, sizeof(dFileTrans->sendBuffer), 0, sizeof(dFileTrans->sendBuffer));

        int32_t lastEncodeHeaderFileId = dFileTrans->lastSentHeaderFileId;
        EncodeFileHeaderFrame(dFileTrans->fileList, &lastEncodeHeaderFileId, dFileTrans->sendBuffer,
            dFileTrans->mtu, &dFileTrans->sendBufferLength);
        int32_t ret = SendFrame(dFileTrans, dFileTrans->sendBuffer, dFileTrans->sendBufferLength, nextState, NULL);
        if (ret != NSTACKX_EOK) {
            break;
        }

        DFILE_LOGI(TAG, "transId %hu send header successfully. len %zu lastEncodeHeaderFileId %d, fileNum %u",
             dFileTrans->transId, dFileTrans->sendBufferLength, lastEncodeHeaderFileId, fileNum);

        dFileTrans->lastSentHeaderFileId = lastEncodeHeaderFileId;
        if (dFileTrans->lastSentHeaderFileId == (int32_t)fileNum) {
            *nextState = STATE_WAIT_FOR_FILE_HEADER_CONFIRM;
            break;
        }
    } while (NSTACKX_TRUE);
}

void FileManagerSenderMsgHandler(uint16_t fileId, FileManagerMsgType msgType, FileManagerMsg *msg,
                                 DFileTrans *dFileTrans)
{
    char *files[NSTACKX_DFILE_MAX_FILE_NUM] = {0};
    if (dFileTrans == NULL) {
        return;
    }
    if (msgType != FILE_MANAGER_TRANS_IN_PROGRESS) {
        DFILE_LOGI(TAG, "transId %u, Sender: File Id %u got message (%d) from file manager, code %d",
             dFileTrans->transId, fileId, msgType, (msgType == FILE_MANAGER_SEND_FAIL) ? msg->errorCode : 0);
    }

    if (msgType == FILE_MANAGER_TRANS_IN_PROGRESS) {
        msg->fileList.fileNum = NSTACKX_DFILE_MAX_FILE_NUM;
        msg->fileList.userData = dFileTrans->fileList->userData;
        msg->fileList.transId = dFileTrans->transId;
        FileListGetNames(dFileTrans->fileList, files, &msg->fileList.fileNum, dFileTrans->fileList->noticeFileNameType);
        msg->fileList.files = (const char **)files;
        dFileTrans->msgReceiver(dFileTrans, DFILE_TRANS_MSG_IN_PROGRESS, msg);
        return;
    }
    if (msgType == FILE_MANAGER_SEND_FAIL) {
        dFileTrans->errorCode = DFILE_TRANS_FILE_SEND_TASK_ERROR;
        SetSendState(dFileTrans, STATE_SEND_FILE_FAIL);
        NotifyTransMsg(dFileTrans, DFILE_TRANS_MSG_FILE_SEND_FAIL);
    }
}

static void FileManagerTransMsgHandler(uint16_t fileId, FileManagerMsgType msgType, FileManagerMsg *msg, void *context,
    uint16_t transId)
{
    DFileSession *session = (DFileSession *)context;
    List *pos = NULL;
    DFileTrans *dFileTrans = NULL;
    uint8_t isFound = NSTACKX_FALSE;
    if (session == NULL || session->closeFlag) {
        return;
    }
    LIST_FOR_EACH(pos, &session->dFileTransChain) {
        dFileTrans = (DFileTrans *)pos;
        if (dFileTrans != NULL && dFileTrans->transId == transId) {
            isFound = NSTACKX_TRUE;
            break;
        }
    }
    if (!isFound) {
        DFILE_LOGE(TAG, "can't get valid trans %u to send msg", transId);
        return;
    }

    if (dFileTrans->isSender) {
        FileManagerSenderMsgHandler(fileId, msgType, msg, dFileTrans);
    } else {
        FileManagerReceiverMsgHandler(fileId, msgType, msg, dFileTrans);
    }
}

static int32_t StartFileManagerSenderTask(DFileTrans *dFileTrans)
{
    FileListMsgPara msgPara;
    FileList *fileList = dFileTrans->fileList;
    uint16_t fileNum = FileListGetNum(fileList);
    SendFileListInfo sendFileListInfo;

    (void)memset_s(&sendFileListInfo, sizeof(sendFileListInfo), 0, sizeof(sendFileListInfo));
    (void)memset_s(&msgPara, sizeof(msgPara), 0, sizeof(msgPara));

    if (dFileTrans->fileManagerTaskStarted) {
        return NSTACKX_EOK;
    }
    if (fileNum > NSTACKX_DFILE_MAX_FILE_NUM) {
        DFILE_LOGE(TAG, "too many files: %u", fileNum);
        return NSTACKX_ENOMEM;
    }
    uint32_t i;
    for (i = 0; i < FileListGetNum(fileList); i++) {
        sendFileListInfo.fileList[i] = fileList->list[i].fullFileName;
        sendFileListInfo.fileSize[i] = fileList->list[i].fileSize;
        sendFileListInfo.startOffset[i] = fileList->list[i].startOffset;
    }

    if (fileList->tarFlag == NSTACKX_TRUE) {
        sendFileListInfo.fileList[i] = fileList->tarFile;
    }
    sendFileListInfo.transId = dFileTrans->transId;
    sendFileListInfo.fileNum = FileListGetNum(fileList);
    sendFileListInfo.tarFlag = fileList->tarFlag;
    sendFileListInfo.smallFlag = fileList->smallFlag;
    msgPara.msgReceiver = FileManagerTransMsgHandler;
    msgPara.context = dFileTrans->session;
    int32_t ret = FileManagerSendFileTask(dFileTrans->fileManager, &sendFileListInfo, &msgPara);
    if (ret != NSTACKX_EOK) {
        DFILE_LOGE(TAG, "Start send file task fail %d", ret);
        return ret;
    }
    dFileTrans->fileManagerTaskStarted = NSTACKX_TRUE;
    dFileTrans->totalDataFrameCnt = GetTotalFrameCount(dFileTrans);
    return NSTACKX_EOK;
}

static void WaitForFileHeaderConfirmPrepare(DFileTrans *dFileTrans)
{
    dFileTrans->lastSentHeaderFileId = -1;
    if (dFileTrans->headerRetryCnt == 0) {
        dFileTrans->timeout = dFileTrans->config.maxRtt;
    } else {
        ExtendTimeout(&dFileTrans->timeout, dFileTrans->config.maxFileHeaderConfirmFrameTimeout);
    }
    ClockGetTime(CLOCK_MONOTONIC, &dFileTrans->ts);
}

static void WaitForFileHeaderConfirm(DFileTrans *dFileTrans, DFileSendState *nextState)
{
    if (FileListAllFileNameAcked(dFileTrans->fileList)) {
        int32_t ret = StartFileManagerSenderTask(dFileTrans);
        if (ret == NSTACKX_EOK) {
            *nextState = STATE_SEND_FILE_DATA_ONGOING;
        } else {
            *nextState = STATE_SEND_FILE_FAIL;
            dFileTrans->errorCode = DFILE_TRANS_INTERNAL_ERROR;
        }
        return;
    }

    if (GetElapseTime(&dFileTrans->ts) >= dFileTrans->timeout) {
        if (dFileTrans->headerRetryCnt > dFileTrans->config.maxCtrlFrameRetryCnt) {
            *nextState = STATE_SEND_FILE_FAIL;
            dFileTrans->errorCode = DFILE_TRANS_FILE_HEADER_CONFIRM_TIMEOUT;
            WaitFileHeaderTimeoutEvent(dFileTrans->errorCode);
            return;
        }
        dFileTrans->headerRetryCnt++;
        *nextState = STATE_SEND_FILE_HEADER_ONGOING;
    }
}

static void SendFileBlockPrepare(DFileTrans *dFileTrans)
{
    ClockGetTime(CLOCK_MONOTONIC, &dFileTrans->ts);
    dFileTrans->timeout = dFileTrans->config.initialAckInterval;
    NotifyTransMsg(dFileTrans, DFILE_TRANS_MSG_FILE_SEND_DATA);
}

static void SendFileDataOngoing(DFileTrans *dFileTrans, DFileSendState *nextState)
{
    if (dFileTrans->fileTransferDoneReceived) {
        *nextState = STATE_SEND_FILE_TRANSFER_DONE_ACK;
        return;
    }
    if (GetElapseTime(&dFileTrans->ts) >= dFileTrans->timeout) {
        if (!CapsTcp(dFileTrans->session)) {
            dFileTrans->lostAckCnt++;
            DFILE_LOGW(TAG, "transId %u Sender lost ACK count %u totalRecvBlocks %llu inboundQueueSize %llu",
                dFileTrans->transId, dFileTrans->lostAckCnt,
                NSTACKX_ATOM_FETCH(&(dFileTrans->session->totalRecvBlocks)),
                dFileTrans->session->inboundQueueSize);
            if (dFileTrans->lostAckCnt >= dFileTrans->config.maxAckCnt) {
                *nextState = STATE_SEND_FILE_FAIL;
                dFileTrans->errorCode = DFILE_TRANS_FILE_DATA_ACK_TIMEOUT;
                DFILE_LOGW(TAG, "transId %u Sender lost too many ACK count", dFileTrans->transId);
                return;
            }
        }

        /* Update timestamp */
        ClockGetTime(CLOCK_MONOTONIC, &dFileTrans->ts);
        return;
    }

    if (FileManagerIsLastBlockRead(dFileTrans->fileManager, dFileTrans->transId)) {
        *nextState = STATE_WAIT_FOR_FILE_TRANSFER_DONE_FRAME;
    }
}

static void WaitForFileTransferDonePrepare(DFileTrans *dFileTrans)
{
    ClockGetTime(CLOCK_MONOTONIC, &dFileTrans->ts);
    dFileTrans->timeout = dFileTrans->config.maxCtrlFrameTimeout;
}

static void WaitForFileTransferDoneFrame(DFileTrans *dFileTrans, DFileSendState *nextState)
{
    if (dFileTrans->fileTransferDoneReceived) {
        *nextState = STATE_SEND_FILE_TRANSFER_DONE_ACK;
    }

    if (GetElapseTime(&dFileTrans->ts) >= dFileTrans->timeout) {
        if (CapsTcp(dFileTrans->session)) {
            *nextState = STATE_SEND_FILE_DATA_ONGOING;
            return;
        }
        *nextState = STATE_SEND_FILE_FAIL;
        dFileTrans->errorCode = DFILE_TRANS_TRANSFER_DONE_TIMEOUT;
        return;
    }

    /* Need to re-send data block. */
    if (!FileManagerIsLastBlockRead(dFileTrans->fileManager, dFileTrans->transId)) {
        *nextState = STATE_SEND_FILE_DATA_ONGOING;
    }
}

static void SendFileTransferDoneAckFrame(DFileTrans *dFileTrans, DFileSendState *nextState)
{
    uint32_t i;

    (void)memset_s(dFileTrans->sendBuffer, sizeof(dFileTrans->sendBuffer), 0, sizeof(dFileTrans->sendBuffer));
    EncodeFileTransferDoneAckFrame(dFileTrans->sendBuffer, dFileTrans->mtu, dFileTrans->transId,
        &dFileTrans->sendBufferLength);
    for (i = 0; i < TRANSFER_DONE_ACK_REPEATED_TIMES; i++) {
        int32_t ret = SendFrame(dFileTrans, dFileTrans->sendBuffer, dFileTrans->sendBufferLength, nextState, NULL);
        if (ret != NSTACKX_EOK) {
            break;
        }
    }
    TransferDoneAckNode *transferDoneAckNode = calloc(1, sizeof(TransferDoneAckNode));
    if (transferDoneAckNode == NULL) {
        DFILE_LOGE(TAG, "transferDoneAckNode calloc failed");
        return;
    }
    transferDoneAckNode->transId = dFileTrans->transId;
    transferDoneAckNode->sendNum = MAX_SEND_TRANSFERDONE_ACK_FRAME_COUNT;
    if (MutexListAddNode(&dFileTrans->session->transferDoneAckList, &transferDoneAckNode->list, 0) != NSTACKX_EOK) {
        free(transferDoneAckNode);
    }
    DFILE_LOGI(TAG, "transferDoneAckNode add transId %u", dFileTrans->transId);
    if (i == 0) {
        return;
    }

    *nextState = STATE_SEND_FILE_DONE;
}

static void SetSendState(DFileTrans *dFileTrans, DFileSendState nextState)
{
    if (dFileTrans->sendState == nextState) {
        return;
    }

    switch (nextState) {
        case STATE_WAIT_FOR_FILE_HEADER_CONFIRM:
            WaitForFileHeaderConfirmPrepare(dFileTrans);
            break;
        case STATE_SEND_FILE_DATA_ONGOING:
            SendFileBlockPrepare(dFileTrans);
            break;
        case STATE_WAIT_FOR_FILE_TRANSFER_DONE_FRAME:
            WaitForFileTransferDonePrepare(dFileTrans);
            break;
        default:
            break;
    }

    if (dFileTrans->sendState >= STATE_SEND_FILE_TRANSFER_DONE_ACK && nextState == STATE_SEND_FILE_FAIL) {
        /*
         * After receiving TRANSFER_DONE frame, sender still may encounter error, such as sending TRANSFER_DONE_ACK
         * frame. In such case, we just stop the state machine and report finish to user.
         */
        DFILE_LOGW(TAG, "transId %u Sender error during state %s - %s, ignore error and finish sending process",
             dFileTrans->transId, GetSendStateMessage(dFileTrans->sendState), GetErrorMessage(dFileTrans->errorCode));
        nextState = STATE_SEND_FILE_DONE;
    }

    if (dFileTrans->errorCode != DFILE_TRANS_NO_ERROR) {
        DFILE_LOGE(TAG, "transId %u error: %s", dFileTrans->transId, GetErrorMessage(dFileTrans->errorCode));
    }
    dFileTrans->sendState = nextState;

    if ((nextState == STATE_SEND_FILE_DONE || nextState == STATE_SEND_FILE_FAIL) &&
        dFileTrans->fileManagerTaskStarted) {
        DFILE_LOGI(TAG, "transId: %u, Send state: %s -> %s", dFileTrans->transId,
                GetSendStateMessage(dFileTrans->sendState),GetSendStateMessage(nextState));
        if (FileManagerStopTask(dFileTrans->fileManager, dFileTrans->transId, FILE_LIST_TRANSFER_FINISH) !=
            NSTACKX_EOK) {
            DFILE_LOGE(TAG, "transId %u FileManagerStopTask failed", dFileTrans->transId);
        }
        dFileTrans->fileManagerTaskStarted = NSTACKX_FALSE;
    }
}

static void SenderFsm(DFileTrans *dFileTrans)
{
    DFileSendState nextState = dFileTrans->sendState;

    do {
        switch (dFileTrans->sendState) {
            case STATE_SEND_FILE_INIT:
                nextState = STATE_SEND_FILE_HEADER_ONGOING;
                dFileTrans->session->transFlag = NSTACKX_TRUE;
                dFileTrans->fileManager->transFlag = NSTACKX_TRUE;
                break;
            case STATE_SEND_FILE_HEADER_ONGOING:
                SendFileHeader(dFileTrans, &nextState);
                break;
            case STATE_WAIT_FOR_FILE_HEADER_CONFIRM:
                WaitForFileHeaderConfirm(dFileTrans, &nextState);
                break;
            case STATE_SEND_FILE_DATA_ONGOING:
                SendFileDataOngoing(dFileTrans, &nextState);
                break;
            case STATE_WAIT_FOR_FILE_TRANSFER_DONE_FRAME:
                WaitForFileTransferDoneFrame(dFileTrans, &nextState);
                break;
            case STATE_SEND_FILE_TRANSFER_DONE_ACK:
                SendFileTransferDoneAckFrame(dFileTrans, &nextState);
                break;
            default:
                break;
        }
        if (dFileTrans->sendState == nextState) {
            break;
        }
        SetSendState(dFileTrans, nextState);
    } while (dFileTrans->sendState != STATE_SEND_FILE_FAIL && dFileTrans->sendState != STATE_SEND_FILE_DONE);
}

static void ReceiveFileHeaderPrepare(DFileTrans *dFileTrans)
{
    ClockGetTime(CLOCK_MONOTONIC, &dFileTrans->ts);
    if (dFileTrans->headerAckRetryCnt == 0) {
        dFileTrans->timeout = dFileTrans->config.maxRtt;
    } else {
        ExtendTimeout(&dFileTrans->timeout, dFileTrans->config.maxCtrlFrameTimeout);
    }
}

static void ReceiveFileHeaderOngoing(DFileTrans *dFileTrans, DFileReceiveState *nextState)
{
    uint8_t timeout = (GetElapseTime(&dFileTrans->ts) >= dFileTrans->timeout) ? NSTACKX_TRUE : NSTACKX_FALSE;
    if (dFileTrans->allFileNameReceived || timeout) {
        *nextState = STATE_SEND_FILE_HEADER_CONFIRM;
    }
}

static void NotifyRecvSucMsg(DFileTrans *dFileTrans)
{
    if (dFileTrans->isRecvSucMsgNotified) {
        return;
    }
    NotifyTransMsg(dFileTrans, DFILE_TRANS_MSG_FILE_RECEIVED);
    dFileTrans->isRecvSucMsgNotified = NSTACKX_TRUE;
}

void FileManagerReceiverMsgHandler(uint16_t fileId, FileManagerMsgType msgType, FileManagerMsg *msg,
                                   DFileTrans *dFileTrans)
{
    if (dFileTrans == NULL) {
        return;
    }
    if (msgType != FILE_MANAGER_RECEIVE_SUCCESS) {
        DFILE_LOGE(TAG, "transId %u, Receiver: File Id %u got message (%d) from file manager, code %d",
             dFileTrans->transId, fileId, msgType, (msgType == FILE_MANAGER_RECEIVE_FAIL) ? msg->errorCode : 0);
    }

    if (msgType == FILE_MANAGER_RECEIVE_FAIL) {
        dFileTrans->errorCode = DFILE_TRANS_FILE_RECEIVE_TASK_ERROR;
        SetReceiveState(dFileTrans, STATE_RECEIVE_FILE_FAIL);
        NotifyTransMsg(dFileTrans, DFILE_TRANS_MSG_FILE_RECEIVE_FAIL);
        return;
    }

    if (fileId) {
        if (msgType == FILE_MANAGER_RECEIVE_SUCCESS) {
            FileListSetFileReceiveSuccess(dFileTrans->fileList, fileId);
        }
        if (FileListAllFileReceived(dFileTrans->fileList)) {
            /*
             * When all files are empty, it won't enter RECEIVE_DATA_ON_GOING state.
             * We have to set allFileDataReceived in this case
             */
            dFileTrans->allFileDataReceived = NSTACKX_TRUE;
            dFileTrans->ioWriteFinishFlag = NSTACKX_TRUE;
            NotifyRecvSucMsg(dFileTrans);
            ReceiverFsm(dFileTrans);
            dFileTrans->isAckSend = NSTACKX_FALSE;
        }
    }
}

static int32_t StartFileManagerReceiverTask(DFileTrans *dFileTrans)
{
    RecvFileListInfo fileListInfo;
    FileList *fileList = dFileTrans->fileList;
    FileListMsgPara msgPara;

    if (dFileTrans->fileManagerTaskStarted) {
        return NSTACKX_EOK;
    }
    fileListInfo.fileBasicInfo = calloc(FileListGetNum(fileList), sizeof(FileBaseInfo));
    if (fileListInfo.fileBasicInfo == NULL) {
        return NSTACKX_ENOMEM;
    }

    for (uint32_t i = 0; i < FileListGetNum(fileList); i++) {
        fileListInfo.fileBasicInfo[i].fileSize = fileList->list[i].fileSize;
        fileListInfo.fileBasicInfo[i].fileId = fileList->list[i].fileId;
        fileListInfo.fileBasicInfo[i].fileName = fileList->list[i].fileName;
        fileListInfo.fileBasicInfo[i].startOffset = fileList->list[i].startOffset;
        dFileTrans->totalBytes += fileList->list[i].fileSize;
    }

    fileListInfo.pathType = FileListGetPathType(fileList);
    fileListInfo.fileNum = FileListGetNum(fileList);
    fileListInfo.transId = dFileTrans->transId;
    fileListInfo.noSyncFlag = fileList->noSyncFlag;
    msgPara.msgReceiver = FileManagerTransMsgHandler;
    msgPara.context = dFileTrans->session;
    int32_t ret = FileManagerRecvFileTask(dFileTrans->fileManager, &fileListInfo, &msgPara);
    if (ret != NSTACKX_EOK) {
        DFILE_LOGE(TAG, "Start receive task fail %d", ret);
        free(fileListInfo.fileBasicInfo);
        return NSTACKX_EFAILED;
    }
    dFileTrans->fileManagerTaskStarted = NSTACKX_TRUE;
    free(fileListInfo.fileBasicInfo);
    return NSTACKX_EOK;
}

static void SendFileHeaderConfirm(DFileTrans *dFileTrans, DFileReceiveState *nextState)
{
    do {
        (void)memset_s(dFileTrans->sendBuffer, sizeof(dFileTrans->sendBuffer), 0, sizeof(dFileTrans->sendBuffer));
        uint16_t lastEncAckedHeaderFileId = dFileTrans->lastAckedHeaderFileId;
        EncodeFileHeaderConfirmFrame(dFileTrans->fileList, &lastEncAckedHeaderFileId,
            dFileTrans->sendBuffer, dFileTrans->mtu, &dFileTrans->sendBufferLength);
        int32_t ret = SendFrame(dFileTrans, dFileTrans->sendBuffer, dFileTrans->sendBufferLength, NULL, nextState);
        if (ret != NSTACKX_EOK) {
            return;
        }
        dFileTrans->lastAckedHeaderFileId = lastEncAckedHeaderFileId;
        if (dFileTrans->lastAckedHeaderFileId == FileListGetNum(dFileTrans->fileList)) {
            DFILE_LOGI(TAG, "transId %u last send header confirm successfully. len %u",
                dFileTrans->transId, dFileTrans->sendBufferLength);
            break;
        }
    } while (NSTACKX_TRUE);

    if (dFileTrans->allFileNameReceived) {
        if (StartFileManagerReceiverTask(dFileTrans) != NSTACKX_EOK) {
            *nextState = STATE_RECEIVE_FILE_FAIL;
            dFileTrans->errorCode = DFILE_TRANS_INTERNAL_ERROR;
        } else {
            *nextState = STATE_RECEIVE_FILE_DATA_ONGOING;
        }
    } else {
        /* Timeout, check should retry or fail */
        if (dFileTrans->headerAckRetryCnt > dFileTrans->config.maxCtrlFrameRetryCnt) {
            *nextState = STATE_RECEIVE_FILE_FAIL;
            dFileTrans->errorCode = DFILE_TRANS_FILE_HEADER_TIMEOUT;
            return;
        }
        *nextState = STATE_RECEIVE_FILE_HEADER_ONGOING;
        dFileTrans->headerAckRetryCnt++;
    }
}

static uint64_t GetTotalFrameCount(DFileTrans *dFileTrans)
{
    uint64_t totalFrameCount = 0;
    uint32_t lastSequence;

    for (uint16_t fileId = NSTACKX_FIRST_FILE_ID; fileId <= FileListGetNum(dFileTrans->fileList); fileId++) {
        if (!FileListGetFileSize(dFileTrans->fileList, fileId)) {
            continue;
        }
        int32_t ret = FileManagerGetLastSequence(dFileTrans->fileManager, dFileTrans->transId, fileId, &lastSequence);
        if (ret != NSTACKX_EOK) {
            continue;
        }
        totalFrameCount += (lastSequence + 1);
    }
    return totalFrameCount;
}

static void ReceiveFileDataPrepare(DFileTrans *dFileTrans)
{
    PeerInfo *peerInfo = dFileTrans->context;
    if (dFileTrans->recvState == STATE_SEND_FILE_HEADER_CONFIRM) {
        /* Update time stamp when entering from "HEADER" stage to "DATA" state */
        ClockGetTime(CLOCK_MONOTONIC, &dFileTrans->ts);
        ClockGetTime(CLOCK_MONOTONIC, &dFileTrans->heartBeatTs);

        dFileTrans->timeout = dFileTrans->config.initialRecvIdleTimeout;
        dFileTrans->ackInterval = peerInfo->ackInterval;
        dFileTrans->transRetryCount = dFileTrans->config.maxRetryPageCnt;
        dFileTrans->receivedDataFrameCnt = 0;
        dFileTrans->totalDataFrameCnt = GetTotalFrameCount(dFileTrans);
        dFileTrans->adjustAckIntervalLimit = NstackAdjustAckIntervalRatio(dFileTrans->totalDataFrameCnt);
        ClockGetTime(CLOCK_MONOTONIC, &dFileTrans->retryAllPacketTs);
#if DFILE_SHOW_RECEIVE_TIME
        ClockGetTime(CLOCK_MONOTONIC, &dFileTrans->startTs);
#endif
    }
}

static uint8_t ReceiverIdleTimeout(DFileTrans *dFileTrans, DFileReceiveState *nextState)
{
    uint8_t timeout = NSTACKX_FALSE;
    uint32_t elapseTime = GetElapseTime(&dFileTrans->ts);
    if (elapseTime >= dFileTrans->timeout) {
        dFileTrans->idleTimeoutCnt++;
        DFILE_LOGE(TAG,
            "transId %u: Over %u ms not recv data. idleTimeoutCnt %u last fileid %u sequence %u recv %llu all %llu",
            dFileTrans->transId, elapseTime, dFileTrans->idleTimeoutCnt, dFileTrans->lastFileDataRecvFileId,
            dFileTrans->lastFileDataSequence, dFileTrans->receivedDataFrameCnt, dFileTrans->totalDataFrameCnt);
        timeout = NSTACKX_TRUE;
    }

    if (timeout && dFileTrans->idleTimeoutCnt >= dFileTrans->config.maxRecvIdleCnt) {
        if (!CapsTcp(dFileTrans->session)) {
            return NSTACKX_TRUE;
        }
    }

    if (timeout) {
        ClockGetTime(CLOCK_MONOTONIC, &dFileTrans->ts);
        *nextState = STATE_SEND_FILE_DATA_ACK;
    }
    return NSTACKX_FALSE;
}

static int32_t RefreshFileRecvStatus(DFileTrans *dFileTrans)
{
    uint16_t fileIdList[NSTACKX_DFILE_MAX_FILE_NUM] = {0};
    uint8_t fileIdSuccessFlag[NSTACKX_DFILE_MAX_FILE_NUM] = {0};
    uint32_t fileIdNum = NSTACKX_DFILE_MAX_FILE_NUM;
    if (FileManagerGetReceivedFiles(dFileTrans->fileManager, dFileTrans->transId,
        fileIdList, fileIdSuccessFlag, &fileIdNum) != NSTACKX_EOK) {
        DFILE_LOGE(TAG, "transId %u get received files failed", dFileTrans->transId);
        return NSTACKX_EFAILED;
    }
    if (fileIdNum == 0) {
        DFILE_LOGI(TAG, "transId %u get zero received files", dFileTrans->transId);
        return NSTACKX_EOK;
    }
    for (uint32_t i = 0; i < fileIdNum; i++) {
        if (fileIdList[i] == 0) {
            continue;
        }
        if (fileIdSuccessFlag[i]) {
            FileListSetFileReceiveSuccess(dFileTrans->fileList, fileIdList[i]);
        } else {
            FileListSetFileReceiveFail(dFileTrans->fileList, fileIdList[i]);
        }
    }
    return NSTACKX_EOK;
}

static void ReceiveFileDataOngoing(DFileTrans *dFileTrans, DFileReceiveState *nextState)
{
    if (dFileTrans->dupFileName) {
        dFileTrans->dupFileName = NSTACKX_FALSE;
        *nextState = STATE_SEND_FILE_HEADER_CONFIRM;
        return;
    }

    if (dFileTrans->allFileDataReceived) {
        if (dFileTrans->ioWriteFinishFlag == NSTACKX_FALSE) {
            return;
        }
        if (RefreshFileRecvStatus(dFileTrans) != NSTACKX_EOK) {
            DFILE_LOGE(TAG, "transId %u refresh file receive status failed", dFileTrans->transId);
            *nextState = STATE_RECEIVE_FILE_FAIL;
            dFileTrans->errorCode = DFILE_TRANS_FILE_RECEIVE_TASK_ERROR;
            return;
        }
        if (FileListAllFileReceived(dFileTrans->fileList)) {
            *nextState = STATE_SEND_FILE_TRANSFER_DONE;
            return;
        }
    } else {
        if (ReceiverIdleTimeout(dFileTrans, nextState)) {
            *nextState = STATE_RECEIVE_FILE_FAIL;
            dFileTrans->errorCode = DFILE_TRANS_FILE_DATA_TIMEOUT;
            return;
        }
    }

    if (*nextState != STATE_SEND_FILE_DATA_ACK && GetElapseTime(&dFileTrans->heartBeatTs) >= dFileTrans->ackInterval) {
        if (dFileTrans->allFileDataReceived) {
            if (FileManagerSetAllDataReceived(dFileTrans->fileManager, dFileTrans->transId) != NSTACKX_EOK) {
                DFILE_LOGE(TAG, "transId %u get set all file data received failed", dFileTrans->transId);
                *nextState = STATE_RECEIVE_FILE_FAIL;
                dFileTrans->errorCode = DFILE_TRANS_FILE_RECEIVE_TASK_ERROR;
                return;
            }
        }
        *nextState = STATE_SEND_FILE_DATA_ACK;
        dFileTrans->isAckSend = NSTACKX_TRUE;
    }
}

static void SendFileTransferDoneFrame(DFileTrans *dFileTrans, DFileReceiveState *nextState)
{
    uint16_t fileIdList[NSTACKX_DFILE_MAX_FILE_NUM] = {0};
    uint32_t fileIdNum = NSTACKX_DFILE_MAX_FILE_NUM;

    if (GetElapseTime(&dFileTrans->ts) >= dFileTrans->timeout) {
        dFileTrans->errorCode = DFILE_TRANS_FILE_WRITE_FAIL;
        DFILE_LOGE(TAG, "SendFileTransferDoneFrame timeout");
        *nextState = STATE_RECEIVE_FILE_FAIL;
        return;
    }
    NotifyRecvSucMsg(dFileTrans);

    FileListGetReceivedFileIdList(dFileTrans->fileList, fileIdList, &fileIdNum);
    (void)memset_s(dFileTrans->sendBuffer, sizeof(dFileTrans->sendBuffer), 0, sizeof(dFileTrans->sendBuffer));
    /*
     * Currently max file number is 500, and default MTU is 1500, so one MTU can contain all the file Id.
     */
    EncodeFileTransferDoneFrame(dFileTrans->sendBuffer, dFileTrans->mtu, fileIdList, fileIdNum,
        &dFileTrans->sendBufferLength);
    int32_t ret = SendFrame(dFileTrans, dFileTrans->sendBuffer, dFileTrans->sendBufferLength, NULL, nextState);
    if (ret != NSTACKX_EOK) {
        return;
    }
    DFILE_LOGI(TAG, "file trans fer done frame: transId %u, frameLen %u, fileIdNum %u",
         dFileTrans->transId, dFileTrans->sendBufferLength, fileIdNum);
    *nextState = STATE_WAIT_FOR_FILE_TRANSFER_DONE_ACK;
}

static void WaitForFileTransferDoneAckPrepare(DFileTrans *dFileTrans)
{
    ClockGetTime(CLOCK_MONOTONIC, &dFileTrans->ts);
    dFileTrans->timeout = dFileTrans->config.maxRtt;
}

static void WaitForFileTransferDoneAck(DFileTrans *dFileTrans, DFileReceiveState *nextState)
{
    if (dFileTrans->fileTransferDoneAcked) {
        *nextState = STATE_RECEIVE_FILE_DONE;
        return;
    }

    if (GetElapseTime(&dFileTrans->ts) >= dFileTrans->timeout) {
        if (dFileTrans->transferDoneRetryCnt > dFileTrans->config.maxCtrlFrameRetryCnt &&
            !CapsTcp(dFileTrans->session)) {
            dFileTrans->errorCode = DFILE_TRANS_TRANSFER_DONE_ACK_TIMEOUT;
            *nextState = STATE_RECEIVE_FILE_FAIL;
            DFILE_LOGI(TAG, "transId %u enter WaitForFileTransferDoneAck and next state is STATE_RECEIVE_FILE_FAIL",
                 dFileTrans->transId);
            return;
        }
        /* Prepare to enter STATE_SEND_FILE_TRANSFER_DONE again */
        ClockGetTime(CLOCK_MONOTONIC, &dFileTrans->ts);
        dFileTrans->transferDoneRetryCnt++;
        *nextState = STATE_SEND_FILE_TRANSFER_DONE;
        DFILE_LOGI(TAG, "transId %u enter WaitForFileTransferDoneAck and next state is STATE_SEND_FILE_TRANSFER_DONE",
             dFileTrans->transId);
    }
}

#if DFILE_SHOW_RECEIVE_TIME
static void CalculateRecvRate(DFileTrans *dFileTrans)
{
    struct timespec endTs;

    ClockGetTime(CLOCK_MONOTONIC, &endTs);
    uint64_t allFileSize = dFileTrans->totalDataFrameCnt * dFileTrans->fileManager->maxFrameLength;
    uint32_t spendTime = GetTimeDiffMs(&endTs, &dFileTrans->startTs);
    if (spendTime != 0) {
        const double rate = 1.0 * allFileSize / DFILE_MEGABYTES * MSEC_TICKS_PER_SEC / spendTime;
        DFILE_LOGI(TAG, "Trans#%u Receive time %u ms rate is %.2f MB/s", dFileTrans->transId, spendTime, rate);
    }
}
#endif

static void SetReceiveStateHandle(DFileTrans *dFileTrans, DFileReceiveState nextState)
{
    switch (nextState) {
        case STATE_RECEIVE_FILE_HEADER_ONGOING:
            ReceiveFileHeaderPrepare(dFileTrans);
            break;
        case STATE_RECEIVE_FILE_DATA_ONGOING:
            ReceiveFileDataPrepare(dFileTrans);
            break;
        case STATE_SEND_FILE_HEADER_CONFIRM:
            dFileTrans->lastAckedHeaderFileId = NSTACKX_RESERVED_FILE_ID;
            break;
        case STATE_WAIT_FOR_FILE_TRANSFER_DONE_ACK:
            WaitForFileTransferDoneAckPrepare(dFileTrans);
            break;
        case STATE_SEND_FILE_TRANSFER_DONE:
            ClockGetTime(CLOCK_MONOTONIC, &dFileTrans->ts);
            dFileTrans->timeout = dFileTrans->config.maxFileWriteTimeout;
            break;
        default:
            break;
    }
}

static void SetReceiveState(DFileTrans *dFileTrans, DFileReceiveState nextState)
{
    if (dFileTrans->recvState == nextState) {
        return;
    }

    SetReceiveStateHandle(dFileTrans, nextState);
    if (dFileTrans->recvState > STATE_SEND_FILE_TRANSFER_DONE && nextState == STATE_RECEIVE_FILE_FAIL) {
        /*
         * For receiver, it may encounter error after sending TRANSFER DONE frame.
         * In such case, we just stop the state machine and report finish to user.
         */
        DFILE_LOGW(TAG, "transId %u, Receiver error during state %s - code %d, ignore and finish receiving process",
            dFileTrans->transId, GetReceiveStateMessage(dFileTrans->recvState), dFileTrans->errorCode);
        nextState = STATE_RECEIVE_FILE_DONE;
    }

    if (dFileTrans->errorCode != DFILE_TRANS_NO_ERROR) {
        DFILE_LOGE(TAG, "transId %u error: %s", dFileTrans->transId, GetErrorMessage(dFileTrans->errorCode));
    }
    dFileTrans->recvState = nextState;

    if ((nextState == STATE_RECEIVE_FILE_DONE || nextState == STATE_RECEIVE_FILE_FAIL) &&
        dFileTrans->fileManagerTaskStarted) {
        DFILE_LOGI(TAG, "transId %u, Receive state: %s -> %s", dFileTrans->transId,
            GetReceiveStateMessage(dFileTrans->recvState), GetReceiveStateMessage(nextState));
        if (FileManagerStopTask(dFileTrans->fileManager, dFileTrans->transId, FILE_LIST_TRANSFER_FINISH) !=
            NSTACKX_EOK) {
            DFILE_LOGE(TAG, "transId %u FileManagerStopTask failed", dFileTrans->transId);
        }
        dFileTrans->fileManagerTaskStarted = NSTACKX_FALSE;
    }
#if DFILE_SHOW_RECEIVE_TIME
    if (nextState == STATE_RECEIVE_FILE_DONE) {
        CalculateRecvRate(dFileTrans);
    }
#endif
}

static void ReceiverFsm(DFileTrans *dFileTrans)
{
    DFileReceiveState nextState = dFileTrans->recvState;

    do {
        switch (dFileTrans->recvState) {
            case STATE_RECEIVE_FILE_INIT:
                nextState = STATE_RECEIVE_FILE_HEADER_ONGOING;
                dFileTrans->session->transFlag = NSTACKX_TRUE;
                dFileTrans->fileManager->transFlag = NSTACKX_TRUE;
                break;
            case STATE_RECEIVE_FILE_HEADER_ONGOING:
                ReceiveFileHeaderOngoing(dFileTrans, &nextState);
                break;
            case STATE_SEND_FILE_HEADER_CONFIRM:
                SendFileHeaderConfirm(dFileTrans, &nextState);
                break;
            case STATE_RECEIVE_FILE_DATA_ONGOING:
                ReceiveFileDataOngoing(dFileTrans, &nextState);
                break;
            case STATE_SEND_FILE_DATA_ACK:
                SendFileDataAck(dFileTrans, &nextState);
                break;
            case STATE_SEND_FILE_TRANSFER_DONE:
                SendFileTransferDoneFrame(dFileTrans, &nextState);
                break;
            case STATE_WAIT_FOR_FILE_TRANSFER_DONE_ACK:
                WaitForFileTransferDoneAck(dFileTrans, &nextState);
                break;
            default:
                break;
        }
        if (dFileTrans->recvState == nextState) {
            break;
        }
        SetReceiveState(dFileTrans, nextState);
    } while (dFileTrans->recvState != STATE_RECEIVE_FILE_FAIL && dFileTrans->recvState != STATE_RECEIVE_FILE_DONE);
}

static void TransferFsm(DFileTrans *dFileTrans)
{
    if (dFileTrans->isSender) {
        SenderFsm(dFileTrans);
    } else {
        ReceiverFsm(dFileTrans);
    }
}

static int32_t RenameFileIfExisting(DFileTrans *dFileTrans)
{
    DFileRenamePara renamePara;
    uint16_t pathType = FileListGetPathType(dFileTrans->fileList);
    if (dFileTrans->onRenameFile == NULL) {
        return NSTACKX_EOK;
    }
    for (uint16_t i = 0; i < FileListGetNum(dFileTrans->fileList); i++) {
        const char *fileName = FileListGetFileName(dFileTrans->fileList, i + 1);
        (void)memset_s(&renamePara, sizeof(DFileRenamePara), 0, sizeof(DFileRenamePara));
        renamePara.rootPathType = pathType;
        renamePara.initFileName = fileName;
        dFileTrans->onRenameFile(&renamePara);

        if (strlen(renamePara.newFileName) == 0 || strlen(renamePara.newFileName) + 1 > NSTACKX_MAX_REMOTE_PATH_LEN) {
            DFILE_LOGE(TAG, "transId %u rename file %s failed remotePath too long", dFileTrans->transId, fileName);
            return NSTACKX_EFAILED;
        }
        if (GetFileNameLen(renamePara.newFileName) > NSTACKX_MAX_FILE_NAME_LEN) {
            DFILE_LOGE(TAG, "transId %u rename file %s failed newFileName too long", dFileTrans->transId, fileName);
            return NSTACKX_EFAILED;
        }
        if (FileListRenameFile(dFileTrans->fileList, i + 1, renamePara.newFileName) != NSTACKX_EOK) {
            DFILE_LOGE(TAG, "transId %u FileListRenameFile  failed", dFileTrans->transId);
            return NSTACKX_EFAILED;
        }
    }
    return NSTACKX_EOK;
}

static int32_t HandleFileNameTableFrame(DFileTrans *dFileTrans, DFileFrame *dFileFrame)
{
    if (dFileTrans->isSender) {
        return NSTACKX_EFAILED;
    }

    if (dFileTrans->recvState != STATE_RECEIVE_FILE_INIT &&
        dFileTrans->recvState != STATE_RECEIVE_FILE_HEADER_ONGOING &&
        dFileTrans->recvState != STATE_SEND_FILE_HEADER_CONFIRM &&
        dFileTrans->recvState != STATE_RECEIVE_FILE_DATA_ONGOING) {
        return NSTACKX_EFAILED;
    }

    if (DecodeFileHeaderFrame(dFileTrans->fileList, (FileHeaderFrame *)dFileFrame) != NSTACKX_EOK) {
        DFILE_LOGE(TAG, "decode file hearder frame failed");
    }

    if (!dFileTrans->allFileNameReceived) {
        /* Check whether all file names are receviced only when previous allFileNameReceived is false */
        dFileTrans->allFileNameReceived = FileListAllFileNameReceived(dFileTrans->fileList);
        if (dFileTrans->allFileNameReceived) {
            if (RenameFileIfExisting(dFileTrans) != NSTACKX_EOK) {
                dFileTrans->errorCode = DFILE_TRANS_FILE_RENAME_FAIL;
                NotifyTransMsg(dFileTrans, DFILE_TRANS_MSG_FILE_RECEIVE_FAIL);
                dFileTrans->allFileNameReceived = NSTACKX_FALSE;
            }

            NotifyTransMsg(dFileTrans, DFILE_TRANS_MSG_FILE_LIST_RECEIVED);
        }
    } else {
        dFileTrans->dupFileName = NSTACKX_TRUE;
    }
    return NSTACKX_EOK;
}

static int32_t HandleFileTableAckFrame(DFileTrans *dFileTrans, DFileFrame *dFileFrame)
{
    if (!dFileTrans->isSender) {
        return NSTACKX_EFAILED;
    }
    dFileTrans->lostAckCnt = 0;
    if (dFileTrans->sendState != STATE_SEND_FILE_HEADER_ONGOING &&
        dFileTrans->sendState != STATE_WAIT_FOR_FILE_HEADER_CONFIRM) {
        return NSTACKX_EFAILED;
    }

    if (DecodeFileHeaderConfirmFrame(dFileTrans->fileList, (FileHeaderConfirmFrame *)dFileFrame) != NSTACKX_EOK) {
        return NSTACKX_EFAILED;
    }
    return NSTACKX_EOK;
}

static void UpdateTransParam(DFileTrans *dFileTrans, uint8_t endFlag, uint16_t fileId, uint16_t len)
{
    uint32_t maxFileId = FileListGetNum(dFileTrans->fileList);
    if (endFlag) {
        FileListSetLastBlockReceived(dFileTrans->fileList, fileId);
        DFILE_LOGI(TAG, "transId %u recv the end frame fileId %hu", dFileTrans->transId, fileId);
    }
    if (FileListGetLastBlockReceived(dFileTrans->fileList, (uint16_t)maxFileId)) {
        dFileTrans->shouldSendAckDividor = NSTACKX_SEND_ACK_PER_TWO_RECYCLE;
        if (!dFileTrans->recvLastFramePrint) {
            DFILE_LOGI(TAG, "transId %u recv the last frame", dFileTrans->transId);
            dFileTrans->recvLastFramePrint = NSTACKX_TRUE;
        }
    }
    if (FileListGetLastBlockReceived(dFileTrans->fileList, (uint16_t)maxFileId) &&
        dFileTrans->receivedDataFrameCnt >= dFileTrans->adjustAckIntervalLimit) {
        if (!dFileTrans->adjustToLastFrameAckInterval) {
            dFileTrans->ackInterval = dFileTrans->config.lastFrameAckInterval;
            dFileTrans->adjustToLastFrameAckInterval = NSTACKX_TRUE;
        }

        dFileTrans->shouldSendAckDividor = NSTACKX_SEND_ACK_PER_ONE_RECYCLE;

        if (!dFileTrans->adjustAckIntervalLimitPrint) {
            DFILE_LOGI(TAG, "transId %u dFileTrans->ackInterval %u", dFileTrans->transId, dFileTrans->ackInterval);
            dFileTrans->adjustAckIntervalLimitPrint = NSTACKX_TRUE;
        }
    }
    if (endFlag && fileId == maxFileId) {
        DFileReceiveState nextState;
        DFILE_LOGI(TAG, "send all retry packets");
        SendFileDataAck(dFileTrans, &nextState);
    }
    dFileTrans->receivedDataFrameCnt++;
    dFileTrans->bytesTransferred += len;
    if (dFileTrans->bytesTransferred <
        dFileTrans->bytesTransferredLastRecord + NSTACKX_KILO_BYTES * KILO_BYTES_TRANSFER_NOTICE_THRESHOLD) {
        return;
    }
    dFileTrans->bytesTransferredLastRecord = dFileTrans->bytesTransferred;
    if (dFileTrans->bytesTransferred >= dFileTrans->totalBytes) {
        return;
    } else {
        NotifyTransProgress(dFileTrans, dFileTrans->bytesTransferred);
    }
}

static int32_t WriteDataFrame(DFileTrans *dFileTrans, FileDataFrame *dataFrame)
{
    uint16_t fileId = ntohs(dataFrame->fileId);
    uint16_t len = ntohs(dataFrame->header.length) + sizeof(DFileFrameHeader) - sizeof(FileDataFrame);
    uint8_t endFlag = CheckDfileFrameEndFlag(dataFrame);

    int32_t ret = FileManagerFileWrite(dFileTrans->fileManager, dataFrame);
    if (ret != NSTACKX_EOK) {
        DFILE_LOGE(TAG, "FileManagerFileWrite failed! ret %d", ret);
        dFileTrans->errorCode = DFILE_TRANS_FILE_WRITE_FAIL;
        SetReceiveState(dFileTrans, STATE_RECEIVE_FILE_FAIL);
        return ret;
    }
    UpdateTransParam(dFileTrans, endFlag, fileId, len);

    return NSTACKX_EOK;
}

static int32_t CheckReceiverTransAndFrameValid(const DFileTrans *dFileTrans, const FileDataFrame *dataFrame)
{
    if (ntohs(dataFrame->header.length) <= sizeof(FileDataFrame) - sizeof(DFileFrameHeader)) {
        return NSTACKX_EFAILED;
    }

    if (dFileTrans->isSender || (dFileTrans->recvState != STATE_RECEIVE_FILE_DATA_ONGOING &&
        dFileTrans->recvState != STATE_SEND_FILE_DATA_ACK)) {
        return NSTACKX_EFAILED;
    }

    /* validate file id */
    if (GetFileIdFromFileDataFrame(dFileTrans->fileList, dataFrame) == NSTACKX_RESERVED_FILE_ID) {
        DFILE_LOGE(TAG, "dFileTrans %u error. GetFileIdFromFileDataFrame failed", dFileTrans->transId);
        return NSTACKX_EFAILED;
    }
    return NSTACKX_EOK;
}

static int32_t HandleFileDataFrame(DFileTrans *trans, DFileFrame *dFileFrame)
{
    FileDataFrame *dataFrame = (FileDataFrame *)dFileFrame;

    int32_t ret = NSTACKX_EFAILED;
    uint8_t received;
    if (CheckReceiverTransAndFrameValid(trans, dataFrame)) {
        goto L_ERR;
    }
    trans->recvCount++;

    if (FileManagerIsRecvBlockWritable(trans->fileManager, trans->transId) != NSTACKX_TRUE) {
        trans->recvBlockListFullTimes++;
        goto L_TIMESTAMP_UPDATE;
    }

    ret = WriteDataFrame(trans, dataFrame);
    if (ret != NSTACKX_EOK) {
        DFILE_LOGE(TAG, "transId %u error. WriteDataFrame ret == %d", trans->transId, ret);
        goto L_ERR;
    }

    received = FileListGetLastBlockReceived(trans->fileList, FileListGetNum(trans->fileList));
    if (trans->receivedDataFrameCnt >= trans->totalDataFrameCnt) {
        DFILE_LOGI(TAG, "transId:%u last block received:%u", trans->transId, received);
        if (received) {
            trans->allFileDataReceived = NSTACKX_TRUE;
            DFILE_LOGI(TAG, "transId %u FINISH!!! retry send %u retry num %u not Insert Count %u %llu/%llu "
                "recvblocklist full times %llu totalSend %llu totalRecv %llu",
                trans->transId, trans->allRetrySendCount, trans->allRetryCount, trans->notInsertCount,
                trans->receivedDataFrameCnt, trans->totalDataFrameCnt, trans->recvBlockListFullTimes,
                trans->session->totalSendBlocks, trans->session->totalRecvBlocks);
        }
    }

L_TIMESTAMP_UPDATE:
    ClockGetTime(CLOCK_MONOTONIC, &trans->ts);
L_ERR:
    return ret;
}

static int32_t HandleTransferDoneFrame(DFileTrans *dFileTrans, DFileFrame *dFileFrame)
{
    if (!dFileTrans->isSender) {
        return NSTACKX_EFAILED;
    }

    if (dFileTrans->sendState != STATE_WAIT_FOR_FILE_TRANSFER_DONE_FRAME &&
        dFileTrans->sendState != STATE_SEND_FILE_TRANSFER_DONE_ACK &&
        dFileTrans->sendState != STATE_SEND_FILE_DATA_ONGOING) {
        DFILE_LOGE(TAG, "transId %u, HandleTransferDoneFrame failed.sendState %d",
             dFileTrans->transId, dFileTrans->sendState);
        return NSTACKX_EFAILED;
    }

    if (!dFileTrans->fileTransferDoneReceived) {
        dFileTrans->fileTransferDoneReceived = NSTACKX_TRUE;
        if (DecodeFileTransferDoneFrame(dFileTrans->fileList, (FileTransferDoneFrame *)dFileFrame) != NSTACKX_EOK) {
            return NSTACKX_EFAILED;
        }
    }
    return NSTACKX_EOK;
}

int32_t HandleDFileFrame(DFileTrans *dFileTrans, DFileFrame *dFileFrame)
{
    int32_t ret = NSTACKX_EFAILED;

    if (dFileTrans->mtu == 0 || DFileTransStateFinished(dFileTrans)) {
        return ret;
    }

    if (dFileFrame->header.type != NSTACKX_DFILE_FILE_DATA_FRAME) {
        DFILE_LOGI(TAG, "transId %u, Handle frame (%hhu):%s",
             dFileTrans->transId, dFileFrame->header.type, GetFrameName(dFileFrame->header.type));
    }

    switch (dFileFrame->header.type) {
        case NSTACKX_DFILE_FILE_HEADER_FRAME:
            ret = HandleFileNameTableFrame(dFileTrans, dFileFrame);
            break;
        case NSTACKX_DFILE_FILE_HEADER_CONFIRM_FRAME:
            ret = HandleFileTableAckFrame(dFileTrans, dFileFrame);
            break;
        case NSTACKX_DFILE_FILE_DATA_FRAME:
            ret = HandleFileDataFrame(dFileTrans, dFileFrame);
            break;
        case NSTACKX_DFILE_FILE_TRANSFER_DONE_FRAME:
            ret = HandleTransferDoneFrame(dFileTrans, dFileFrame);
            break;
        case NSTACKX_DFILE_FILE_TRANSFER_DONE_ACK_FRAME:
            if (!dFileTrans->isSender) {
                dFileTrans->fileTransferDoneAcked = NSTACKX_TRUE;
            }
            ret = NSTACKX_EOK;
            break;
        default:
            break;
    }

    /* Continue FSM as per frame */
    TransferFsm(dFileTrans);
    if (dFileTrans->isAckSend) {
        NotifyTransMsg(dFileTrans, DFILE_TRANS_MSG_FILE_SEND_ACK);
        dFileTrans->isAckSend = NSTACKX_FALSE;
    }
    DFileTransNotifyEndMsg(dFileTrans);

    return ret;
}

void DFileTransProcess(DFileTrans *dFileTrans)
{
    if (dFileTrans->mtu == 0 || DFileTransStateFinished(dFileTrans)) {
        return;
    }

    TransferFsm(dFileTrans);
    dFileTrans->isAckSend = NSTACKX_FALSE;
    DFileTransNotifyEndMsg(dFileTrans);
}

static uint32_t GetRemainingTime(uint32_t maxTime, const struct timespec *now, const struct timespec *ts)
{
    uint32_t elapseTime = GetTimeDiffMs(now, ts);
    if (elapseTime >= maxTime) {
        return 0;
    } else {
        return maxTime - elapseTime;
    }
}

static int64_t SenderGetTimeout(DFileTrans *dFileTrans)
{
    struct timespec now;

    if (dFileTrans->sendState != STATE_WAIT_FOR_FILE_HEADER_CONFIRM &&
        dFileTrans->sendState != STATE_SEND_FILE_DATA_ONGOING &&
        dFileTrans->sendState != STATE_WAIT_FOR_FILE_TRANSFER_DONE_FRAME) {
        return NSTACKX_EFAILED;
    }

    ClockGetTime(CLOCK_MONOTONIC, &now);
    uint32_t remainTime = GetRemainingTime(dFileTrans->timeout, &now, &dFileTrans->ts);

    return (int64_t)remainTime;
}

static int64_t ReceiverGetTimeout(DFileTrans *dFileTrans)
{
    struct timespec now;
    if (dFileTrans->recvState != STATE_RECEIVE_FILE_HEADER_ONGOING &&
        dFileTrans->recvState != STATE_RECEIVE_FILE_DATA_ONGOING &&
        dFileTrans->recvState != STATE_SEND_FILE_TRANSFER_DONE &&
        dFileTrans->recvState != STATE_WAIT_FOR_FILE_TRANSFER_DONE_ACK) {
        return NSTACKX_EFAILED;
    }

    ClockGetTime(CLOCK_MONOTONIC, &now);
    uint32_t remainTime = GetRemainingTime(dFileTrans->timeout, &now, &dFileTrans->ts);
    if (dFileTrans->recvState == STATE_RECEIVE_FILE_DATA_ONGOING) {
        uint32_t remainTimeHeartBeat = GetRemainingTime(dFileTrans->ackInterval, &now, &dFileTrans->heartBeatTs);
        if (remainTime > remainTimeHeartBeat) {
            remainTime = remainTimeHeartBeat;
        }
    }

    return (int64_t)remainTime;
}

int64_t DFileTransGetTimeout(DFileTrans *dFileTrans)
{
    if (dFileTrans->isSender) {
        return SenderGetTimeout(dFileTrans);
    } else {
        return ReceiverGetTimeout(dFileTrans);
    }
}

int32_t DFileTransSetMtu(DFileTrans *dFileTrans, uint16_t mtu)
{
    if (mtu <= offsetof(FileDataFrame, blockPayload) || mtu > NSTACKX_MAX_FRAME_SIZE) {
        return NSTACKX_EINVAL;
    }

    if (dFileTrans->mtu == mtu) {
        return NSTACKX_EOK;
    }

    dFileTrans->mtu = mtu;
    return NSTACKX_EOK;
}

DFileTrans *DFileTransCreate(const DFileTransPara *para)
{
    DFileTrans *dFileTrans = malloc(sizeof(DFileTrans));
    if (dFileTrans == NULL) {
        return NULL;
    }
    (void)memset_s(dFileTrans, sizeof(DFileTrans), 0, sizeof(DFileTrans));

    dFileTrans->fileList = FileListCreate();
    if (dFileTrans->fileList == NULL) {
        free(dFileTrans);
        return NULL;
    }

    dFileTrans->lastSentHeaderFileId = -1;
    dFileTrans->isSender = para->isSender;
    dFileTrans->transId = para->transId;
    dFileTrans->fileManager = para->fileManager;
    dFileTrans->connType = para->connType;
    dFileTrans->writeHandle = para->writeHandle;
    dFileTrans->msgReceiver = para->msgReceiver;
    dFileTrans->context = para->context;
    dFileTrans->session = para->session;
    dFileTrans->onRenameFile = para->onRenameFile;
    dFileTrans->shouldSendAckDividor = NSTACKX_SEND_ACK_PER_THREE_RECYCLE;
    ListInitHead(&dFileTrans->retryList);

    if (ConfigDFileTrans(dFileTrans->connType, &dFileTrans->config) != NSTACKX_EOK) {
        FileListDestroy(dFileTrans->fileList);
        free(dFileTrans);
        return NULL;
    }

    return dFileTrans;
}

void DFileTransDestroy(DFileTrans *dFileTrans)
{
    dFileTrans->session->allTaskCount--;
    DFileTransDestroyInner(dFileTrans);
}

void DFileTransDestroyInner(DFileTrans *dFileTrans)
{
    free(dFileTrans->remainDataFrame);
    dFileTrans->remainDataFrame = NULL;

    if (dFileTrans->fileManagerTaskStarted) {
        DFILE_LOGI(TAG, "transId %u FileManagerStopTask", dFileTrans->transId);
        if (FileManagerStopTask(dFileTrans->fileManager, dFileTrans->transId, FILE_LIST_TRANSFER_FINISH) !=
            NSTACKX_EOK) {
            DFILE_LOGE(TAG, "transId %u FileManagerStopTask failed", dFileTrans->transId);
        }
    }

    FileListDestroy(dFileTrans->fileList);
    free(dFileTrans);
}

uint64_t DFileTransGetTotalBytes(const DFileTrans *dFileTrans)
{
    if (dFileTrans == NULL) {
        return 0;
    }
    return GetFilesTotalBytes(dFileTrans->fileList);
}
