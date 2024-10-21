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

#ifndef NSTACKX_DFILE_TRANSFER_H
#define NSTACKX_DFILE_TRANSFER_H

#include <stdint.h>
#include <stdio.h>
#include "nstackx_list.h"
#include "nstackx_dfile.h"
#include "nstackx_util.h"
#include "nstackx_file_list.h"
#include "nstackx_dfile_frame.h"
#include "nstackx_file_manager.h"
#include "nstackx_dfile_config.h"
#include "nstackx_timer.h"
#include "nstackx_dev.h"

#define DFILE_SHOW_RECEIVE_TIME 1
#define NSTACKX_RETRY_HISTORY_DATA_ARRAY_SIZE   6
#define INTEGRAL_TIME 2

typedef enum {
    DFILE_TRANS_MSG_FILE_SEND_DATA,
    DFILE_TRANS_MSG_FILE_LIST_RECEIVED,
    DFILE_TRANS_MSG_FILE_RECEIVED, /* Receiver receive all the file data */
    DFILE_TRANS_MSG_FILE_RECEIVE_FAIL,
    DFILE_TRANS_MSG_FILE_RECEIVED_TO_FAIL,
    DFILE_TRANS_MSG_FILE_SENT, /* Sender send TRANSFER DONE ACK frame and come to end */
    DFILE_TRANS_MSG_FILE_SEND_FAIL,
    DFILE_TRANS_MSG_IN_PROGRESS,
    DFILE_TRANS_MSG_FILE_SEND_ACK,
    DFILE_TRANS_MSG_END,
} DFileTransMsgType;

typedef enum {
    DFILE_TRANS_NO_ERROR = 0,
    DFILE_TRANS_SOCKET_ERROR, /* Socket IO error */
    DFILE_TRANS_INTERNAL_ERROR, /* Internal error, such as no memory. */
    /* For sender */
    DFILE_TRANS_FILE_HEADER_CONFIRM_TIMEOUT, /* Wait for HEADER CONFIRM frame timeout */
    DFILE_TRANS_FILE_DATA_ACK_TIMEOUT, /* Heart beat (DATA ACK frame) timeout */
    DFILE_TRANS_TRANSFER_DONE_TIMEOUT, /* Wait for TRANSFER DONE frame timeout */
    /* For receiver */
    DFILE_TRANS_FILE_HEADER_TIMEOUT, /* Receive HEADER frame timeout (partially received) */
    DFILE_TRANS_FILE_DATA_TIMEOUT, /* Receive file data timeout (partially received) */
    /* Receiver wait for TRANSFER DONE ACK frame timeout, for debug purpose, won't report to user */
    DFILE_TRANS_TRANSFER_DONE_ACK_TIMEOUT,
    DFILE_TRANS_FILE_SEND_TASK_ERROR, /* Send task error */
    DFILE_TRANS_FILE_RECEIVE_TASK_ERROR, /* Receive task error */
    DFILE_TRANS_FILE_WRITE_FAIL, /* Write file list fail */
    DFILE_TRANS_FILE_RENAME_FAIL, /* Rename file fail */
} DFileTransErrorCode;

typedef enum {
    STATE_SEND_FILE_INIT = 0,
    STATE_SEND_FILE_HEADER_ONGOING,
    STATE_WAIT_FOR_FILE_HEADER_CONFIRM,
    STATE_SEND_FILE_DATA_ONGOING,
    STATE_WAIT_FOR_FILE_TRANSFER_DONE_FRAME,
    STATE_SEND_FILE_TRANSFER_DONE_ACK,
    STATE_SEND_FILE_DONE,
    STATE_SEND_FILE_FAIL,
} DFileSendState;

typedef enum {
    STATE_RECEIVE_FILE_INIT = 0,
    STATE_RECEIVE_FILE_HEADER_ONGOING,
    STATE_SEND_FILE_HEADER_CONFIRM,
    STATE_RECEIVE_FILE_DATA_ONGOING,
    STATE_SEND_FILE_DATA_ACK,
    STATE_SEND_FILE_TRANSFER_DONE,
    STATE_WAIT_FOR_FILE_TRANSFER_DONE_ACK,
    STATE_RECEIVE_FILE_DONE,
    STATE_RECEIVE_FILE_FAIL,
} DFileReceiveState;

struct DFileTrans;
/* Reuse DFileMsg for ease use */
typedef DFileMsg DFileTransMsg;

typedef int32_t (*DFileTransWriteHandle)(const uint8_t *frame, size_t len, void *context);
typedef void (*DFileTransMsgReceiver)(struct DFileTrans *dFileTrans, DFileTransMsgType msgType, DFileTransMsg *msg);

typedef struct {
    uint16_t lastRetranFileId;
    uint8_t lastRetranLevel;
    uint32_t sameRetraLostBlocks;
    uint32_t lastRetranFileSequence;
} RetranFileRecord;

typedef struct DFileTrans {
    List list;
    uint16_t transId;
    uint8_t isSender;
    DFileSendState sendState;
    DFileReceiveState recvState;
    /* members for sending file */
    uint8_t headerRetryCnt;
    uint8_t lostAckCnt;
    uint8_t fileTransferReqReceived; /* Flag: Receive File Transfer REQ frame */
    uint8_t fileTransferDoneReceived; /* Flag: Receive File Transfer Done frame */
    int32_t lastSentHeaderFileId;
    uint8_t *remainDataFrame;
    /* members for receiving file */
    struct timespec retryAllPacketTs;
    struct timespec heartBeatTs;
    uint16_t lastAckedHeaderFileId;
    uint16_t lastFileDataRecvFileId;
    uint32_t lastFileDataSequence;
    uint16_t prefileId;
    uint16_t haveRetransFilefileId;
    uint32_t preSequence;
    uint32_t haveRetransFilepreSequence;
    uint8_t headerAckRetryCnt;
    uint8_t idleTimeoutCnt;
    uint8_t allFileNameReceived;
    uint8_t dupFileName;
    uint8_t allFileDataReceived;
    uint8_t fileTransferDoneAcked;
    uint8_t transferDoneRetryCnt;
    uint8_t recvPacketFlag;
    uint8_t retransFileFlag;
    /* members for data lost and retry */
    List retryList;
    List *retryPointer;
    uint32_t retryCount;
    uint32_t allRetryCount;
    uint32_t allRetrySendCount;
    uint32_t shouldSendAck;
    uint32_t shouldSendAckDividor;

    uint32_t ackInterval;
    uint32_t transRetryCount;
    uint32_t notInsertCount;
#if DFILE_SHOW_RECEIVE_TIME
    struct timespec startTs;
#endif
    uint64_t totalDataFrameCnt;
    uint64_t receivedDataFrameCnt;
    uint64_t adjustAckIntervalLimit;
    uint8_t fileManagerTaskStarted;
    uint8_t isRecvSucMsgNotified;
    uint8_t isAckSend;
    uint8_t recvLastFramePrint;
    uint8_t adjustAckIntervalLimitPrint;
    uint8_t adjustToLastFrameAckInterval;
    uint8_t sendRetransFileCount;
    uint8_t ioWriteFinishFlag;

    uint16_t connType;
    uint16_t mtu;
    DFileTransConfig config;
    DFileTransErrorCode errorCode;
    uint32_t timeout;
    struct timespec ts;
    uint8_t sendBuffer[NSTACKX_MAX_FRAME_SIZE];
    size_t sendBufferLength;
    FileList *fileList;
    FileManager *fileManager;
    DFileTransWriteHandle writeHandle;
    DFileTransMsgReceiver msgReceiver;
    void *context;
    DFileSession *session;

    uint64_t bytesTransferredLastRecord; /* just usefully for receiver */
    uint64_t bytesTransferred; /* just usefully for receiver */
    uint64_t totalBytes;  /* just usefully for receiver */
    uint64_t recvBlockListFullTimes;
    OnDFileRenameFile onRenameFile;
    uint32_t recvCount;
    uint32_t backPressureBypassCnt;
} DFileTrans;

typedef struct {
    uint8_t isSender;
    uint16_t transId;
    ConnectType connType;
    FileManager *fileManager;
    DFileTransWriteHandle writeHandle;
    DFileTransMsgReceiver msgReceiver;
    void *context;
    DFileSession *session;
    OnDFileRenameFile onRenameFile;
} DFileTransPara;

typedef enum SettingState {
    SETTING_NEGOTIATING = 0,
    SETTING_NEGOTIATED
} SettingState;

typedef struct PeerInfo {
    List list;
    struct sockaddr_in dstAddr;
    char localInterfaceName[IFNAMSIZ];
    DFileSession *session;
    Timer *settingTimer;
    struct PeerInfo *brotherPeer;
    uint64_t overRun;
    uint16_t localMtu;
    uint16_t mtu;
    uint16_t mtuInuse;
    uint16_t dataFrameSize;
    uint16_t connType;
    uint8_t settingTimeoutCnt;
    uint8_t socketIndex;
    int32_t remoteSessionId;
    SettingState state;

    /* congestion control info */
    WifiStationInfo rxWifiStationInfo; /* save the bitrate of the server endian to calculate the sendrate */
    int8_t rxWifiStationInfoStatus;
    double integralLossRate[INTEGRAL_TIME];
    uint32_t fastStartCounter;
    /* qdisc info */
    uint16_t qdiscMaxLeft;
    uint16_t qdiscMinLeft;
    uint32_t qdiscSearchNum;
    uint32_t qdiscAveLeft;

    FlowCtrlInfo flowCtrlInfo; /* flow control info */

    struct timespec startTime;
    uint32_t sendCount;
    uint32_t sendCountRateMB;
    uint16_t sendRate;
    uint16_t maxSendRate;
    uint32_t sendFrameRate;
    uint32_t intervalSendCount;
    int32_t amendSendRate;
    uint8_t decreaseStatus;
    uint8_t gotWifiRate;
    uint16_t sendAckNum;
    uint32_t eAgainCount;
    struct timespec measureBefore;
    struct timespec ackDropTimer;
    uint32_t maxRetryCountPerSec;
    uint32_t maxRetryCountLastSec;

    uint32_t recvCount;
    uint32_t recvFrameRate;
    uint32_t recvCountRateMB;
    uint32_t allDtransRetryCount;

    uint32_t retryCountHistoryData[NSTACKX_RETRY_HISTORY_DATA_ARRAY_SIZE];
    uint16_t sendRateHistoryData[NSTACKX_RETRY_HISTORY_DATA_ARRAY_SIZE];
    uint16_t recvRateHistoryData[NSTACKX_RETRY_HISTORY_DATA_ARRAY_SIZE];
    uint16_t locationHistoryData;
    uint16_t ackInterval;
    uint32_t rateStateInterval;
    uint32_t remoteDFileVersion;
    uint32_t linkSequence;
    uint32_t lastMaxSeq;
    uint32_t lastTimes;
    uint32_t duplicateCount;
    uint32_t currentTransCount;
} PeerInfo;

static inline void ClearPeerinfoStats(PeerInfo *peerInfo)
{
    peerInfo->sendCount = 0;
    peerInfo->qdiscMinLeft = 0;
    peerInfo->qdiscMaxLeft = 0;
    peerInfo->qdiscAveLeft = 0;
    peerInfo->qdiscSearchNum = 0;
}

int32_t DFileTransSendFiles(DFileTrans *trans, FileListInfo *fileListInfo);
int32_t DFileTransAddExtraInfo(DFileTrans *trans, uint16_t pathType, uint8_t noticeFileNameType, char *userData);
int32_t HandleDFileFrame(DFileTrans *dFileTrans, DFileFrame *dFileFrame);
void DFileTransProcess(DFileTrans *dFileTrans);
int64_t DFileTransGetTimeout(DFileTrans *dFileTrans);
int32_t DFileTransSetMtu(DFileTrans *dFileTrans, uint16_t mtu);

DFileTrans *DFileTransCreate(const DFileTransPara *para);
void DFileTransDestroy(DFileTrans *dFileTrans);
void DFileTransDestroyInner(DFileTrans *dFileTrans);
uint64_t DFileTransGetTotalBytes(const DFileTrans *dFileTrans);
void FileManagerReceiverMsgHandler(uint16_t fileId, FileManagerMsgType msgType, FileManagerMsg *msg,
                                   DFileTrans *dFileTrans);
void FileManagerSenderMsgHandler(uint16_t fileId, FileManagerMsgType msgType, FileManagerMsg *msg,
                                 DFileTrans *dFileTrans);
int32_t SendFrame(DFileTrans *dFileTrans, uint8_t *frame, size_t frameLength, DFileSendState *nextSend,
                  DFileReceiveState *nextRecv);
void ReviewSuccessMsg(const DFileTrans *dFileTrans, DFileTransMsgType *msgType,
    DFileTransMsg *msg, char *files[]);
#endif /* NSTACKX_DFILE_TRANSFER_H */
