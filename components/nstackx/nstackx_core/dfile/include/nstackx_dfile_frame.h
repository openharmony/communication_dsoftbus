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

#ifndef NSTACKX_DFILE_FRAME_H
#define NSTACKX_DFILE_FRAME_H

#include <stdint.h>
#include <time.h>
#include "nstackx_list.h"
#include "nstackx_file_list.h"
#include "nstackx_congestion.h"

#ifdef __cplusplus
extern "C" {
#endif

/* RST_CODE */
#define NSTACKX_DFILE_NO_ERROR                200
#define NSTACKX_DFILE_WITHOUT_SETTING_ERROR   201
#define NSTACKX_DFILE_FILE_WRITE_ERROR        202
#define NSTACKX_DFILE_FILE_READ_ERROR         203
#define NSTACKX_DFILE_NO_ENOUGH_STORAGE_ERROR 204
#define NSTACKX_DFILE_INTERNAL_ERROR          209
#define NSTACKX_DFILE_CANCEL_ERROR            210

#define NSTACKX_DFILE_HEADER_FRAME_USER_DATA_FLAG 0x1
#define NSTACKX_DFILE_HEADER_FRAME_PATH_TYPE_FLAG 0x2
#define NSTACKX_DFILE_HEADER_FRAME_NO_SYNC_FLAG 0x4
#define NSTACKX_DFILE_HEADER_FRAME_VTRANS_FLAG 0x8

#define NSTACKX_DFILE_DATA_FRAME_START_FLAG 0x0
#define NSTACKX_DFILE_DATA_FRAME_CONTINUE_FLAG 0x1
#define NSTACKX_DFILE_DATA_FRAME_END_FLAG 0x3
#define NSTACKX_DFILE_DATA_FRAME_RETRAN_FLAG 0x4

#define NSTACKX_DFILE_ACK_RETRAN_FILE_FLAG 0x1

#define NSTACKX_RESERVED_FILE_ID 0
#define NSTACKX_FIRST_FILE_ID 1

#define NSTACKX_MAX_FRAME_SIZE              14720
#define NSTACKX_DEFAULT_FRAME_SIZE          1472
#define NSTACKX_MAX_USER_DATA_SIZE          1024
#define NSTACKX_MAX_FILE_SIZE               (0x7FFFFFFFFF) /* Max file size 512GB */
#define NSTACKX_MIN_MTU_SIZE                64

typedef enum {
    NSTACKX_DFILE_FILE_HEADER_FRAME = 1,
    NSTACKX_DFILE_FILE_HEADER_CONFIRM_FRAME,
    NSTACKX_DFILE_FILE_TRANSFER_REQ_FRAME,
    NSTACKX_DFILE_FILE_DATA_FRAME,
    NSTACKX_DFILE_FILE_DATA_ACK_FRAME,
    NSTACKX_DFILE_FILE_TRANSFER_DONE_FRAME,
    NSTACKX_DFILE_FILE_TRANSFER_DONE_ACK_FRAME,
    NSTACKX_DFILE_SETTING_FRAME,
    NSTACKX_DFILE_RST_FRAME,
    NSTACKX_DFILE_FLOW_CONTROL_FRAME,
    NSTACKX_DFILE_CONGESTION_CONTROL_FRAME,
    NSTACKX_DFILE_PEER_DOWN_FRAME,
    NSTACKX_DFILE_FILE_BACK_PRESSURE_FRAME,
    NSTACKX_DFILE_TYPE_MAX
} DFileFrameType;

#pragma pack(push, 1)
typedef struct {
    uint8_t type;
    uint8_t flag;
    uint16_t sessionId;
    uint16_t transId;
    uint16_t length;
} DFileFrameHeader;

#define DFILE_FRAME_HEADER_LEN sizeof(DFileFrameHeader)

typedef struct {
    uint16_t fileId;
    uint64_t fileSize;
    uint16_t fileNameLength;
    uint8_t fileName[0];
} FileInfoUnit;

typedef struct {
    uint16_t fileId;
    uint64_t fileSize;
    uint16_t fileNameLength;
    uint64_t startOffset;
    uint8_t fileName[0];
} FileInfoUnitMp;

typedef struct {
    uint16_t pathType;
    uint8_t userData[0];
} UserDataUnit;

typedef struct {
    DFileFrameHeader header;
    uint16_t nodeNumber;
    uint8_t fileInfoUnit[0];
} FileHeaderFrame;

typedef struct {
    DFileFrameHeader header;
    uint16_t fileId[0];
} FileHeaderConfirmFrame;

typedef struct {
    DFileFrameHeader header;
    uint16_t fileId[0];
} FileTransferReqFrame;

typedef struct {
    DFileFrameHeader header;
    uint16_t fileId;
    uint32_t blockSequence;
    uint8_t blockPayload[0];
} FileDataFrame;

typedef struct {
    DFileFrameHeader header;
    uint16_t fileId;
    uint32_t blockSequence;
    uint32_t linkSequence;
    uint8_t socketIndex;
    uint8_t blockPayload[0];
} FileDataFrameZS;

typedef struct {
    uint8_t recvListOverIo;
    uint8_t recvBufThreshold; /* for reserved */
    uint32_t stopSendPeriod;
} DataBackPressure;

typedef struct {
    DFileFrameHeader header;
    DataBackPressure backPressure;
} BackPressureFrame;

typedef struct {
    DFileFrameHeader header;
    uint16_t fileId[0];
} FileTransferDoneFrame;

typedef struct {
    DFileFrameHeader header;
    uint16_t fileId[0];
} FileTransferDoneAckFrame;

#define VERSION_STR_LEN 64
typedef struct {
    DFileFrameHeader header;
    uint16_t mtu;
    uint16_t connType;
    uint32_t dFileVersion;
    uint32_t abmCapability; /* keep the same format of SettingFrame with Hicomm branch */
    uint32_t capability;
    uint32_t dataFrameSize;
    uint32_t capsCheck;
    char productVersion[VERSION_STR_LEN]; /* DFX */
    uint8_t isSupport160M;
    uint8_t isSupportMtp;
    uint8_t mtpPort;
    uint8_t headerEnc;
    uint32_t mtpCapability;
    uint32_t cipherCapability;
} SettingFrame;

typedef struct {
    DFileFrameHeader header;
    uint16_t code;
    uint16_t fileId[0];
} RstFrame;

typedef struct {
    DFileFrameHeader header;
    WifiStationInfo wifiStationInfo;
    RamInfo ramInfo;
} CongestionControlFrame;
#pragma pack(pop)

typedef struct {
    uint32_t flowCtrlType;
    uint32_t kernelRecvQueueDropPacket;
    uint32_t kernelRecvQueueRate;
    uint32_t appProcessQueueRatio;
    uint32_t appProcessQueueRate;
    uint32_t sysTemperature;
} FlowCtrlInfo;

#pragma pack(push, 1)
typedef struct {
    DFileFrameHeader header;
    FlowCtrlInfo flowCtrlInfo;
} FlowCtrlFrame;

typedef struct {
    DFileFrameHeader header;
    uint8_t payload[0];
} DFileFrame;
#pragma pack(pop)

static inline void SetDfileFrameTransID(DFileFrame *dFileFrame, uint16_t value)
{
    (dFileFrame)->header.transId = htons(value);
    return;
}

static inline void SetDfileFrameUserDataFlag(DFileFrameHeader *header)
{
    header->flag |= NSTACKX_DFILE_HEADER_FRAME_USER_DATA_FLAG;
    return;
}

static inline void SetDfileFramePathTypeFlag(DFileFrameHeader *header)
{
    header->flag |= NSTACKX_DFILE_HEADER_FRAME_PATH_TYPE_FLAG;
    return;
}

static inline void SetDfileFrameNoSyncFlag(DFileFrameHeader *header)
{
    header->flag |= NSTACKX_DFILE_HEADER_FRAME_NO_SYNC_FLAG;
}

static inline uint8_t CheckDfileFrameEndFlag(FileDataFrame *fileDataFrame)
{
    return (((fileDataFrame)->header.flag & NSTACKX_DFILE_DATA_FRAME_END_FLAG) == NSTACKX_DFILE_DATA_FRAME_END_FLAG);
}

const char *GetFrameName(DFileFrameType frameType);
void EncodeFileHeaderFrame(FileList *fileList, int32_t *fileId, uint8_t *buffer, size_t length, size_t *frameLength);
void EncodeFileHeaderConfirmFrame(FileList *fileList, uint16_t *fileId, uint8_t *buffer, size_t length,
                                  size_t *frameLength);
int32_t EncodeFileDataFrame(FileList *fileList, uint16_t fileId, uint8_t *buffer, size_t length, size_t *frameLength);
void EncodeFileTransferDoneFrame(uint8_t *buffer, size_t length, uint16_t fileIdList[], uint32_t fileIdNum,
                                 size_t *frameLength);
void EncodeFileTransferDoneAckFrame(uint8_t *buffer, size_t length, uint16_t transId, size_t *frameLength);
void EncodeSettingFrame(uint8_t *buffer, size_t length, size_t *frameLength, const SettingFrame *settingFramePara);
void EncodeRstFrame(uint8_t *buffer, size_t length, size_t *frameLength, uint16_t transId, uint16_t errCode);
void EncodeBackPressFrame(uint8_t *buffer, size_t length, size_t *frameLength, uint8_t recvListOverIo);
int32_t DecodeDFileFrame(const uint8_t *buffer, size_t bufferLength, DFileFrame **frame);
int32_t DecodeFileHeaderFrame(FileList *fileList, FileHeaderFrame *headerFrame);
int32_t DecodeFileHeaderConfirmFrame(FileList *fileList, FileHeaderConfirmFrame *confirmFrame);
int32_t DecodeFileDataFrame(FileList *fileList, FileDataFrame *dataFrame);
int16_t GetFileIdFromFileDataFrame(const FileList *fileList, const FileDataFrame *fileDataFrame);
int32_t DecodeFileTransferDoneFrame(FileList *fileList, FileTransferDoneFrame *transferDoneFrame);
int32_t DecodeSettingFrame(SettingFrame *netSettingFrame, SettingFrame *hostSettingFrame);
int32_t DecodeRstFrame(RstFrame *rstFrame, uint16_t *code, uint16_t **fileIdList, uint16_t *listCount);
int32_t DecodeBackPressFrame(const BackPressureFrame *backPressFrame, DataBackPressure *backPressInfo);

#ifdef __cplusplus
}
#endif

#endif  /* #ifndef NSTACKX_DFILE_FRAME_H */
