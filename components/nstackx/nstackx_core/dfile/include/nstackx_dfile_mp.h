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

#ifndef NSTACKX_DFILE_MP_H
#define NSTACKX_DFILE_MP_H
#include "nstackx_dfile_session.h"
#include "nstackx_dfile_transfer.h"
#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    DFileSession *session;
    uint8_t socketIndex;
} SenderThreadPara;

typedef struct {
    List     list;
    DFileTrans *trans;
    int16_t status;
    uint16_t deleted;
    uint16_t vtransId;
} DFileVtrans;

typedef struct {
    uint8_t fileCreated;
    char newfileName[NSTACKX_MAX_REMOTE_PATH_LEN];
} RealFileInfo;

typedef struct {
    List     list;
    uint16_t vtransRealTransId;
    uint16_t vtransTotalNum;
    uint16_t vtransFinishedNum;
    RealFileInfo *realFileInfo;
    List     vtransListHead;
} DFileVtransManager;

typedef struct {
    const char *files[NSTACKX_MAX_FILE_LIST_NUM];
    const char *remotePath[NSTACKX_MAX_FILE_LIST_NUM];
    uint64_t fileSize[NSTACKX_MAX_FILE_LIST_NUM];
    uint64_t startOffset[NSTACKX_MAX_FILE_LIST_NUM];
    uint16_t realFileId[NSTACKX_MAX_FILE_LIST_NUM];
    uint16_t realTransId;
    uint16_t totalFileNum;
    uint16_t transNum;
    uint64_t totalFileSize;
} DFileRebuildFileList;

typedef struct {
    const char *file;
    const char *remotePath;
    uint64_t totalFileSize;
    uint64_t vFileSize;
    uint64_t offset;
    uint64_t vtranSize;
    uint16_t realFileId;
} VFilePara;

int32_t DFileSocketRecvSP(DFileSession *session);
PeerInfo *TransSelectPeerInfo(DFileSession *session);
PeerInfo *ClientGetPeerInfoByTransId(DFileSession *session);
PeerInfo *ClientGetPeerInfoBySocketIndex(uint8_t socketIndex, const DFileSession *session);
int32_t CreateSenderThread(DFileSession *session);
int32_t RebuildFilelist(const char *files[], const char *remotePath[], uint32_t fileNum,
    DFileSession *session, DFileRebuildFileList *rebuildList);
int32_t InitOutboundQueueWait(DFileSession *session);
void DestroyOutboundQueueWait(DFileSession *session);
void PostOutboundQueueWait(DFileSession *session);

#ifdef __cplusplus
}
#endif
#endif // NSTACKX_DFILE_MP_H
