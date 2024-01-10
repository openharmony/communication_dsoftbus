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

#include "nstackx_dfile_mp.h"
#include "nstackx_dfile_log.h"
#include "nstackx_dfile_send.h"
#include "nstackx_dfile_transfer.h"
#include "nstackx_file_manager.h"
#include "securec.h"

#define TAG "nStackXDfileMp"

int32_t DFileSocketRecvSP(DFileSession *session)
{
    struct sockaddr_in peerAddr;
    socklen_t addrLen = sizeof(struct sockaddr_in);
    uint8_t frame[NSTACKX_MAX_FRAME_SIZE] = {0};
    int32_t ret;

    (void)memset_s(&peerAddr, addrLen, 0, addrLen);
    if (CapsTcp(session)) {
        if (session->sessionType == DFILE_SESSION_TYPE_SERVER) {
            if (session->acceptFlag == 0) {
                ret = DFileAcceptSocket(session);
                return ret;
            } else {
                ret = SocketRecvForTcp(session, session->recvBuffer, &peerAddr, &addrLen);
            }
        } else {
            ret = SocketRecvForTcp(session, session->recvBuffer, &peerAddr, &addrLen);
        }
        if (ret == NSTACKX_PEER_CLOSE) {
            return ret;
        }
    } else {
        ret = SocketRecv(session->socket[0], frame, sizeof(frame), &peerAddr, &addrLen);
    }
    if (ret <= 0) {
        if (ret != NSTACKX_EAGAIN) {
            DFILE_LOGE(TAG, "socket recv failed");
            return NSTACKX_EFAILED;
        }
        return NSTACKX_EAGAIN;
    }
    NSTACKX_ATOM_FETCH_INC(&session->totalRecvBlocks);
    if (CapsTcp(session)) {
        ret = DFileSessionHandleReadBuffer(session, session->recvBuffer, (size_t)session->recvLen, &peerAddr, 0);
        session->recvLen = 0;
    } else {
        ret = DFileSessionHandleReadBuffer(session, frame, (size_t)ret, &peerAddr, 0);
    }
    if (ret != NSTACKX_EOK) {
        DFILE_LOGE(TAG, "handle read buffer failed");
    }
    return ret;
}

PeerInfo *TransSelectPeerInfo(DFileSession *session)
{
    PeerInfo *peerInfo = (PeerInfo *)ListGetFront(&session->peerInfoChain);
    return peerInfo;
}

/* only for client */
PeerInfo *ClientGetPeerInfoByTransId(DFileSession *session)
{
    PeerInfo *peerInfo = (PeerInfo *)ListGetFront(&session->peerInfoChain);
    return peerInfo;
}

/* only for client */
PeerInfo *ClientGetPeerInfoBySocketIndex(uint8_t socketIndex, const DFileSession *session)
{
    PeerInfo *peerInfo = NULL;
    List     *pos = NULL;

    LIST_FOR_EACH(pos, &session->peerInfoChain) {
        peerInfo = (PeerInfo *)pos;
        if (peerInfo->socketIndex == socketIndex) {
            return peerInfo;
        }
    }
    return NULL;
}

int32_t CreateSenderThread(DFileSession *session)
{
    SenderThreadPara *para = NULL;

    para = malloc(sizeof(SenderThreadPara));
    if (para == NULL) {
        DFILE_LOGE(TAG, "Failed to allocate memory for SenderThreadPara");
        return NSTACKX_ENOMEM;
    }
    para->session = session;
    para->socketIndex = 0;
    if (PthreadCreate(&(session->senderTid[0]), NULL, DFileSenderHandle, para)) {
        DFILE_LOGE(TAG, "Create sender thread 0 failed");
        free(para);
        return NSTACKX_EFAILED;
    }

    return NSTACKX_EOK;
}

int32_t RebuildFilelist(const char *files[], const char *remotePath[], uint32_t fileNum,
    DFileSession *session, DFileRebuildFileList *rebuildList)
{
    if (session->allTaskCount >= NSTACKX_MAX_FILE_LIST_NUM) {
        DFILE_LOGI(TAG, "more than %d send task", NSTACKX_MAX_FILE_LIST_NUM);
        return NSTACKX_EFAILED;
    }

    (void)memset_s(rebuildList, sizeof(DFileRebuildFileList), 0, sizeof(DFileRebuildFileList));

    rebuildList->transNum = 1;
    for (uint32_t i = 0; i < fileNum; i++) {
        rebuildList->files[i] = files[i];
        if (remotePath) {
            rebuildList->remotePath[i] = remotePath[i];
        }
    }
    return NSTACKX_EOK;
}

int32_t InitOutboundQueueWait(DFileSession *session)
{
    if (SemInit(&session->outboundQueueWait[0], 0, 0) != 0) {
        return NSTACKX_EFAILED;
    }

    return NSTACKX_EOK;
}

void DestroyOutboundQueueWait(DFileSession *session)
{
    SemDestroy(&session->outboundQueueWait[0]);
}

void PostOutboundQueueWait(DFileSession *session)
{
    SemPost(&session->outboundQueueWait[0]);
}
