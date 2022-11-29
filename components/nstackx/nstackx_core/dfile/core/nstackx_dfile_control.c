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

#include "nstackx_dfile_control.h"

#include "securec.h"

#include "nstackx_dfile_config.h"
#include "nstackx_dfile_mp.h"
#include "nstackx_error.h"
#include "nstackx_dfile_log.h"

#define TAG "nStackXDFile"

static void SendSessionFileTransferDoneAckFrame(PeerInfo *peerInfo, uint16_t transId)
{
    uint8_t buf[NSTACKX_DEFAULT_FRAME_SIZE];
    size_t frameLen = 0;
    DFileMsg data;
    (void)memset_s(buf, sizeof(buf), 0, sizeof(buf));
    (void)memset_s(&data, sizeof(data), 0, sizeof(data));
    EncodeFileTransferDoneAckFrame(buf, NSTACKX_DEFAULT_FRAME_SIZE, transId, &frameLen);
    int32_t ret = DFileWriteHandle(buf, frameLen, peerInfo);
    if (ret != (int32_t)frameLen && ret != NSTACKX_EAGAIN) {
        data.errorCode = NSTACKX_EFAILED;
        NotifyMsgRecver(peerInfo->session, DFILE_ON_CONNECT_FAIL, &data);
    }
}

void DFileSendTransferDoneAck(DFileSession *session)
{
    if (session->transferDoneAckList.size == 0) {
        return;
    }

    PeerInfo *peerInfo = NULL;
    List *pos = NULL;
    List *tmp = NULL;
    TransferDoneAckNode *transferDoneAckNode = NULL;
    if (PthreadMutexLock(&session->transferDoneAckList.lock) != 0) {
        DFILE_LOGE(TAG, "pthread mutex lock error");
        return;
    }
    LIST_FOR_EACH_SAFE(pos, tmp, &session->transferDoneAckList.head) {
        transferDoneAckNode = (TransferDoneAckNode *)pos;
        if (transferDoneAckNode == NULL) {
            continue;
        }
        DFILE_LOGI(TAG, "transferDoneAckList transId %u send num %u",
            transferDoneAckNode->transId, transferDoneAckNode->sendNum);
        if (transferDoneAckNode->sendNum > 0) {
            peerInfo = ClientGetPeerInfoByTransId(session);
            if (!peerInfo) {
                if (PthreadMutexUnlock(&session->transferDoneAckList.lock) != 0) {
                    DFILE_LOGE(TAG, "pthread mutex unlock error");
                }
                return;
            }
            SendSessionFileTransferDoneAckFrame(peerInfo, transferDoneAckNode->transId);
            transferDoneAckNode->sendNum--;
        } else {
            ListRemoveNode(&transferDoneAckNode->list);
            free(transferDoneAckNode);
            session->transferDoneAckList.size--;
        }
    }
    if (PthreadMutexUnlock(&session->transferDoneAckList.lock) != 0) {
        DFILE_LOGE(TAG, "pthread mutex unlock error");
    }
}

void DFileSenderControlHandle(DFileSession *session)
{
    while (!session->closeFlag) {
        DFileSendTransferDoneAck(session);
        if (usleep(NSTACKX_CONTROL_INTERVAL) != 0) {
            DFILE_LOGE(TAG, "usleep(NSTACKX_CONTROL_INTERVAL) failed %d", errno);
        }
    }
}

void DFileReceiverControlHandle(DFileSession *session)
{
    while (!session->closeFlag) {
        if (usleep(NSTACKX_CONTROL_INTERVAL) != 0) {
            DFILE_LOGE(TAG, "usleep(NSTACKX_CONTROL_INTERVAL) failed %d", errno);
        }
    }
}
