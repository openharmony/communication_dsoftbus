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

#include "nstackx_dfile_retransmission.h"

#include "nstackx_dfile_session.h"
#include "nstackx_log.h"

#define TAG "nStackXDFile"

static void SendBackPressureFrame(DFileTrans *dFileTrans)
{
    PeerInfo *peerInfo = (PeerInfo *)(dFileTrans->context);
    uint8_t buf[NSTACKX_DEFAULT_FRAME_SIZE];
    size_t frameLen = 0;

    if (!CapsRecvFeedback(dFileTrans->session)) {
        return;
    }

    EncodeBackPressFrame(buf, NSTACKX_DEFAULT_FRAME_SIZE, &frameLen, dFileTrans->fileManager->recvListOverIo);
    int32_t ret = DFileWriteHandle(buf, frameLen, peerInfo);
    if (ret != (int32_t)frameLen && ret != NSTACKX_EAGAIN) {
        LOGE(TAG, "send back pressure frame failed");
    }
#ifndef NSTACKX_WITH_LITEOS
    LOGI(TAG, "socket %d send back pressure fileManager->recvListOverIo %hhu", peerInfo->socketIndex,
         dFileTrans->fileManager->recvListOverIo);
#endif
    if (dFileTrans->fileManager->recvListOverIo == 1) {
        ClockGetTime(CLOCK_MONOTONIC, &dFileTrans->ts);
    }

    dFileTrans->fileManager->recvListOverIo = 0;
}

void SendFileDataAck(DFileTrans *dFileTrans, DFileReceiveState *nextState, int32_t flag)
{
    ClockGetTime(CLOCK_MONOTONIC, &dFileTrans->heartBeatTs);
    *nextState = STATE_RECEIVE_FILE_DATA_ONGOING;

    SendBackPressureFrame(dFileTrans);
}
