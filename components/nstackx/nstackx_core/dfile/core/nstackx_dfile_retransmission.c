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
#include "nstackx_dfile_log.h"

#define TAG "nStackXDFile"

#define NSTACKX_BACK_PRESSURE_BYPASS_TIME 10
static void SendBackPressureFrame(DFileTrans *dFileTrans)
{
    PeerInfo *peerInfo = (PeerInfo *)(dFileTrans->context);
    uint8_t buf[NSTACKX_DEFAULT_FRAME_SIZE];
    size_t frameLen = 0;
    uint32_t recvListAllSize;
    uint32_t recvInnerAllSize;
    uint32_t allSize;
    uint32_t blockFrameSize = sizeof(BlockFrame) + dFileTrans->fileManager->maxFrameLength;

    if (!CapsRecvFeedback(dFileTrans->session)) {
        return;
    }

    if (dFileTrans->backPressureBypassCnt <= NSTACKX_BACK_PRESSURE_BYPASS_TIME) {
        dFileTrans->backPressureBypassCnt++;
        return;
    }

    if (GetFileBlockListSize(&dFileTrans->fileManager->taskList, &recvListAllSize, &recvInnerAllSize) != NSTACKX_EOK) {
        dFileTrans->fileManager->errCode = FILE_MANAGER_EMUTEX;
        NotifyFileManagerMsg(dFileTrans->fileManager, FILE_MANAGER_INNER_ERROR);
        DFILE_LOGE(TAG, "failed to get GetFileBlockListSize");
        return;
    }
    allSize = recvListAllSize + recvInnerAllSize;
    uint32_t recvListWindowSize = (dFileTrans->fileManager->iowMaxRate * DFILE_KILOBYTES / NSTACKX_MILLI_TICKS)
        * NSTACKX_ACK_INTERVAL * FILE_RECV_LIST_SLOW_START_RATE;
    if (((allSize >= (uint32_t)(dFileTrans->fileManager->iowCount * FILE_RECV_LIST_IO_WRITE_THRESHOLD)) ||
        (allSize >= (uint32_t)(dFileTrans->fileManager->maxRecvBlockListSize * FILE_RECV_LIST_IO_WRITE_THRESHOLD)) ||
        (allSize * blockFrameSize >= recvListWindowSize)) &&
        allSize > 0) {
        dFileTrans->fileManager->recvListOverIo = 1;
    } else {
        dFileTrans->fileManager->recvListOverIo = 0;
    }

    EncodeBackPressFrame(buf, NSTACKX_DEFAULT_FRAME_SIZE, &frameLen, dFileTrans->fileManager->recvListOverIo);
    int32_t ret = DFileWriteHandle(buf, frameLen, peerInfo);
    if (ret != (int32_t)frameLen && ret != NSTACKX_EAGAIN) {
        DFILE_LOGE(TAG, "send back pressure frame failed");
    }
    if (dFileTrans->fileManager->recvListOverIo == 1) {
        DFILE_LOGI(TAG, "socket %hhu send back pressure fileManager->recvListOverIo %hhu allSize %u iowCount %llu",
             peerInfo->socketIndex, dFileTrans->fileManager->recvListOverIo, allSize,
             dFileTrans->fileManager->iowCount);
    }
    if (dFileTrans->fileManager->recvListOverIo == 1) {
        ClockGetTime(CLOCK_MONOTONIC, &dFileTrans->ts);
    }
}

void SendFileDataAck(DFileTrans *dFileTrans, DFileReceiveState *nextState)
{
    ClockGetTime(CLOCK_MONOTONIC, &dFileTrans->heartBeatTs);
    *nextState = STATE_RECEIVE_FILE_DATA_ONGOING;

    SendBackPressureFrame(dFileTrans);
}
