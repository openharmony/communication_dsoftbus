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
#include "nstackx_log.h"

#define TAG "nStackXDFile"

int32_t WaitSocketEvent(const DFileSession *session, SocketDesc fd, uint32_t timeoutMs,
    uint8_t *canRead, uint8_t *canWrite)
{
    int32_t nfds = fd + 1;
    fd_set writeFds, readFds;
    struct timeval tv;

    if (fd >= FD_SETSIZE) {
        LOGE(TAG, "fd %d is too big", fd);
        return NSTACKX_EFAILED;
    }

    FD_ZERO(&readFds);
    FD_ZERO(&writeFds);
    if (canRead != NULL) {
        *canRead = NSTACKX_FALSE;
        FD_SET(fd, &readFds);
    }
    if (canWrite != NULL) {
        *canWrite = NSTACKX_FALSE;
        FD_SET(fd, &writeFds);
    }

    if (session != NULL) {
        /*
         * Monitoring receiverPipe, so that "select" will got unblock either by incoming packet, or by receiverPipe when
         * calling NSTACKX_DFileClose().
         */
        PipeDesc pipe = session->receiverPipe[PIPE_OUT];
        if (pipe >= FD_SETSIZE) {
            LOGE(TAG, "pipe fd %d is too big", pipe);
            return NSTACKX_EFAILED;
        }
        if (nfds < pipe + 1) {
            nfds = pipe + 1;
        }
        FD_SET(pipe, &readFds);
    }

    tv.tv_sec = timeoutMs / NSTACKX_MILLI_TICKS;
    tv.tv_usec = (timeoutMs % NSTACKX_MILLI_TICKS) * NSTACKX_MICRO_SEC_PER_MILLI_SEC;

    int32_t ret = select(nfds, &readFds, &writeFds, NULL, &tv);
    if (ret < 0) {
        if (errno == EINTR) {
            return NSTACKX_EOK;
        }
        return NSTACKX_EFAILED;
    }

    if (ret) {
        if (FD_ISSET(fd, &readFds) && (canRead != NULL)) {
            *canRead = NSTACKX_TRUE;
        }
        if (FD_ISSET(fd, &writeFds) && (canWrite != NULL)) {
            *canWrite = NSTACKX_TRUE;
        }
    }
    return NSTACKX_EOK;
}