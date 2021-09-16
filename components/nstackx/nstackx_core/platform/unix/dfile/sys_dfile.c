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

int32_t CheckFdSetSize(SocketDesc sock)
{
    if (sock >= FD_SETSIZE) {
        return NSTACKX_EFAILED;
    }
    return NSTACKX_EOK;
}

int32_t CreateReceiverPipe(DFileSession *session)
{
    if (pipe(session->receiverPipe) < 0) {
        LOGE(TAG, "create pipe error: %d", errno);
        return NSTACKX_EFAILED;
    }

    /* Note: If the monitoring method is not select, this restriction should be removed */
    if (session->receiverPipe[PIPE_OUT] >= FD_SETSIZE) {
        LOGE(TAG, "pipe fd %d is too big for monitoring by select", session->receiverPipe[PIPE_OUT]);
        goto L_ERR_FAILED;
    }

    for (uint32_t i = 0; i < PIPE_FD_NUM; i++) {
        int32_t flags = fcntl(session->receiverPipe[i], F_GETFL, 0);
        if (flags < 0) {
            LOGE(TAG, "fcntl get flags failed: %d", errno);
            goto L_ERR_FAILED;
        }

        flags = (int32_t)((uint32_t)flags | O_NONBLOCK);
        int32_t ret = fcntl(session->receiverPipe[i], F_SETFL, flags);
        if (ret < 0) {
            LOGE(TAG, "fcntl set flags to non-blocking failed: %d", errno);
            goto L_ERR_FAILED;
        }
    }
    return NSTACKX_EOK;
L_ERR_FAILED:
    CloseDesc(session->receiverPipe[PIPE_OUT]);
    CloseDesc(session->receiverPipe[PIPE_IN]);
    return NSTACKX_EFAILED;
}

void NotifyPipeEvent(const DFileSession *session)
{
    char notify = 0;

    if (write(session->receiverPipe[PIPE_IN], &notify, sizeof(notify)) <= 0) {
        LOGE(TAG, "write to receiver pipe failed. errno %d", errno);
    }
}
