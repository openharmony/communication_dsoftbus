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
    struct EpollDescStr fds;

    if (CreateEpollFdPair(&fds) != NSTACKX_EOK) {
        return NSTACKX_EFAILED;
    }
    session->receiverPipe[PIPE_OUT] = fds.recvFd;
    session->receiverPipe[PIPE_IN] = fds.sendFd;

    return NSTACKX_EOK;
}

void NotifyPipeEvent(const DFileSession *session)
{
    char notify = 0;

    if (write(session->receiverPipe[PIPE_IN], &notify, sizeof(notify)) <= 0) {
        LOGE(TAG, "write to receiver pipe failed. errno %d", errno);
    }
}
