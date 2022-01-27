/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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

#ifndef SOCKET_COMMON_H
#define SOCKET_COMMON_H

#ifdef __cplusplus
extern "C" {
#endif

#define MAX_APP_DATA_LENGTH_FOR_CAL_COST (30 * 1024)

void EpollEventCallback(struct FtSocket *sock, FILLP_UINT32 upEvent);

static inline FILLP_INT FillpValidateFuncPtr(void *ptr, FILLP_UINT32 size)
{
    FILLP_UINT32 index;
    void **sysFunction = (void **)ptr;

    size /= sizeof(void *);
    for (index = 0; index < size; index++) {
        if (sysFunction[index] == FILLP_NULL_PTR) {
            return -1;
        }
    }

    return ERR_OK;
}

extern struct GlobalAppResource g_appResource;

void InitGlobalAppResourceDefault(void);
void SockFreeSocket(struct FtSocket *sock);
struct FtSocket *SockAllocSocket(void);
struct FtSocket *SockGetSocket(FILLP_INT sockIndex);
FILLP_BOOL SockCanSendData(FILLP_CONST struct FtSocket *sock);
FILLP_BOOL SockCanRecvData(struct FtSocket *sock);
struct FtSocket *SockApiGetAndCheck(int sockIdx);
FILLP_INT SockUpdatePktDataOpt(struct FtSocket *sock, FILLP_UINT16 addFlag, FILLP_UINT16 delFlag);

#ifdef __cplusplus
}
#endif

#endif /* SOCKET_COMMON_H */