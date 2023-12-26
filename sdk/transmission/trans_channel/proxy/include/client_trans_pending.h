/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#ifndef CLIENT_TRANS_PENDING_H
#define CLIENT_TRANS_PENDING_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    char *data;
    uint32_t len;
} TransPendData;

int32_t InitPendingPacket(void);
void DestroyPendingPacket(void);
int32_t CreatePendingPacket(uint32_t id, uint64_t seq);
void DeletePendingPacket(uint32_t id, uint64_t seq);

int32_t GetPendingPacketData(uint32_t id, uint64_t seq, uint32_t waitMillis, bool isDelete, TransPendData *data);
int32_t SetPendingPacketData(uint32_t id, uint64_t seq, const TransPendData *data);
#ifdef __cplusplus
}
#endif
#endif // CLIENT_TRANS_PENDING_H
