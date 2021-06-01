/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#ifndef CLIENT_TRANS_TCP_DIRECT_MESSAGE_H
#define CLIENT_TRANS_TCP_DIRECT_MESSAGE_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define DC_DATA_HEAD_SIZE 16
#ifndef MAGIC_NUMBER
#define MAGIC_NUMBER 0xBABEFACE
#endif

enum {
    FLAG_BYTES = 0,
    FLAG_ACK = 1,
    FLAG_MESSAGE = 2,
    FILE_FIRST_FRAME = 3,
    FILE_ONGOINE_FRAME = 4,
    FILE_LAST_FRAME = 5,
    FILE_ONLYONE_FRAME = 6,
    FILE_ALLFILE_SENT = 7,
    FLAG_ASYNC_MESSAGE = 8,
    FLAG_SET_LOW_LATENCY = 9
};

typedef struct {
    uint32_t magicNumber;
    int32_t seq;
    uint32_t flags;
    uint32_t dataLen;
} __attribute__((packed)) TcpDataPacketHead;

int32_t TransTdcPreProcessRecvData(int32_t fd, char *data, uint32_t size);
int32_t TransTdcProcessRecvData(int32_t channelId, const char *data);

#ifdef __cplusplus
}
#endif
#endif // CLIENT_TRANS_TCP_DIRECT_MESSAGE_H