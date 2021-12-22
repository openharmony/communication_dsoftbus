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
#ifndef NSTACKX_DFILE_RETRANSMISSION_H
#define NSTACKX_DFILE_RETRANSMISSION_H

#include "nstackx_dfile_transfer.h"

#define SEND_RETRY_DIVISOR 1
#define ALL_RETRY_DIVISOR 2

#define NSTACKX_RETRY_MAX_COUNT_BIT 0

#define FRAME_INSERT_TAIL   0
#define FRAME_INSERT_HEAD   1
#define FRAME_NOT_INSERT    2

#define RETRANS_FILE_MIN_RETRY_COUNT 1000
#define TRANSFER_ALL_RETRY_COUNT_ELAPSE_TIME 3000
#define TRANSFER_ALL_RETRY_COUNT_MIN_NUM 5000
#define TRANSFER_ALL_RETRY_COUNT_MAX_NUM 10000

void SendFileDataAck(DFileTrans *dFileTrans, DFileReceiveState *nextState);

#endif /* NSTACKX_DFILE_RETRANSMISSION_H */
