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

#ifndef NSTACKX_DFILE_ADAPTER_H
#define NSTACKX_DFILE_ADAPTER_H

#include <stdint.h>
#include "session.h"

#include "nstackx_dfile.h"

#ifdef __cplusplus
extern "C" {
#endif

int32_t StartNStackXDFileServer(const char *myIp, const uint8_t *key,
    uint32_t keyLen, DFileMsgReceiver msgReceiver, int32_t *filePort);

int32_t StartNStackXDFileClient(const char *peerIp, int32_t peerPort, const uint8_t *key,
    uint32_t keyLen, DFileMsgReceiver msgReceiver);
#ifdef __cplusplus
}
#endif
#endif // NSTACKX_DFILE_ADAPTER_H