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

#ifndef FILLP_OUTPUT_H
#define FILLP_OUTPUT_H
#include "fillptypes.h"
#include "fillp_pcb.h"
#include "fillp.h"

#ifdef __cplusplus
extern "C" {
#endif

#define FILLP_UNLIMIT_BYTES (1 * 1024 * 1024)

FILLP_INT FillpSendItem(struct FillpPcbItem *item, struct FillpPcb *fpcb);
FILLP_UINT32 FillpSendOne(struct FillpPcb *pcb, FILLP_UINT32 totalSendBytes, FILLP_UINT32 sendPktNum);
void FillpSendAdhocpackToDetectRtt(struct FillpPcb *pcb);
FILLP_BOOL FillpSendPackWithPcbBuffer(struct FillpPcb *pcb);

#ifdef __cplusplus
}
#endif

#endif // FILLP_OUTPUT_H