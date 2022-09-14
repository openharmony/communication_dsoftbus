/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#ifndef FILLP_DFX_H
#define FILLP_DFX_H

#include "fillptypes.h"
#include "sockets.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    FILLP_DFX_LINK_RETRANSMIT_OUT,
    FILLP_DFX_LINK_KEEPALIVE_TIMEOUT,
    FILLP_DFX_LINK_IP_REMOVED,
    FILLP_DFX_LINK_CLOSE,
    FILLP_DFX_LINK_FIN_INPUT,
    FILLP_DFX_LINK_EVT_MAX,
} FillpDfxLinkEvtType;

typedef enum {
    FILLP_DFX_PKT_PARSE_FAIL,
    FILLP_DFX_PKT_SEMI_RELIABLE_DROP,
    FILLP_DFX_PKT_EVT_MAX,
} FillpDfxPktEvtType;

void FillpDfxDoEvtCbSet(void *softObj, FillpDfxEventCb evtCb);
FILLP_INT FillpDfxEvtCbSet(void *softObj, FillpDfxEventCb evtCb);
void FillpDfxSockLinkAndQosNotify(const struct FtSocket *sock, FillpDfxLinkEvtType evtType);
void FillpDfxPktNotify(FILLP_INT sockIdx, FillpDfxPktEvtType evtType, FILLP_UINT32 dropCnt);

#ifdef FILLP_ENABLE_DFX_HIDUMPER
FILLP_INT FillpDfxDump(FILLP_UINT32 argc, const FILLP_CHAR **argv, void *softObj, FillpDfxDumpFunc dump);
#endif /* FILLP_ENABLE_DFX_HIDUMPER */

#ifdef __cplusplus
}
#endif

#endif /* FILLP_DFX_H */