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

#ifndef FILLP_STACK_CONFIG_IN_H
#define FILLP_STACK_CONFIG_IN_H

#include "res.h"
#include "spunge.h"
#include "spunge_stack.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

FILLP_INT32 FtConfigSetRxBurst(IN FILLP_CONST void *value);
FILLP_INT32 FtConfigSetRecvCachePktNumBufferSize(IN FILLP_CONST void *value);
FILLP_INT32 FtConfigSetOutOfOrderCacheFeature(IN FILLP_CONST void *value);
FILLP_INT32 FtConfigSetCpuCoreUse(IN FILLP_CONST void *value);
FILLP_INT32 FtConfigSetMaxSockNum(IN FILLP_CONST void *value);
FILLP_INT32 FtConfigSetMaxConnectionNum(IN FILLP_CONST void *value);
FILLP_INT32 FtConfigSetFullCpu(IN FILLP_CONST void *value);
FILLP_INT32 FtConfigSetFullCpuUseThresholdRate(IN FILLP_CONST void *value);
FILLP_INT32 FtConfigSetOppositeSetPercentage(IN FILLP_CONST void *value);
FILLP_INT32 FtConfigSetNackRepeatTimes(IN FILLP_CONST void *value);
FILLP_INT32 FtConfigSetAlg(IN FILLP_CONST void *value);
FILLP_INT32 FtConfigSetPktLossAllow(IN FILLP_CONST void *value);
FILLP_INT32 FtConfigSetInitialRate(IN FILLP_CONST void *value);
FILLP_INT32 FtConfigSetMaxRatePercentage(IN FILLP_CONST void *value);
FILLP_INT32 FtConfigSetSupportFairness(IN FILLP_CONST void *value);
FILLP_INT32 FtConfigSetMaxRate(IN FILLP_CONST void *value);
FILLP_INT32 FtConfigSetLimitRate(IN FILLP_CONST void *value);
FILLP_INT32 FtConfigSetMaxRecvRate(IN FILLP_CONST void *value);
FILLP_INT32 FtConfigSetSendCache(IN FILLP_CONST void *value);
FILLP_INT32 FtConfigSetRecvCache(IN FILLP_CONST void *value);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* FILLP_STACK_CONFIG_IN_H */
