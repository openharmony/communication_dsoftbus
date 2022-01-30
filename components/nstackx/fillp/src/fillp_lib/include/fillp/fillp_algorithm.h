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

#ifndef FILLP_ALGORITHM_H
#define FILLP_ALGORITHM_H

#include "fillptypes.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Calculate fillp pack interval */
typedef void (*fillpAlgCalPackInterval)(void *argPcb);
typedef void (*fillpAlgPackTimer)(void *argPcb);
typedef void (*fillpAlgAnalysePack)(void *argPcb, FILLP_CONST void *argPack);
typedef void (*fillpAlgAnalyseNack)(void *argPcb, FILLP_CONST void *argNack);
typedef void (*fillpAlgHdlPackFlag)(void *argPcb, FILLP_CONST void *argPack);
typedef FILLP_INT (*fillpAlgFcInit)(void *argPcb);
typedef void (*fillpAlgFcDeinit)(void *argPcb);
typedef FILLP_UINT16 (*fillpAlgGetRedunCount)(void *argPcb, void *item);
typedef void (*fillpAlgFcUpdateExpectSendBytes)(void *argPcb, FILLP_UINT32 *expectBytes);
typedef void (*fillpAlgFcTimer)(void *argPcb);
typedef FILLP_UINT32 (*fillpAlgFcGetSrtt)(void *argPcb);

struct FillpAlgFuncs {
    fillpAlgFcInit fcInit;
    fillpAlgFcDeinit fcDeinit;
    fillpAlgCalPackInterval calPackInterval;
    fillpAlgPackTimer packTimer;
    fillpAlgHdlPackFlag hdlPackFlag;
    fillpAlgAnalysePack analysisPack;
    fillpAlgAnalyseNack analysisNack;
    fillpAlgGetRedunCount getRedunCount;
    fillpAlgFcUpdateExpectSendBytes updateExpectSendBytes;
    fillpAlgFcTimer fcTime;
};

extern struct FillpAlgFuncs g_fillpAlg0;

FILLP_INT FillpAlg0FcInit(void *argPcb);

void FillpAlg0FcDeinit(void *argPcb);

void FillpAlg0CalPackInterval(void *argPcb);

void FillpAlg0AnalysePack(void *argPcb, FILLP_CONST void *argPack);

#ifdef __cplusplus
}
#endif

#endif /* FILLP_ALGORITHM_H */
