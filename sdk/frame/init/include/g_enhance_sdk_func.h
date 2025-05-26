/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef G_ENHANCE_SDK_FUNC_H
#define G_ENHANCE_SDK_FUNC_H

#ifdef __cplusplus
extern "C" {
#endif

#include "client_trans_file_struct.h"

#define FILLP_TYPES_ERR_OK_INVALID true
#ifdef FILLP_TYPES_ENHANCE_ENABLED
#include "include/fillptypes.h"
#else
#include "fillptypes.h"
#endif
#include "stdint.h"
#include "trans_type.h"

typedef void (*BusCenterExProxyDeInitFunc)(void);
typedef int32_t (*DiscRecoveryPolicyFunc)(void);
typedef int32_t (*CheckFileSchemaFunc)(int32_t sessionId, FileSchemaListener *fileSchemaListener);
typedef int32_t (*SetSchemaCallbackFunc)(FileSchema fileSchema, const char *sFileList[], uint32_t fileCnt);
typedef int32_t (*SetExtSocketOptFunc)(int32_t socket, OptLevel level, OptType optType, void *optValue, uint32_t optValueSize);
typedef int32_t (*GetExtSocketOptFunc)(int32_t socket, OptLevel level, OptType optType, void *optValue, int32_t *optValueSize);
typedef int32_t (*TransFileSchemaInitFunc)(void);
typedef void (*TransFileSchemaDeinitFunc)(void);
typedef int32_t (*VtpSetSocketMultiLayerFunc)(int fd, OnFrameEvt *cb, const void *para);
typedef bool (*IsVtpFrameSentEvtFunc)(const FtEventCbkInfo *info);
typedef int (*HandleVtpFrameEvtFunc)(int fd, OnFrameEvt cb, const FtEventCbkInfo *info);

typedef struct TagClientEnhanceFuncList {
    BusCenterExProxyDeInitFunc busCenterExProxyDeInit;
    DiscRecoveryPolicyFunc discRecoveryPolicy;
    CheckFileSchemaFunc checkFileSchema;
    SetSchemaCallbackFunc setSchemaCallback;
    SetExtSocketOptFunc setExtSocketOpt;
    GetExtSocketOptFunc getExtSocketOpt;
    TransFileSchemaInitFunc transFileSchemaInit;
    TransFileSchemaDeinitFunc transFileSchemaDeinit;
    VtpSetSocketMultiLayerFunc vtpSetSocketMultiLayer;
    IsVtpFrameSentEvtFunc isVtpFrameSentEvt;
    HandleVtpFrameEvtFunc handleVtpFrameEvt;
} ClientEnhanceFuncList;

ClientEnhanceFuncList *ClientEnhanceFuncListGet(void);
int32_t ClientRegisterEnhanceFunc(void *soHandle);

#ifdef __cplusplus
}
#endif

#endif