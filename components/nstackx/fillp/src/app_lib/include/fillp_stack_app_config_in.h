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

#ifndef FILLP_STACK_APP_CONFIG_IN_H
#define FILLP_STACK_APP_CONFIG_IN_H

#include "utils.h"
#include "spunge.h"
#include "socket_common.h"
#include "res.h"
#include "spunge_stack.h"
#include "spunge_message.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#define FILLP_RARE_3 3

FILLP_INT32 FtAppInitConfigGet(IO FillpAppGlobalConfigsSt *globalResource, IN FILLP_INT sockIndex);
FILLP_INT32 FtAppInitConfigSet(IN FILLP_CONST FillpAppGlobalConfigsSt *globalResource, IN FILLP_INT sockIndex);
FILLP_INT32 FtGetConfigApp(IN FILLP_UINT32 name, IO void *value, IN FILLP_CONST void *param);
FILLP_INT32 FtSetConfigApp(IN FILLP_UINT32 name, IN FILLP_CONST void *value, IN FILLP_CONST void *param);
FILLP_INT32 FtAppValidateConfigParams(IN FILLP_CONST FillpAppGlobalConfigsSt *globalResource);
FILLP_INT32 FtInnerAppConfigGet(IN FILLP_UINT32 name, IO void *value,
    IN FILLP_CONST struct GlobalAppResource *resource);
FILLP_INT32 FtInnerAppConfigSet(IN FILLP_UINT32 name, IN FILLP_CONST void *value,
    IN struct GlobalAppResource *resource, IN FILLP_INT sockIndex, IN struct FtSocket *sock);
FILLP_INT FtAppConfigInitNackDelayCfg(FILLP_INT sockIndex, struct GlobalAppResource *resource);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* FILLP_STACK_APP_CONFIG_IN_H */
