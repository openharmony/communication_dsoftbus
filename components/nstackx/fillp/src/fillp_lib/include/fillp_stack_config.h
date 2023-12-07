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

#ifndef FILLP_STACK_CONFIG_H
#define FILLP_STACK_CONFIG_H

#include "fillpinc.h"

#ifdef __cplusplus
extern "C" {
#endif

/*******************************************************************
  Function      : FtValidateConfigParams
  Description   : function to validate the Config parameter of FillpGlobalConfigsSt structure.
  Calls         :
  Called By     :
  Input         : globalResource : structure of type FillpGlobalConfigsSt
  Output        :
  Return        : ERR_OK on SUCCESS/ Error code on FAILURE
  Others        :
********************************************************************/
FILLP_INT32 FtValidateConfigParams(IN FILLP_CONST FillpGlobalConfigsSt *globalResource);

#ifdef __cplusplus
}
#endif

#endif /* FILLP_STACK_CONFIG_H */

