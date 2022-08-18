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

#include "log.h"

#ifdef __cplusplus
extern "C" {
#endif

FILLP_INT32 FillpApiSetDebugLogLevel(IN FILLP_UINT8 logLevel)
{
    if (logLevel < FILLP_DBG_LVL_DEBUG || logLevel > FILLP_DBG_LVL_ERROR) {
        return ERR_PARAM;
    }

    g_fillpLmGlobal.debugLevel = (FILLP_UINT8)logLevel;
    return ERR_OK;
}

FILLP_UINT32 FillpApiConfigLogModules(IN FILLP_ULLONG logModules)
{
    g_fillpLmGlobal.logModules = logModules;
    return ERR_OK;
}

FILLP_INT FillpApiSetMgtMsgLog(IN FILLP_INT enable)
{
#ifdef FILLP_MGT_MSG_LOG
    g_fillpLmGlobal.mgtMsgLog = !!enable;
    return ERR_OK;
#else
    FILLP_LOGERR("do not support mgt msg log");
    FILLP_UNUSED_PARA(enable);
    return ERR_COMM;
#endif
}

#ifdef __cplusplus
}
#endif
