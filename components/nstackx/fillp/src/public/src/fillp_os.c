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

#ifdef FILLP_LINUX
#include <fcntl.h>
#endif /* FILLP_LINUX */

#include "utils.h"
#include "log.h"
#include "fillp_function.h"
#include "fillp_os.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
Description: Global LM structure
Value Range: None
Access: Used to store values for global lm structure.
Remarks:
*/
FillpLmGlobal g_fillpLmGlobal = {
    FILLP_DEBUG_ID_ALL,  /* logModules */
    FILLP_DBG_LVL_ERROR, /* debugLevel */
    FILLP_FALSE,         /* funcTrace */
    FILLP_FALSE,         /* reserve */
#ifdef FILLP_64BIT_ALIGN
    FILLP_FALSE, /* padd */
#endif
    { FILLP_NULL_PTR }, /* lmCallbackFn */
};
/*
Description: System OS Basic Function
Value Range: None
Access: Used to store system basic OS functions.
Remarks:
*/
FillpSysLibBasicCallbackFuncSt g_fillpOsBasicLibFun;

/*
Description: System OS semophore functions
Value Range: None
Access: Used to store system semophore library functions.
Remarks:
*/
FillpSysLibSemCallbackFuncSt g_fillpOsSemLibFun;

/*
Description: System OS socket functions
Value Range: None
Access: Used to store system socket functions.
Remarks:
*/
FillpSysLibSockCallbackFuncSt g_fillpOsSocketLibFun;

/*
Description: System or APP other functions
Value Range: None
Access: Used to store APP other functions.
Remarks:
*/
FillpAppCallbackFunc g_fillpAppCbkFun;

#ifdef FILLP_LINUX

FILLP_INT SysArchSetSockBlocking(FILLP_INT sock, FILLP_BOOL blocking)
{
    FILLP_INT flags;

    if (sock < 0) {
        return ERR_PARAM;
    }

    flags = FILLP_FCNTL(sock, F_GETFL, 0);
    if (flags < 0) {
        return ERR_COMM;
    }
    flags = (FILLP_INT)(blocking ? ((FILLP_UINT)flags & ~(FILLP_UINT)O_NONBLOCK) :
        ((FILLP_UINT)flags | (FILLP_UINT)O_NONBLOCK));
    if (FILLP_FCNTL(sock, F_SETFL, flags) < 0) {
        return ERR_COMM;
    }

    return ERR_OK;
}

#elif defined(FILLP_WIN32)

FILLP_INT SysArchSetSockBlocking(FILLP_INT sock, FILLP_BOOL blocking)
{
    FILLP_ULONG mode = blocking ? 0 : 1;
    if (sock < 0) {
        return FILLP_ERR_VAL;
    }

    return FILLP_IOCTLSOCKET(sock, (FILLP_INT)FIONBIO, &mode);
}

#else

#error "define SysArchSetSockBlocking!!!"

#endif

/* Common for linux and windows */
FILLP_INT SysSetThreadName(FILLP_CHAR *name, FILLP_UINT16 nameLen)
{
    if (name == FILLP_NULL_PTR || nameLen == 0) {
        FILLP_LOGERR("SysSetThreadName para invalid");
        return ERR_OK;
    }
#if defined(FILLP_LINUX) && !defined(FILLP_MAC)
    (void)prctl(PR_SET_NAME, name);
    return ERR_OK;
#else
    return ERR_OK;
#endif /* FILLP_LINUX */
}

FILLP_INT SysArchSetSockSndbuf(FILLP_INT sock, FILLP_UINT size)
{
    if (sock < 0) {
        return ERR_PARAM;
    }

    return FILLP_SETSOCKOPT(sock, SOL_SOCKET, SO_SNDBUF, (FILLP_CONST char *)&size, sizeof(FILLP_INT));
}

FILLP_INT SysArchSetSockRcvbuf(FILLP_INT sock, FILLP_UINT size)
{
    if (sock < 0) {
        return ERR_PARAM;
    }

    return FILLP_SETSOCKOPT(sock, SOL_SOCKET, SO_RCVBUF, (FILLP_CONST char *)&size, sizeof(FILLP_INT));
}

#ifdef __cplusplus
}
#endif
