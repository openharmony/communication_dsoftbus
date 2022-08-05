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

#ifndef FILLP_LOG_H
#define FILLP_LOG_H

#include "fillp_os.h"
#include "opt.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifdef FILLP_LINUX

#ifdef PDT_UT

/* for UT statement coverage */
#define FILLP_LOG_IN(_level, _type, _pre, fmt, ...)

#else

#if FILLP_LOG_WITH_TIME

static inline void FillpLogGetNowTime(struct timeval *tv, struct tm *nowTime)
{
    (void)gettimeofday(tv, FILLP_NULL_PTR);
    time_t sec = (time_t)tv->tv_sec;
    (void)localtime_r(&sec, nowTime);
}

#define FILLP_LM_LOG_OUTPUT(_type, _level, _pre, fmt, ...) do { \
        struct timeval tv; \
        struct tm nowTime; \
        FillpLogGetNowTime(&tv, &nowTime); \
        (*g_fillpLmGlobal.lmCallbackFn.debugCallbackFunc)(_type, _level, 0, \
            "%02d%02d %02d:%02d:%02d.%06ld %s:[%d] : <%s>" fmt "\r\n", \
            nowTime.tm_mon + 1, nowTime.tm_mday, nowTime.tm_hour, nowTime.tm_min, nowTime.tm_sec, \
            (long)tv.tv_usec, __func__, __LINE__, _pre, ##__VA_ARGS__); \
    } while (0)

#else

#define FILLP_LM_LOG_OUTPUT(_type, _level, _pre, fmt, ...) ((*g_fillpLmGlobal.lmCallbackFn.debugCallbackFunc)( \
    _type, _level, 0, "%s:[%d] : <%s>" fmt "\r\n", __func__, __LINE__, _pre, ##__VA_ARGS__))

#endif /* FILLP_LOG_WITH_TIME */

#define FILLP_LOG_IN(_level, _type, _pre, fmt, ...) \
    do { \
        if ((_level) >= g_fillpLmGlobal.debugLevel && \
            (g_fillpLmGlobal.lmCallbackFn.debugCallbackFunc != FILLP_NULL_PTR)) { \
            FILLP_LM_LOG_OUTPUT(_type, _level, _pre, fmt, ##__VA_ARGS__); \
        } \
    } while (0)

#endif

#else

#define FILLP_LOG_IN(_level, _type, _pre, fmt, ...)

#endif /* FILLP_LINUX */

#define FILLP_LOGERR(fmt, ...) FILLP_LOG_IN(FILLP_DBG_LVL_ERROR, FILLP_DBG_LOG, "F-LOGERR", fmt, ##__VA_ARGS__)

#define FILLP_LOGWAR(fmt, ...) FILLP_LOG_IN(FILLP_DBG_LVL_WARNING, FILLP_DBG_LOG, "F-LOGWAR", fmt, ##__VA_ARGS__)

#define FILLP_LOGINF(fmt, ...) FILLP_LOG_IN(FILLP_DBG_LVL_INFO, FILLP_DBG_LOG, "F-LOGINF", fmt, ##__VA_ARGS__)

#define FILLP_LOGDTL(fmt, ...) FILLP_LOG_IN(FILLP_DBG_LVL_DETAIL, FILLP_DBG_LOG, "F-LOGDTL", fmt, ##__VA_ARGS__)

#define FILLP_LOGDBG(fmt, ...) FILLP_LOG_IN(FILLP_DBG_LVL_DEBUG, FILLP_DBG_LOG, "F-LOGDBG", fmt, ##__VA_ARGS__)

#define FILLP_LOGBUTT(fmt, ...) FILLP_LOG_IN(FILLP_DBG_LVL_BUTT, FILLP_DBG_LOG, "F-LOGBUTT", fmt, ##__VA_ARGS__)

#define FILLP_HELPBUTT(fmt, ...) FILLP_LOG_IN(FILLP_DBG_LVL_BUTT, FILLP_DBG_HELP, "F-HELPBUTT", fmt, ##__VA_ARGS__)

#define FILLP_SHOWDATABUTT(fmt, ...) \
        FILLP_LOG_IN(FILLP_DBG_LVL_BUTT, FILLP_DBG_SHOW_DATA, "F-SHOWDATABUTT", fmt, ##__VA_ARGS__)

#define FILLP_SHOWLEVELBUTT(fmt, ...) \
        FILLP_LOG_IN(FILLP_DBG_LVL_BUTT, FILLP_DBG_SHOW_LEVEL, "F-SHOWLEVELBUTT", fmt, ##__VA_ARGS__)

#ifdef FILLP_MGT_MSG_LOG
#define FILLP_LOGMGTMSG(fmt, ...) FILLP_LOG_IN(FILLP_DBG_LVL_INFO, FILLP_DBG_LOG, "F-LOGMGTMSG", fmt, ##__VA_ARGS__)
#endif

FILLP_INT FillpApiSetMgtMsgLog(FILLP_INT enable);

#ifdef __cplusplus
}
#endif
#endif /* FILLP_LOG_H */

