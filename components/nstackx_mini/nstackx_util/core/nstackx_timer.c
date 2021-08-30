/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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

#include "nstackx_timer.h"
#include "nstackx_log.h"
#include "securec.h"

#define TAG "nStackXTimer"

uint32_t GetTimeDiffMs(const struct timespec *etv, const struct timespec *stv)
{
    uint64_t ms;

    if (etv->tv_sec < stv->tv_sec || (etv->tv_sec == stv->tv_sec && etv->tv_nsec < stv->tv_nsec)) {
        LOGE(TAG, "invalid input: etv is smaller than stv");
        return 0;
    }

    if (etv->tv_nsec < stv->tv_nsec) {
        ms = ((uint64_t)etv->tv_sec - (uint64_t)stv->tv_sec - 1) * NSTACKX_MILLI_TICKS;
        ms += (NSTACKX_NANO_TICKS + (uint64_t)etv->tv_nsec - (uint64_t)stv->tv_nsec) / NSTACKX_MICRO_TICKS;
    } else {
        ms = ((uint64_t)etv->tv_sec - (uint64_t)stv->tv_sec) * NSTACKX_MILLI_TICKS;
        ms += ((uint64_t)etv->tv_nsec - (uint64_t)stv->tv_nsec) / NSTACKX_MICRO_TICKS;
    }
    if (ms > UINT32_MAX) {
        ms = UINT32_MAX;
    }
    return (uint32_t)ms;
}

uint32_t GetTimeDiffUs(const struct timespec *etv, const struct timespec *stv)
{
    uint64_t us;
    if (etv->tv_sec < stv->tv_sec || (etv->tv_sec == stv->tv_sec && etv->tv_nsec < stv->tv_nsec)) {
        LOGE(TAG, "invalid input: etv is smaller than stv");
        return 0;
    }
    if (etv->tv_nsec < stv->tv_nsec) {
        us = ((uint64_t)etv->tv_sec - (uint64_t)stv->tv_sec - 1) * NSTACKX_MICRO_TICKS;
        us += (NSTACKX_NANO_TICKS + (uint64_t)etv->tv_nsec - (uint64_t)stv->tv_nsec) / NSTACKX_NANO_SEC_PER_MICRO_SEC;
    } else {
        us = ((uint64_t)etv->tv_sec - (uint64_t)stv->tv_sec) * NSTACKX_MILLI_TICKS;
        us += ((uint64_t)etv->tv_nsec - (uint64_t)stv->tv_nsec) / NSTACKX_NANO_SEC_PER_MICRO_SEC;
    }
    if (us > UINT32_MAX) {
        us = UINT32_MAX;
    }
    return (uint32_t)us;
}
