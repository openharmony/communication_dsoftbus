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

#ifndef SPINLOCK_H
#define SPINLOCK_H

typedef struct {
    volatile int lock;
} Spinlock;


#if defined(__x86_64__)
#include <emmintrin.h>

inline static void Pause(void)
{
    _mm_pause();
}
#elif defined(RTP_ARCH_ARM)
static inline void Pause(void)
{
    asm volatile("yield" ::: "memory");
}
#else
static inline void Pause(void)
{
}
#endif

static inline void SpinLockInit(Spinlock *spinlock)
{
    spinlock->lock = 0;
}

static inline int SpinLockTryLock(Spinlock *spinlock)
{
    if (__sync_bool_compare_and_swap(&spinlock->lock, 0, 1) == 0) {
        return 0;
    }

    return 1;
}

static inline void SpinLock(Spinlock *spinlock)
{
    while (!SpinLockTryLock(spinlock)) {
        do {
            Pause();
        } while (!!spinlock->lock);
    }
}

static inline void SpinUnlock(Spinlock *spinlock)
{
    __sync_lock_release(&spinlock->lock);
}

#endif /* SPINLOCK_H */

