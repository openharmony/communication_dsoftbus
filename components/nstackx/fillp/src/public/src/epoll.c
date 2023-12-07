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

#include "utils.h"
#include "fillp_function.h"
#include "log.h"
#include "epoll.h"

#ifdef __cplusplus
extern "C" {
#endif


void EpDelRdlnode(struct EventPoll *ep, struct EpItem *epi)
{
    if (!HLISTNODE_LINKED(&epi->rdlNode)) {
        return;
    }

    HlistDelete(&ep->rdList, &epi->rdlNode);
}

/**
 *  Add epitem to eventpoll->rdllist
 *  scb is the core pointer
 */
void EpSocketReady(struct EventPoll *scb, struct EpItem *epiItem)
{
    if ((scb == FILLP_NULL_PTR) || (epiItem == FILLP_NULL_PTR)) {
        FILLP_LOGERR("NULL Pointer");
        return;
    }
    if (!HLISTNODE_LINKED(&epiItem->rdlNode)) {
        HlistAddTail(&scb->rdList, &epiItem->rdlNode);
    }

    if (!SYS_ARCH_ATOMIC_READ(&scb->semSignalled)) {
        (void)SYS_ARCH_ATOMIC_SET(&scb->semSignalled, 1);
        (void)SYS_ARCH_SEM_POST(&scb->waitSem);
    }

    return;
}

#ifdef __cplusplus
}
#endif
