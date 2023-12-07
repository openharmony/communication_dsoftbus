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

#ifndef FILLP_EPOLL_H
#define FILLP_EPOLL_H
#include "rb_tree.h"
#include "hlist.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * This structure is stored inside the "private_data" member of the file
 * structure and represent the main data structure for the eventpoll
 * interface.
 */
struct EventPoll {
    struct Hlist rdList; /* epitem(ready fd) list */
    /* RB-Tree root used to store checked fd structs */
    struct RbRoot rbr; /* epitem storage. epitem will be storaged here if added by epoll_ctl */

    SYS_ARCH_SEM appSem;     /* protect data from multiple app thread */
    SYS_ARCH_SEM waitSem;    /* Notify the ep_wait */
    SYS_ARCH_SEM appCoreSem; /* protect data from app thread and core thread */

    /** don't signal the same semaphore twice: set to 1 when signalled */
    SysArchAtomic semSignalled;

#ifdef FILLP_64BIT_ALIGN
    FILLP_UINT8 padd[4];
#endif
};

/*
 * Each file descriptor added to the eventpoll interface will
 * have an entry of this type linked to the hash.
 */
struct EpItem {
    /* RB-Tree node used to link this structure to the eventpoll rb-tree */
    struct RbNode rbn; /* Will be added to eventpoll->rbr */

    /* List header used to link this structure to the eventpoll ready list */
    struct HlistNode rdlNode; /* Will be added to eventpoll->rdllist */

    struct HlistNode sockWaitNode; /* Will be added to ftSock->epoll_taskList */

    /* The "container" of this item -- this is core pointer always */
    struct EventPoll *ep;

    /* The structure that describe the interested events and the source fd */
    struct SpungeEpollEvent event;
    FILLP_UINT32 revents;

    FILLP_INT fileDespcriptor; /* The file descriptor information this item refers to */

    void *next;
};

static __inline struct EpItem *EpItemEntryRbNode(struct RbNode *node)
{
    return (struct EpItem *)((char *)(node) - (uintptr_t)(&(((struct EpItem *)0)->rbn)));
}

static __inline struct EpItem *EpItemEntryRdlNode(struct HlistNode *node)
{
    return (struct EpItem *)((char *)(node) - (uintptr_t)(&(((struct EpItem *)0)->rdlNode)));
}

static __inline struct EpItem *EpitemEntrySockWaitNode(struct HlistNode *node)
{
    return (struct EpItem *)((char *)(node) - (uintptr_t)(&(((struct EpItem *)0)->sockWaitNode)));
}

void EpSocketReady(struct EventPoll *scb, struct EpItem *epiItem);
void EpDelRdlnode(struct EventPoll *ep, struct EpItem *epi);
void EpollUpdateEpEvent(struct EpItem *epi);


#ifdef __cplusplus
}
#endif

#endif /* FILLP_EPOLL_H */
