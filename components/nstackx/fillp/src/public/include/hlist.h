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

#ifndef FILLP_HLIST_H
#define FILLP_HLIST_H
#include "fillp_os.h"
#ifdef __cplusplus
extern "C" {
#endif

struct HlistNode {
    struct HlistNode *next;
    struct HlistNode **pprev;
    void *list;
};

struct Hlist {
    struct HlistNode head;
    FILLP_UINT32 size;
#ifdef FILLP_64BIT_ALIGN
    FILLP_UINT8 padd[4];
#endif
};


#define HLIST_INIT(ptr) do {                 \
    (ptr)->head.next = FILLP_NULL_PTR;       \
    (ptr)->head.pprev = &((ptr)->head.next); \
    (ptr)->size = 0;                         \
} while (0)
#define HLIST_INIT_NODE(node) do {      \
    (node)->list = FILLP_NULL_PTR;      \
    (node)->next = FILLP_NULL_PTR;      \
    (node)->pprev = FILLP_NULL_PTR;     \
} while (0)
#define HLIST_PREV(ptr) ((struct HlistNode *)(ptr)->pprev)
#define HLIST_EMPTY(list) (!((list)->size))
#define HLISTNODE_LINKED(_node) ((_node)->pprev != FILLP_NULL_PTR)
#define HLIST_FIRST(_list) ((_list)->head.next)
#define HLIST_TAIL(_list) (HLIST_EMPTY(_list) ? FILLP_NULL_PTR : HLIST_PREV(&(_list)->head))

#define HLIST_FOREACH_SAFE(_pos, _next, list) \
    for ((_pos) = HLIST_FIRST(list); ((_pos) != FILLP_NULL_PTR) && ((_next) = (_pos)->next, FILLP_TRUE); \
        (_pos) = (_next))

#define HLIST_FOREACH_AT_SAFE(_pos, _next) \
    for (; ((_pos) != FILLP_NULL_PTR) && ((_next) = (_pos)->next, FILLP_TRUE); (_pos) = (_next))

static __inline void HlistDelete(struct Hlist *list, struct HlistNode *n);
static void HlistAddAfter(struct Hlist *list, struct HlistNode *prev, struct HlistNode *toBeAdded);

static struct HlistNode *HlistPopHead(struct Hlist *list);

static void HlistAddTail(struct Hlist *list, struct HlistNode *node);
static void HlistAddHead(struct Hlist *list, struct HlistNode *node);

static __inline void HlistAddAfter(struct Hlist *list, struct HlistNode *prev, struct HlistNode *toBeAdded)
{
    if (prev->next != FILLP_NULL_PTR) {
        prev->next->pprev = &toBeAdded->next;
    } else {
        list->head.pprev = &toBeAdded->next;
    }

    toBeAdded->next = prev->next;
    toBeAdded->pprev = &prev->next;
    prev->next = toBeAdded;

    list->size++;

    toBeAdded->list = (void *)list;
}

static __inline void HlistAddTail(struct Hlist *list, struct HlistNode *node)
{
    HlistAddAfter(list, HLIST_PREV(&list->head), node);
    return;
}

static __inline void HlistAddHead(struct Hlist *list, struct HlistNode *node)
{
    HlistAddAfter(list, &list->head, node);
    return;
}

void HlistDelete(struct Hlist *list, struct HlistNode *n)
{
    if (n == HLIST_TAIL(list)) {
        list->head.pprev = n->pprev;
    }

    HLIST_PREV(n)->next = n->next;
    if (n->next != FILLP_NULL_PTR) {
        n->next->pprev = n->pprev;
    }
    HLIST_INIT_NODE(n);

    if (list->size > 0) {
        list->size--;
    }
}

static __inline void HlistDelNode(struct HlistNode *n)
{
    if (n->list != FILLP_NULL_PTR) {
        HlistDelete(n->list, n);
    }
}

static __inline struct HlistNode *HlistPopHead(struct Hlist *list)
{
    struct HlistNode *ret = FILLP_NULL_PTR;
    if (list == FILLP_NULL_PTR) {
        return FILLP_NULL_PTR;
    }

    ret = HLIST_FIRST(list);
    if (ret) {
        HlistDelete(list, ret);
    }
    return ret;
}


#ifdef __cplusplus
}
#endif

#endif /* FILLP_HLIST_H */
