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

#ifndef SKIPLIST_H
#define SKIPLIST_H
#include "lf_ring.h"
#include "queue.h"
#include "log.h"

#ifdef __cplusplus
extern "C" {
#endif

#define MAX_SKIPLIST_LEVEL 16

typedef FILLP_INT (*funcSkiplistCompair)(void *v1, void *v2);

struct SkipListNode {
    void *item;                                       /* value */
    struct SkipListNode *forward[MAX_SKIPLIST_LEVEL]; /* level next */
    struct SkipListNode *pre[MAX_SKIPLIST_LEVEL];
    FILLP_INT level;
#ifdef FILLP_64BIT_ALIGN
    FILLP_UINT8 padd[4];
#endif
};

struct SkipList {
    struct SkipListNode *head;
    struct SkipListNode *tail;

    struct SkipListNode *hnode[MAX_SKIPLIST_LEVEL]; /* point to the first node of each level */
    struct SkipListNode *tnode[MAX_SKIPLIST_LEVEL]; /* point to the last node of each level */
    FILLP_INT level;                                /* the current max level of list */
    FILLP_UINT32 nodeNum;
    funcSkiplistCompair funcCmp;
    FILLP_UINT8 randomLev[MAX_RANDOM_LEV];
    FILLP_UINT32 randomIndex;
};

/*******************************************************************************
    Function    : SkipListGetPop

    Description : This function will be invoked to pop the head node from
                  SkipList.

    Input       : list - SkipList pointer

    Output      : None

    Return      : None
*******************************************************************************/
static __inline struct SkipListNode *SkipListGetPop(struct SkipList *list)
{
    return ((list == FILLP_NULL_PTR) || (list->head == FILLP_NULL_PTR)) ? FILLP_NULL_PTR : list->head;
}

/*******************************************************************************
    Function    : SkipListGetTail

    Description : This function will be invoked to pop the head node from
                  SkipList.

    Input       : list - SkipList pointer

    Output      : None

    Return      : None
*******************************************************************************/
static __inline struct SkipListNode *SkipListGetTail(struct SkipList *list)
{
    return ((list == FILLP_NULL_PTR) || (list->tail == FILLP_NULL_PTR)) ? FILLP_NULL_PTR : list->tail;
}

/*******************************************************************************
    Function    : SkiplistInit

    Description : This function will be invoked to init the SkipList.

    Input       : list - SkipList to be initialised
                  cmp - SkipList compare function

    Output      : None

    Return      : If success, returns ERR_OK. Otherwise, returns Error code.
*******************************************************************************/
FILLP_INT SkiplistInit(struct SkipList *list, funcSkiplistCompair cmp);

/*******************************************************************************
    Function    : SkipListInsert

    Description : This function will be invoked to insert a node to SkipList.

    Input       : list - SkipList pointer
                  item - value of the SkipList node
                  node - SkipList node to be inserted to SkipList
                  err_if_conflict - Flag to decide whether to give error if any
                  conflicts between item of node to be inserted and existing
                  node

    Output      : None

    Return      : ERR_OK, if success. Error codes on failures.
*******************************************************************************/
FILLP_INT SkipListInsert(struct SkipList *list, void *item, struct SkipListNode *node, FILLP_BOOL errIfConflict);

/*******************************************************************************
    Function    : SkipListPopValue

    Description : This function will be invoked to pop a value from SkipList.

    Input       : list - SkipList to be destroyed

    Output      : None

    Return      : None
*******************************************************************************/
void *SkipListPopValue(struct SkipList *list);


/*******************************************************************************
    Function    : SkipListPopTail

    Description : This function will be invoked to pop tail value from SkipList.

    Input       : list - SkipList pointer

    Output      : None

    Return      : None
*******************************************************************************/
void *SkipListPopTail(struct SkipList *list);


/*******************************************************************************
    Function    : SkiplistDestroy

    Description : This function will be invoked to destroy the SkipList.

    Input       : list - SkipList to be destroyed

    Output      : None

    Return      : None
*******************************************************************************/
void SkiplistDestroy(struct SkipList *list);

FILLP_UINT32 SkiplistGetNodeNum(struct SkipList *list);

#ifdef __cplusplus
}
#endif
#endif /* SKIPLIST_H */