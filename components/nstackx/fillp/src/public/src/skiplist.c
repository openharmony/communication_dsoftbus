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

#include "skiplist.h"

#ifdef __cplusplus
extern "C" {
#endif

/*******************************************************************************
    Function    : SkiplistRandomLevel

    Description : This function will be invoked to generate random level for
                SkipList node.

    Input       : None

    Output      : None

    Return      : SkipList node level
*******************************************************************************/
static FILLP_INT SkiplistRandomLevel(struct SkipList *list)
{
    FILLP_INT k = 1;

    while ((list->randomLev[(list->randomIndex++) & (MAX_RANDOM_LEV - 1)]) && (k < MAX_SKIPLIST_LEVEL)) {
        k++;
    }
    return k;
}

/*******************************************************************************
    Function    : SkiplistInit

    Description : This function will be invoked to init the SkipList.

    Input       : list - SkipList to be initialised
                  cmp - SkipList compare function

    Output      : None

    Return      : If success, returns ERR_OK. Otherwise, returns Error code.
*******************************************************************************/
FILLP_INT SkiplistInit(struct SkipList *list, funcSkiplistCompair cmp)
{
    int i;

    /* do not set when skip_item_pool has value check by code cc */
    if (list == FILLP_NULL_PTR) {
        FILLP_LOGERR("list->skip_item_pool is not NULL");
        return ERR_PARAM;
    }

    list->level = 0;
    list->head = FILLP_NULL_PTR;
    list->tail = FILLP_NULL_PTR;
    (void)memset_s(list->hnode, sizeof(list->hnode), 0, sizeof(list->hnode));
    (void)memset_s(list->tnode, sizeof(list->tnode), 0, sizeof(list->tnode));
    list->nodeNum = 0;

    list->funcCmp = cmp;
    list->randomIndex = 0;

    for (i = 0; i < MAX_RANDOM_LEV; i++) {
        list->randomLev[i] = (FILLP_UINT8)(FILLP_RAND() & 0x01);
    }
    return ERR_OK;
}

/*******************************************************************************
    Function    : SkiplistDestroy

    Description : This function will be invoked to destroy the SkipList.

    Input       : list - SkipList to be destroyed

    Output      : None

    Return      : None
*******************************************************************************/
void SkiplistDestroy(struct SkipList *list)
{
    list->head = FILLP_NULL_PTR;
    list->tail = FILLP_NULL_PTR;
    list->nodeNum = 0;

    (void)memset_s(list->hnode, sizeof(list->hnode), 0, sizeof(list->hnode));
    (void)memset_s(list->tnode, sizeof(list->tnode), 0, sizeof(list->tnode));
}

/*******************************************************************************
    Function    : SkipListPopValue

    Description : This function will be invoked to pop a value from SkipList.

    Input       : list - SkipList pointer

    Output      : None

    Return      : None
*******************************************************************************/
void *SkipListPopValue(struct SkipList *list)
{
    struct SkipListNode *head = FILLP_NULL_PTR;
    FILLP_INT index;

    if ((list == FILLP_NULL_PTR) || (list->head == FILLP_NULL_PTR)) {
        return FILLP_NULL_PTR;
    }

    head = list->head;

    for (index = head->level - 1; index >= 0; index--) {
        list->hnode[index] = head->forward[index];

        if (list->hnode[index] == FILLP_NULL_PTR) {
            /* the last one of this level */
            list->tnode[index] = FILLP_NULL_PTR;
            list->level--;
        } else {
            list->hnode[index]->pre[index] = FILLP_NULL_PTR;
        }
    }

    list->head = head->forward[0];
    if (list->head == FILLP_NULL_PTR) {
        list->tail = FILLP_NULL_PTR;
    }

    list->nodeNum--;
    return head->item;
}

/*******************************************************************************
    Function    : SkipListPopTail

    Description : This function will be invoked to pop tail value from SkipList.

    Input       : list - SkipList pointer

    Output      : None

    Return      : None
*******************************************************************************/
void *SkipListPopTail(struct SkipList *list)
{
    struct SkipListNode *tail = FILLP_NULL_PTR;
    struct SkipListNode *tnode = FILLP_NULL_PTR;
    FILLP_INT index;

    if ((list == FILLP_NULL_PTR) || (list->tail == FILLP_NULL_PTR)) {
        return FILLP_NULL_PTR;
    }

    tail = list->tail;

    for (index = tail->level - 1; index >= 0; index--) {
        tnode = tail->pre[index];
        if (tnode != FILLP_NULL_PTR) {
            tnode->forward[index] = FILLP_NULL_PTR;
        } else {
            // It is the only one of this level
            list->level--;
            list->hnode[index] = FILLP_NULL_PTR;
        }
        list->tnode[index] = tnode;
    }

    list->tail = tail->pre[0];
    if (list->tail == FILLP_NULL_PTR) {
        list->head = FILLP_NULL_PTR;
    }

    list->nodeNum--;
    return tail->item;
}

static FILLP_INT SkiplistInsertAtMid(struct SkipList *list, void *item,
    struct SkipListNode *node, FILLP_BOOL errIfConflict, FILLP_INT curMinLevel)
{
    struct SkipListNode *prevRecord[MAX_SKIPLIST_LEVEL];
    struct SkipListNode *prev = FILLP_NULL_PTR;
    struct SkipListNode *next = FILLP_NULL_PTR;
    FILLP_INT index;

    (void)memset_s(prevRecord, sizeof(prevRecord), 0, sizeof(prevRecord));

    for (index = list->level - 1; index >= 0; index--) {
        /* for each level, find the pre node of the point to insert */
        if (prev == FILLP_NULL_PTR) {
            next = list->hnode[index];
        } else {
            next = prev->forward[index];
        }

        while (next && list->funcCmp(item, next->item) > 0) {
            prev = next;
            next = next->forward[index];
        }
        prevRecord[index] = prev;
    }

    if ((next != FILLP_NULL_PTR) && (list->funcCmp(next->item, item) == 0) && errIfConflict) {
        return ERR_COMM;
    }

    /* after inser the item after pre node, if the pre node is the last node, update list->tnode */
    for (index = 0; index < curMinLevel; index++) {
        if (prevRecord[index] == FILLP_NULL_PTR) {
            /* min value of this level */
            node->forward[index] = list->hnode[index];
            list->hnode[index]->pre[index] = node;
            list->hnode[index] = node;
            continue;
        }
        node->forward[index] = prevRecord[index]->forward[index];
        node->pre[index] = prevRecord[index];
        if (node->forward[index] == FILLP_NULL_PTR) {
            list->tnode[index] = node;
        } else {
            prevRecord[index]->forward[index]->pre[index] = node;
        }
        prevRecord[index]->forward[index] = node;
    }
    return 0;
}

static void SkipListInsertFirstNode(struct SkipList *list, struct SkipListNode *node)
{
    FILLP_INT index;
    FILLP_INT level = node->level;
    list->head = node;
    list->tail = node;

    for (index = level - 1; index >= 0; index--) {
        list->hnode[index] = node;
        list->tnode[index] = node;
    }
    list->level = level;

    list->nodeNum++;
}

static void SkipListInsertAtTail(struct SkipList *list, struct SkipListNode *node, int curMinLevel)
{
    int index;
    for (index = 0; index < curMinLevel; index++) {
        node->pre[index] = list->tnode[index];
        list->tnode[index]->forward[index] = node;
        list->tnode[index] = node;
    }
}

static void SkipListInsertAtHead(struct SkipList *list, struct SkipListNode *node, int curMinLevel)
{
    int index;
    for (index = 0; index < curMinLevel; index++) {
        list->hnode[index]->pre[index] = node;
        node->forward[index] = list->hnode[index];
        list->hnode[index] = node;
    }
}

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
FILLP_INT SkipListInsert(struct SkipList *list, void *item, struct SkipListNode *node, FILLP_BOOL errIfConflict)
{
    FILLP_INT index;
    FILLP_INT level;
    FILLP_INT curMinLevel;
    FILLP_INT i = 0;

    if ((list == FILLP_NULL_PTR) || (item == FILLP_NULL_PTR)) {
        FILLP_LOGWAR("SkipListInsert; Invalid parameters passed \r\n");
        return ERR_PARAM;
    }

    node->level = SkiplistRandomLevel(list);
    node->item = item;
    while (i < MAX_SKIPLIST_LEVEL) {
        node->forward[i] = FILLP_NULL_PTR;
        node->pre[i] = FILLP_NULL;
        i++;
    }

    level = node->level;

    /* list is empty */
    if (list->head == FILLP_NULL_PTR) {
        SkipListInsertFirstNode(list, node);
        return ERR_OK;
    }

    curMinLevel = (list->level > level) ? level : list->level;
    /* the key value of item is large than the max value of list */
    if (list->funcCmp(item, list->tail->item) > 0) {
        /* add the item to the tail */
        SkipListInsertAtTail(list, node, curMinLevel);
    } else if (list->funcCmp(list->head->item, item) > 0) {
        /* insert the item to front */
        SkipListInsertAtHead(list, node, curMinLevel);
    } else {
        if (SkiplistInsertAtMid(list, item, node, errIfConflict, curMinLevel)) {
            return ERR_COMM;
        }
    }

    /* If list->level incresed */
    if (list->level < level) {
        for (index = list->level; index < level; index++) {
            list->hnode[index] = node;
            list->tnode[index] = node;
        }
        list->level = level;
    }
    list->nodeNum++;

    /* The timer_manager use SkipList to sort all timer nodes. If the value of
       new node to be inserted equals the value of list header,
       it will get problem - The list->head won't fresh.
    */
    list->head = list->hnode[0];
    list->tail = list->tnode[0];

    return ERR_OK;
}

FILLP_UINT32 SkiplistGetNodeNum(struct SkipList *list)
{
    return list->nodeNum;
}

#ifdef __cplusplus
}
#endif
