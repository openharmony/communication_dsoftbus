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

#include "rb_tree.h"

#ifdef __cplusplus
extern "C" {
#endif

static void FillpRbRotateLeft(struct RbNode *x, struct RbRoot *root)
{
    /*
     * rotate Node x to left *
     */
    struct RbNode *y = x->rbRight;

    /* estblish x->Right link */
    x->rbRight = y->rbLeft;
    if (y->rbLeft != FILLP_NULL_PTR) {
        y->rbLeft->rbParent = x;
    }

    /* estblish y->parent link */
    y->rbParent = x->rbParent;
    if (x->rbParent != FILLP_NULL_PTR) {
        if (x == x->rbParent->rbLeft) {
            x->rbParent->rbLeft = y;
        } else {
            x->rbParent->rbRight = y;
        }
    } else {
        root->rbNode = y;
    }

    /* link x and y */
    y->rbLeft = x;
    x->rbParent = y;
}


static void FillpRbRotateRight(struct RbNode *x, struct RbRoot *root)
{
    /*
     * rotate Node x to right  *
     */
    struct RbNode *y = x->rbLeft;

    /* estblish x->Left link */
    x->rbLeft = y->rbRight;
    if (y->rbRight != FILLP_NULL_PTR) {
        y->rbRight->rbParent = x;
    }

    /* estblish y->parent link */
    y->rbParent = x->rbParent;
    if (x->rbParent != FILLP_NULL_PTR) {
        if (x == x->rbParent->rbRight) {
            x->rbParent->rbRight = y;
        } else {
            x->rbParent->rbLeft = y;
        }
    } else {
        root->rbNode = y;
    }

    /* link x and y */
    y->rbRight = x;
    x->rbParent = y;
}

static struct RbNode *EqualRight(struct RbNode *x, struct RbRoot *root)
{
    if (x == x->rbParent->rbRight) {
        /* make x a left child */
        x = x->rbParent;
        FillpRbRotateLeft(x, root);
    }
    return x;
}

static struct RbNode *EqualLeft(struct RbNode *x, struct RbRoot *root)
{
    if (x == x->rbParent->rbLeft) {
        x = x->rbParent;
        FillpRbRotateRight(x, root);
    }
    return x;
}

/* x, y are for application */
void FillpRbInsertColor(struct RbNode *x, struct RbRoot *root)
{
    /* maintain red-black tree balance  *
     * after inserting node x           *
     * check red-black properties */
    while (x != root->rbNode && x->rbParent->color == RB_RED) {
        /* we have a violation */
        if (x->rbParent == x->rbParent->rbParent->rbLeft) {
            struct RbNode *y = x->rbParent->rbParent->rbRight;
            if (y && y->color == RB_RED) {
                /* uncle is red */
                x->rbParent->color = RB_BLACK;
                y->color = RB_BLACK;
                x->rbParent->rbParent->color = RB_RED;
                x = x->rbParent->rbParent;
            } else {
                /* uncle is black */
                x = EqualRight(x, root);

                /* recolor and rotate */
                x->rbParent->color = RB_BLACK;
                x->rbParent->rbParent->color = RB_RED;
                FillpRbRotateRight(x->rbParent->rbParent, root);
            }
        } else {
            /* miror image of above code */
            struct RbNode *y = x->rbParent->rbParent->rbLeft;
            if ((y != FILLP_NULL_PTR) && (y->color == RB_RED)) {
                /* uncle is red */
                x->rbParent->color = RB_BLACK;
                y->color = RB_BLACK;
                x->rbParent->rbParent->color = RB_RED;
                x = x->rbParent->rbParent;
            } else {
                /* uncle is black */
                x = EqualLeft(x, root);
                x->rbParent->color = RB_BLACK;
                x->rbParent->rbParent->color = RB_RED;
                FillpRbRotateLeft(x->rbParent->rbParent, root);
            }
        }
    }

    root->rbNode->color = RB_BLACK;
}

static int FillpRbEraseColorAtLeft(struct RbNode **x, struct RbNode **parent, struct RbRoot *root)
{
    struct RbNode *w = (*parent)->rbRight;
    if (w->color == RB_RED) {
        w->color = RB_BLACK;
        (*parent)->color = RB_RED; /* parent != NIL? */
        FillpRbRotateLeft((*parent), root);
        return 0;
    }
    if (((w->rbLeft == FILLP_NULL_PTR) || (w->rbLeft->color == RB_BLACK)) &&
        ((w->rbRight == FILLP_NULL_PTR) || (w->rbRight->color == RB_BLACK))) {
        w->color = RB_RED;
        (*x) = (*parent);
        (*parent) = (*x)->rbParent;
        return 0;
    } else {
        if ((w->rbRight == FILLP_NULL_PTR) || (w->rbRight->color == RB_BLACK)) {
            if (w->rbLeft != FILLP_NULL_PTR) {
                w->rbLeft->color = RB_BLACK;
            }
            w->color = RB_RED;
            FillpRbRotateRight(w, root);
            w = (*parent)->rbRight;
        }
        w->color = (*parent)->color;
        (*parent)->color = RB_BLACK;
        if (w->rbRight->color != RB_BLACK) {
            w->rbRight->color = RB_BLACK;
        }
        FillpRbRotateLeft((*parent), root);
        (*x) = root->rbNode;
        return 1;
    }
}

static int FillpRbEraseColorAtRight(struct RbNode **x, struct RbNode **parent, struct RbRoot *root)
{
    struct RbNode *w = (*parent)->rbLeft;
    if (w->color == RB_RED) {
        w->color = RB_BLACK;
        (*parent)->color = RB_RED; /* parent != NIL? */
        FillpRbRotateRight((*parent), root);
        return 0;
    }
    if (((w->rbLeft == FILLP_NULL_PTR) || (w->rbLeft->color == RB_BLACK)) &&
        ((w->rbRight == FILLP_NULL_PTR) || (w->rbRight->color == RB_BLACK))) {
        w->color = RB_RED;
        (*x) = (*parent);
        (*parent) = (*x)->rbParent;
        return 0;
    } else {
        if ((w->rbLeft == FILLP_NULL_PTR) || (w->rbLeft->color == RB_BLACK)) {
            if (w->rbRight != FILLP_NULL_PTR) {
                w->rbRight->color = RB_BLACK;
            }
            w->color = RB_RED;
            FillpRbRotateLeft(w, root);
            w = (*parent)->rbLeft;
        }
        w->color = (*parent)->color;
        (*parent)->color = RB_BLACK;
        if (w->rbLeft->color != RB_BLACK) {
            w->rbLeft->color = RB_BLACK;
        }
        FillpRbRotateRight((*parent), root);
        (*x) = root->rbNode;
        return 1;
    }
}

static void FillpRbEraseColor(struct RbNode *x, struct RbNode *parent, struct RbRoot *root)
{
    /*
     * maintain red-black tree balance  *
     * after deleting node x            *
     */
    int ret;
    while ((x != root->rbNode) && ((x == FILLP_NULL_PTR) || (x->color == RB_BLACK))) {
        if (parent == FILLP_NULL_PTR) {
            break;
        }

        if (x == parent->rbLeft) {
            ret = FillpRbEraseColorAtLeft(&x, &parent, root);
            if (ret != 0) {
                break;
            }
        } else {
            ret = FillpRbEraseColorAtRight(&x, &parent, root);
            if (ret != 0) {
                break;
            }
        }
    }

    if (x != FILLP_NULL_PTR) {
        x->color = RB_BLACK;
    }
}

static void FillpRbEraseLowlvlNode(struct RbNode *node, struct RbRoot *root)
{
    struct RbNode *childNode = FILLP_NULL_PTR;
    struct RbNode *parentNode = FILLP_NULL_PTR;
    struct RbNode *oldNode = node;
    struct RbNode *leftNode;
    FILLP_UINT color;

    node = node->rbRight;
    leftNode = node->rbLeft;
    while (leftNode != FILLP_NULL_PTR) {
        node = leftNode;
        leftNode = node->rbLeft;
    }

    if (oldNode->rbParent != FILLP_NULL_PTR) {
        if (oldNode->rbParent->rbLeft == oldNode) {
            oldNode->rbParent->rbLeft = node;
        } else {
            oldNode->rbParent->rbRight = node;
        }
    } else {
        root->rbNode = node;
    }

    childNode = node->rbRight;
    parentNode = node->rbParent;
    color = node->color;

    if (parentNode == oldNode) {
        parentNode = node;
    } else {
        if (childNode != FILLP_NULL_PTR) {
            childNode->rbParent = parentNode;
        }

        parentNode->rbLeft = childNode;

        node->rbRight = oldNode->rbRight;
        oldNode->rbRight->rbParent = node;
    }

    node->color = oldNode->color;
    node->rbParent = oldNode->rbParent;
    node->rbLeft = oldNode->rbLeft;
    oldNode->rbLeft->rbParent = node;

    if (color == RB_BLACK) {
        FillpRbEraseColor(childNode, parentNode, root);
    }
}

void FillpRbErase(struct RbNode *node, struct RbRoot *root)
{
    struct RbNode *childNode = FILLP_NULL_PTR;
    struct RbNode *parentNode = FILLP_NULL_PTR;
    FILLP_UINT color;

    if (node->rbLeft == FILLP_NULL_PTR) {
        childNode = node->rbRight;
    } else if (node->rbRight == FILLP_NULL_PTR) {
        childNode = node->rbLeft;
    } else {
        FillpRbEraseLowlvlNode(node, root);
        return;
    }

    parentNode = node->rbParent;
    color = node->color;

    if (childNode != FILLP_NULL_PTR) {
        childNode->rbParent = parentNode;
    }

    if (parentNode != FILLP_NULL_PTR) {
        if (parentNode->rbLeft == node) {
            parentNode->rbLeft = childNode;
        } else {
            parentNode->rbRight = childNode;
        }
    } else {
        root->rbNode = childNode;
    }

    if (color == RB_BLACK) {
        FillpRbEraseColor(childNode, parentNode, root);
    }
}


#ifdef __cplusplus
}
#endif
