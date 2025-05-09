#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>

#include "web-form-resolve-path.h"

typedef struct List {
  char * value;
  struct List * next;
  struct List * prev;
} ListT;

/**
 * Allocate a new, uninitialised node on the heap.
 */
static ListT * newList() {
  return calloc(1, sizeof(ListT));
}

/**
 * Free a list, assume freeing from the head, disregard prev.
 */
static void freeList(ListT * xs) {
  for (ListT * ptr = xs, * next = NULL; ptr; ptr = next) {
    next = ptr->next;
    free(ptr->value); // safe because free(NULL) = nop
    free(ptr);
  }
}

/**
 * Copy a list pointed to by @xs@. Returns a new list, that holds the same
 * values as @xs@. Pointers are obviously different.
 */
static ListT * copyList(ListT * xs) {
  ListT * head  = NULL;
  ListT ** tail = &head;
  ListT ** prev = NULL;

  if (xs) {
    // invariant: *tail always points to the next address that can hold a new
    // node i.e. current node->next address;
    for (ListT * ptr = xs; ptr; ptr = ptr->next) {
      *tail = newList();
      (*tail)->value = strdup(ptr->value);

      if (prev) {
        (*prev)->next = *tail;
        (*tail)->prev = *prev;
      }

      prev = tail;
      tail = &(*tail)->next;
    }
  }

  return head;
}

static int listIsEmpty(ListT * xs) {
  return xs == NULL;
}

/**
 * Converts a string @path@ to a list. Returns a pointer to a list on the heap.
 * Caller is responsible for freeing the pointer.
 */
static ListT * pathToList(char * path) {

  ListT *  head = NULL;
  ListT ** tail = &head;
  ListT *  prev = NULL;

  char * saveptr;
  char * tok;

  if (path) {
    while ((tok = strtok_r(path, "/", &saveptr))) {
      *tail = newList();
      (*tail)->value = strdup(tok);

      if (prev) {
        (*tail)->prev = prev;
      }

      prev = *tail;
      tail = &(*tail)->next;
      path = NULL;
    }
  }

  return head;
}

/**
 * Pretty printer for lists to paths. Returns a pointer to a string on the heap
 * that represents the path held by list @xs@. Caller is responsible for freeing
 * the string.
 */
static char * listToPath(ListT * xs, bool stripTrailingSlash) {

  char * path = NULL
     , * end  = NULL
     ;
  size_t length = 0;

  if (xs) {
    length = 1;

    for (ListT * h = xs; h; h = h->next) {
      length += strlen(h->value) + 1;
    }

    path = calloc(length, sizeof(char) + 1);

    *path = '/';
    end = path+1;

    for (ListT * h = xs; h; h = h->next) {
      end = stpcpy(end, h->value);
      *(end++) = '/';
      *end = '\0';
    }
  } else {
    path = calloc(1, sizeof(char));
  }

  if (stripTrailingSlash)
    *(--end) = '\0';

  return path;
}

/**
 * Resolve a path with root @xs@ and relative path @ys@. The algorithm is
 * straight forward: concatenate both lists and walk from the head to the tail.
 * For each element evaluate wheter the value is one of:
 *
 *  ..    back up the list by one node, deallocate the last node. If the list
 *        was empty, it remains empty.
 *  .     do nothing, ignore
 *  else  create a new node at the end of the list that holds this value. If the
 *        list was empty, the first element is created and the pointers are set
 *        to reflect that. Otherwise, a node is appended to the end.
 */
static char * resolvePathLists(ListT * xs, ListT * ys, bool stripTrailingSlash) {

  ListT * path = NULL
      , * prev = NULL
      , * last = xs
      , ** cur = &path // points to the last link (except when empty path)
      ;
  
  char * res = "";

  if (!listIsEmpty(xs) && !listIsEmpty(ys)) {

    // find the last link of xs and join ys
    for (last = xs; last->next; last = last->next);
    last->next = ys;

    // walk the entire list
    for (ListT * ptr = xs; ptr; ptr = ptr->next) {
      if (!strncmp(ptr->value, "..", 2)) {
        // drop the last link if it exists, otherwise nop
        if (!listIsEmpty(*cur)) {
          if ((*cur)->prev) { // length > 1
            // length > 1, move cur back to previous node and free the current
            // one.
            cur = &(*cur)->prev;
            freeList((*cur)->next);
            (*cur)->next = NULL;
            prev = (*cur)->prev;
          } else { // length == 1
            // length == 0. set everything back to initial values
            freeList(*cur);
            cur = &path;
            path = NULL;
            prev = NULL;
          }
        }
      } else if (*ptr->value == '.') {
        // nop
        continue;
      } else {
        if (path) { // length > 0
          // length > 0. Add a new node to the end and adjust the pointers
          (*cur)->next = newList();
          prev = *cur;
          cur = &(*cur)->next;
          (*cur)->prev = prev;
        } else { // length == 0
          // length == 0, create a new first node and adjust the pointers
          *cur = newList();
          prev = NULL;
        }
        (*cur)->value = strdup(ptr->value);
      }
    }

    // unlink the lists
    last->next = NULL;

  } else if (listIsEmpty(xs)) { // !xs && ys
    path = copyList(ys);
  } else if (listIsEmpty(ys)) { // xs && !ys
    path = copyList(xs);
  } else { // neither
    path = newList();
    path->value = calloc(1, sizeof(char));
  }

  res = listToPath(path, stripTrailingSlash);
  freeList(path);
  return res;
}

char * resolvePath(char * root, char * path) {

  ListT * xs = pathToList(root)
      , * ys = pathToList(path)
      ;

  // keep the trailing slash if there is a trailing slash in y
  size_t length = strlen(path);
  bool stripTrailingSlash = path[length - 1] != '/';

  char * pathstr = resolvePathLists(xs, ys, stripTrailingSlash);
  
  freeList(xs);
  freeList(ys);
  return pathstr;
}
