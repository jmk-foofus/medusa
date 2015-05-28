#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <pthread.h>

void* do_one_thing(void* arg);

int main(void) {
    pthread_t t[500];
    int i = 0;
    for (i = 0; i < 499; i++) {
        int code = pthread_create(&(t[i]), NULL, do_one_thing, NULL);
        if (code != 0) {
            printf("pthread_create error on thread %d, error code = %d\n", i, code);
            exit(1);
        }

        printf("thread %d created.\n", i);
    }

    for (i = 0; i < 499; i++) {
        if (!pthread_join(t[i], NULL)) {
            printf("pthread_join error on thread %d\n", i+1);
        }
    }

    return 0;
}

void* do_one_thing(void* arg) {
  return NULL;
}
