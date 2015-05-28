/*
 *
 * Thread Pool Implementation
 * Based on Sun Microsystems, Inc. "Multithreaded Programming Guide"
 * http://docs.sun.com/app/docs/doc/816-5137/ggedn?a=view
 *
 * Declarations for the clients of a thread pool.
 */

#include <pthread.h>

typedef unsigned int     uint_t;

/*
 * The thr_pool_t type is opaque to the client.
 * It is created by thr_pool_create() and must be passed
 * unmodified to the remainder of the interfaces.
 */
typedef struct thr_pool thr_pool_t;

/*
 * Create a thread pool.
 *  min_threads:  the minimum number of threads kept in the pool,
 *      always available to perform work requests.
 *  max_threads:  the maximum number of threads that can be
 *      in the pool, performing work requests.
 *  linger:   the number of seconds excess idle worker threads
 *      (greater than min_threads) linger before exiting.
 *  attr:   attributes of all worker threads (can be NULL);
 *      can be destroyed after calling thr_pool_create().
 * On error, thr_pool_create() returns NULL with errno set to the error code.
 */
extern  thr_pool_t  *thr_pool_create(uint_t min_threads, uint_t max_threads,
        uint_t linger, pthread_attr_t *attr);

/*
 * Enqueue a work request to the thread pool job queue.
 * If there are idle worker threads, awaken one to perform the job.
 * Else if the maximum number of workers has not been reached,
 * create a new worker thread to perform the job.
 * Else just return after adding the job to the queue;
 * an existing worker thread will perform the job when
 * it finishes the job it is currently performing.
 *
 * The job is performed as if a new detached thread were created for it:
 *  pthread_create(NULL, attr, void *(*func)(void *), void *arg);
 *
 * On error, thr_pool_queue() returns -1 with errno set to the error code.
 */
extern  int thr_pool_queue(thr_pool_t *pool, void *func, void *arg);

/*
 * Wait for all queued jobs to complete.
 */
extern  void  thr_pool_wait(thr_pool_t *pool);

/*
 * Cancel all queued jobs and destroy the pool.
 */
extern  void  thr_pool_destroy(thr_pool_t *pool);
