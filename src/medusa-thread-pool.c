/*
 *
 * Thread Pool Implementation
 * Based on Sun Microsystems, Inc. "Multithreaded Programming Guide"
 * http://docs.sun.com/app/docs/doc/816-5137/ggedn?a=view
 *
 * See <medusa-thread-pool.h> for interface declarations.
 */

#if !defined(_REENTRANT)
#define _REENTRANT
#endif

//#include "medusa-thread-pool.h"
#include "medusa.h"
#include <stdlib.h>
#include <signal.h>
#include <errno.h>

/*
 * FIFO queued job
 */
typedef struct job job_t;
struct job {
  job_t *job_next;    /* linked list of jobs */
  void  *(*job_func)(void *); /* function to call */
  void  *job_arg;   /* its argument */
};

/*
 * List of active worker threads, linked through their stacks.
 */
typedef struct active active_t;
struct active {
  active_t  *active_next; /* linked list of threads */
  pthread_t active_tid; /* active thread id */
};

/*
 * The thread pool, opaque to the clients.
 */
struct thr_pool {
  thr_pool_t  *pool_forw; /* circular linked list */
  thr_pool_t  *pool_back; /* of all thread pools */
  pthread_mutex_t pool_mutex; /* protects the pool data */
  pthread_cond_t  pool_busycv;  /* synchronization in pool_queue */
  pthread_cond_t  pool_workcv;  /* synchronization with workers */
  pthread_cond_t  pool_waitcv;  /* synchronization in pool_wait() */
  active_t  *pool_active; /* list of threads performing work */
  job_t   *pool_head; /* head of FIFO job queue */
  job_t   *pool_tail; /* tail of FIFO job queue */
  pthread_attr_t  pool_attr;  /* attributes of the workers */
  int   pool_flags; /* see below */
  uint_t    pool_linger;  /* seconds before idle workers exit */
  int   pool_minimum; /* minimum number of worker threads */
  int   pool_maximum; /* maximum number of worker threads */
  int   pool_nthreads;  /* current number of worker threads */
  int   pool_idle;  /* number of idle workers */
};

/* pool_flags */
#define POOL_WAIT 0x01    /* waiting in thr_pool_wait() */
#define POOL_DESTROY  0x02    /* pool is being destroyed */

/* the list of all created and not yet destroyed thread pools */
static thr_pool_t *thr_pools = NULL;

/* protects thr_pools */
static pthread_mutex_t thr_pool_lock = PTHREAD_MUTEX_INITIALIZER;

/* set of all signals */
static sigset_t fillset;

static void *worker_thread(void *);

static int
create_worker(thr_pool_t *pool)
{
  sigset_t oset;
  int error;

  /* jmk - The original code passed NULL to pthread_create for thread ID.
           This appears to cause segfaults on Linux... */
  pthread_t *ppthread;
  ppthread = malloc( sizeof(pthread_t) );
  memset(ppthread, 0, sizeof(pthread_t));

  (void) pthread_sigmask(SIG_SETMASK, &fillset, &oset);
  error = pthread_create(ppthread, &pool->pool_attr, worker_thread, pool);
  (void) pthread_sigmask(SIG_SETMASK, &oset, NULL);

  free(ppthread);

  return (error);
}

/*
 * Worker thread is terminating.  Possible reasons:
 * - excess idle thread is terminating because there is no work.
 * - thread was cancelled (pool is being destroyed).
 * - the job function called pthread_exit().
 * In the last case, create another worker thread
 * if necessary to keep the pool populated.
 */
static void
worker_cleanup(thr_pool_t *pool)
{
  --pool->pool_nthreads;
  if (pool->pool_flags & POOL_DESTROY) {
    if (pool->pool_nthreads == 0)
      (void) pthread_cond_broadcast(&pool->pool_busycv);
  } else if (pool->pool_head != NULL &&
      pool->pool_nthreads < pool->pool_maximum &&
      create_worker(pool) == 0) {
    pool->pool_nthreads++;
  }
  (void) pthread_mutex_unlock(&pool->pool_mutex);
}

static void
notify_waiters(thr_pool_t *pool)
{
  if (pool->pool_head == NULL && pool->pool_active == NULL) {
    pool->pool_flags &= ~POOL_WAIT;
    (void) pthread_cond_broadcast(&pool->pool_waitcv);
  }
}

/*
 * Called by a worker thread on return from a job.
 */
static void
job_cleanup(thr_pool_t *pool)
{
  pthread_t my_tid = pthread_self();
  active_t *activep;
  active_t **activepp;

  (void) pthread_mutex_lock(&pool->pool_mutex);
  for (activepp = &pool->pool_active;
      (activep = *activepp) != NULL;
      activepp = &activep->active_next) {
    if (activep->active_tid == my_tid) {
      *activepp = activep->active_next;
      break;
    }
  }
  if (pool->pool_flags & POOL_WAIT)
    notify_waiters(pool);
}

static void *
worker_thread(void *arg)
{
  thr_pool_t *pool = (thr_pool_t *)arg;
  int timedout;
  job_t *job;
  void *(*func)(void *);
  active_t active;
  struct timespec ts;
#ifndef HAVE_CLOCK_GETTIME
  struct timeval tv;
#endif

  /*
   * This is the worker's main loop.  It will only be left
   * if a timeout occurs or if the pool is being destroyed.
   */
  (void) pthread_mutex_lock(&pool->pool_mutex);
  pthread_cleanup_push((void *)worker_cleanup, pool);
  active.active_tid = pthread_self();
  for (;;) {
    /*
     * We don't know what this thread was doing during
     * its last job, so we reset its signal mask and
     * cancellation state back to the initial values.
     */
    (void) pthread_sigmask(SIG_SETMASK, &fillset, NULL);
    (void) pthread_setcanceltype(PTHREAD_CANCEL_DEFERRED, NULL);
    (void) pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);

    timedout = 0;
    pool->pool_idle++;
    if (pool->pool_flags & POOL_WAIT)
      notify_waiters(pool);
    while (pool->pool_head == NULL &&
        !(pool->pool_flags & POOL_DESTROY)) {
      if (pool->pool_nthreads <= pool->pool_minimum) {
        (void) pthread_cond_wait(&pool->pool_workcv,
            &pool->pool_mutex);
      } else {
#ifndef HAVE_CLOCK_GETTIME
      	gettimeofday(&tv, NULL);
	ts.tv_sec = tv.tv_sec;
	ts.tv_nsec = tv.tv_usec * 1000;
#else
        (void) clock_gettime(CLOCK_REALTIME, &ts);
#endif
        ts.tv_sec += pool->pool_linger;
        if (pool->pool_linger == 0 ||
            pthread_cond_timedwait(&pool->pool_workcv,
            &pool->pool_mutex, &ts) == ETIMEDOUT) {
          timedout = 1;
          break;
        }
      }
    }
    pool->pool_idle--;
    if (pool->pool_flags & POOL_DESTROY)
      break;
    if ((job = pool->pool_head) != NULL) {
      timedout = 0;
      func = job->job_func;
      arg = job->job_arg;
      pool->pool_head = job->job_next;
      if (job == pool->pool_tail)
        pool->pool_tail = NULL;
      active.active_next = pool->pool_active;
      pool->pool_active = &active;
      (void) pthread_mutex_unlock(&pool->pool_mutex);
      pthread_cleanup_push((void *)job_cleanup, pool);
      free(job);
      /*
       * Call the specified job function.
       */
      (void) func(arg);
      /*
       * If the job function calls pthread_exit(), the thread
       * calls job_cleanup(pool) and worker_cleanup(pool);
       * the integrity of the pool is thereby maintained.
       */
      pthread_cleanup_pop(1); /* job_cleanup(pool) */
    }
    if (timedout && pool->pool_nthreads > pool->pool_minimum) {
      /*
       * We timed out and there is no work to be done
       * and the number of workers exceeds the minimum.
       * Exit now to reduce the size of the pool.
       */
      break;
    }
  }
  pthread_cleanup_pop(1); /* worker_cleanup(pool) */
  return (NULL);
}

static void
clone_attributes(pthread_attr_t *new_attr, pthread_attr_t *old_attr)
{
  struct sched_param param;
  void *addr;
  size_t size;
  int value;

  (void) pthread_attr_init(new_attr);

  if (old_attr != NULL) {
    (void) pthread_attr_getstack(old_attr, &addr, &size);
    /* don't allow a non-NULL thread stack address */
    (void) pthread_attr_setstack(new_attr, NULL, size);

    (void) pthread_attr_getscope(old_attr, &value);
    (void) pthread_attr_setscope(new_attr, value);

    (void) pthread_attr_getinheritsched(old_attr, &value);
    (void) pthread_attr_setinheritsched(new_attr, value);

    (void) pthread_attr_getschedpolicy(old_attr, &value);
    (void) pthread_attr_setschedpolicy(new_attr, value);

    (void) pthread_attr_getschedparam(old_attr, &param);
    (void) pthread_attr_setschedparam(new_attr, &param);

    (void) pthread_attr_getguardsize(old_attr, &size);
    (void) pthread_attr_setguardsize(new_attr, size);
  }

  /* make all pool threads be detached threads */
  (void) pthread_attr_setdetachstate(new_attr, PTHREAD_CREATE_DETACHED);
}

thr_pool_t *
thr_pool_create(uint_t min_threads, uint_t max_threads, uint_t linger,
  pthread_attr_t *attr)
{
  thr_pool_t  *pool;

  (void) sigfillset(&fillset);

  if (min_threads > max_threads || max_threads < 1) {
    errno = EINVAL;
    return (NULL);
  }

  if ((pool = malloc(sizeof (*pool))) == NULL) {
    errno = ENOMEM;
    return (NULL);
  }
  (void) pthread_mutex_init(&pool->pool_mutex, NULL);
  (void) pthread_cond_init(&pool->pool_busycv, NULL);
  (void) pthread_cond_init(&pool->pool_workcv, NULL);
  (void) pthread_cond_init(&pool->pool_waitcv, NULL);
  pool->pool_active = NULL;
  pool->pool_head = NULL;
  pool->pool_tail = NULL;
  pool->pool_flags = 0;
  pool->pool_linger = linger;
  pool->pool_minimum = min_threads;
  pool->pool_maximum = max_threads;
  pool->pool_nthreads = 0;
  pool->pool_idle = 0;

  /*
   * We cannot just copy the attribute pointer.
   * We need to initialize a new pthread_attr_t structure using
   * the values from the caller-supplied attribute structure.
   * If the attribute pointer is NULL, we need to initialize
   * the new pthread_attr_t structure with default values.
   */
  clone_attributes(&pool->pool_attr, attr);

  /* insert into the global list of all thread pools */
  (void) pthread_mutex_lock(&thr_pool_lock);
  if (thr_pools == NULL) {
    pool->pool_forw = pool;
    pool->pool_back = pool;
    thr_pools = pool;
  } else {
    thr_pools->pool_back->pool_forw = pool;
    pool->pool_forw = thr_pools;
    pool->pool_back = thr_pools->pool_back;
    thr_pools->pool_back = pool;
  }
  (void) pthread_mutex_unlock(&thr_pool_lock);

  return (pool);
}

int
thr_pool_queue(thr_pool_t *pool, void *func, void *arg)
{
  job_t *job;

  if ((job = malloc(sizeof (*job))) == NULL) {
    errno = ENOMEM;
    return (-1);
  }
  job->job_next = NULL;
  job->job_func = func;
  job->job_arg = arg;

  (void) pthread_mutex_lock(&pool->pool_mutex);

  if (pool->pool_head == NULL)
    pool->pool_head = job;
  else
    pool->pool_tail->job_next = job;
  pool->pool_tail = job;
  
  if (pool->pool_idle > 0)
    (void) pthread_cond_signal(&pool->pool_workcv);
  else if (pool->pool_nthreads < pool->pool_maximum &&
      create_worker(pool) == 0)
    pool->pool_nthreads++;

  (void) pthread_mutex_unlock(&pool->pool_mutex);
  return (0);
}

void
thr_pool_wait(thr_pool_t *pool)
{
  (void) pthread_mutex_lock(&pool->pool_mutex);
  pthread_cleanup_push((void *)pthread_mutex_unlock, &pool->pool_mutex);
  while (pool->pool_head != NULL || pool->pool_active != NULL) {
    pool->pool_flags |= POOL_WAIT;
    (void) pthread_cond_wait(&pool->pool_waitcv, &pool->pool_mutex);
  }
  pthread_cleanup_pop(1); /* pthread_mutex_unlock(&pool->pool_mutex); */
}

void
thr_pool_destroy(thr_pool_t *pool)
{
  active_t *activep;
  job_t *job;

  (void) pthread_mutex_lock(&pool->pool_mutex);
  pthread_cleanup_push((void *)pthread_mutex_unlock, &pool->pool_mutex);

  /* mark the pool as being destroyed; wakeup idle workers */
  pool->pool_flags |= POOL_DESTROY;
  (void) pthread_cond_broadcast(&pool->pool_workcv);

  /* cancel all active workers */
  for (activep = pool->pool_active;
      activep != NULL;
      activep = activep->active_next)
    (void) pthread_cancel(activep->active_tid);

  /* wait for all active workers to finish */
  while (pool->pool_active != NULL) {
    pool->pool_flags |= POOL_WAIT;
    (void) pthread_cond_wait(&pool->pool_waitcv, &pool->pool_mutex);
  }

  /* the last worker to terminate will wake us up */
  while (pool->pool_nthreads != 0)
    (void) pthread_cond_wait(&pool->pool_busycv, &pool->pool_mutex);

  pthread_cleanup_pop(1); /* pthread_mutex_unlock(&pool->pool_mutex); */

  /*
   * Unlink the pool from the global list of all pools.
   */
  (void) pthread_mutex_lock(&thr_pool_lock);
  if (thr_pools == pool)
    thr_pools = pool->pool_forw;
  if (thr_pools == pool)
    thr_pools = NULL;
  else {
    pool->pool_back->pool_forw = pool->pool_forw;
    pool->pool_forw->pool_back = pool->pool_back;
  }
  (void) pthread_mutex_unlock(&thr_pool_lock);

  /*
   * There should be no pending jobs, but just in case...
   */
  for (job = pool->pool_head; job != NULL; job = pool->pool_head) {
    pool->pool_head = job->job_next;
    free(job);
  }
  (void) pthread_attr_destroy(&pool->pool_attr);
  free(pool);
}
