#ifndef _NGX_HTTPSO_ASYNC_WORK_H_
#define _NGX_HTTPSO_ASYNC_WORK_H_

#include <deque>
#include <vector>
#include <condition_variable>
#include <common/ngx_httpso_entry.h>

class NgxHttpsoAsyncWork
{
public:
    NgxHttpsoAsyncWork();
    int AsyncWorkStart(int thread_count);
    int AsyncWorkStop(void);

public:
    int AsyncWorkAddWork(AsyncWorkEntryPtr &e);
    AsyncWorkEntryPtr AsyncWorkPopComplete(void);

private:
    void AsyncWorkTaskFunc(void);

private:
    std::vector<ThreadPtr>  work_tasks_;
    bool                     work_tasks_stop_;

    typedef std::deque<AsyncWorkEntryPtr> WorkEntryQue;

    std::condition_variable  work_entrys_cond_;
    std::mutex    work_entrys_lock_;
    WorkEntryQue  work_entrys_;

    std::mutex    complete_entrys_lock_;
    WorkEntryQue  complete_entrys_;
};
typedef std::shared_ptr<NgxHttpsoAsyncWork> NgxHttpsoAsyncWorkPtr;

#endif

