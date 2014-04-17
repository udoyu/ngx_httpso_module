extern "C" {
    #include <ngx_config.h>
    #include <ngx_core.h>
    #include <ngx_http.h>
}

#include <ngx_httpso_async_work.h>
#include <algorithm>

NgxHttpsoAsyncWork::NgxHttpsoAsyncWork()
{
    work_tasks_stop_ = true;
}

int
NgxHttpsoAsyncWork::AsyncWorkStart(int thread_count)
{
    work_tasks_stop_ = false;
    for(int i=0; i<thread_count; ++i) {
        ThreadPtr t(new std::thread(
            std::bind(&NgxHttpsoAsyncWork::AsyncWorkTaskFunc, this)));
        work_tasks_.push_back(t);
    }

    return 0;
}

int 
NgxHttpsoAsyncWork::AsyncWorkStop(void)
{
    work_tasks_stop_ = true;
    work_entrys_cond_.notify_all();
    std::for_each(work_tasks_.begin(), work_tasks_.end(), 
        std::bind(&std::thread::join, std::placeholders::_1));

    return 0;
}

int
NgxHttpsoAsyncWork::AsyncWorkAddWork(AsyncWorkEntryPtr &e)
{
    std::unique_lock<std::mutex> lock(work_entrys_lock_);

    work_entrys_.push_back(e);
    work_entrys_cond_.notify_one();

    return 0;
}

AsyncWorkEntryPtr
NgxHttpsoAsyncWork::AsyncWorkPopComplete()
{
    AsyncWorkEntryPtr e;

    {
        std::unique_lock<std::mutex> lock(complete_entrys_lock_);
        if (! complete_entrys_.empty()) {
            e = complete_entrys_.front();
            complete_entrys_.pop_front();
        }
    }

    return e;
}

void
NgxHttpsoAsyncWork::AsyncWorkTaskFunc(void)
{
    std::unique_lock<std::mutex> lock(work_entrys_lock_);

    while(! work_tasks_stop_) {
        while (! work_entrys_.empty()) {
            AsyncWorkEntryPtr e = work_entrys_.front();
            work_entrys_.pop_front();
            lock.unlock();
            (*(e->work_call_in_async))();
            {
                std::unique_lock<std::mutex> guard(complete_entrys_lock_);
                complete_entrys_.push_back(e);
            }
            lock.lock();

        }
        work_entrys_cond_.wait(lock);
    }

    return;
}

