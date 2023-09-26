#include "../lib/full-write.h"
#include <vector>
#include <thread>
#include <algorithm>
#include <sys/types.h>
#include <stdint.h>
#include <iostream>
#include <unistd.h>
#include <string>
#include <map>
#include <mutex>
#include <functional>
#include <string.h>
#include <condition_variable>
#include <atomic>
#include <cstdint>
#include <fcntl.h>
#include <assert.h>
#include <stdarg.h>
#include <sys/sendfile.h>

#define OX_PATH 010000000     // octal! = 0x200000
#define OPG_PATH 0x10000000   // = much higher than real flags (we hope) = 02000000000 octal
#ifdef O_PATH
    static_assert((O_PATH)==OX_PATH, "Expecting that O_PATH is a global constant!");
#endif


int SetExitCode(int set_failure = 0);

static void LogMessage(const char * format, ... ) {
    #define LOG_BUFFER_SIZE 4096
    static char * log_level = getenv("CUNO_CLOUD_DEBUG");
    if(log_level != nullptr && strcmp(log_level, "trace") == 0) {
        char l_buffer[LOG_BUFFER_SIZE];
        char l_buffer2[LOG_BUFFER_SIZE];
        snprintf(l_buffer2, LOG_BUFFER_SIZE, "[CUNO-CP] trace: " "%s\n", format);
        l_buffer2[LOG_BUFFER_SIZE-1] = 0;
        va_list args;
        va_start (args, format);
        vsnprintf(l_buffer, LOG_BUFFER_SIZE, l_buffer2, args);
        va_end (args);
        std::cerr << l_buffer;
    }
}

std::atomic<int> counterRecordOp {0};
struct RecordOp
{
  void* ptr;
  enum OP
  {

    OP_ADD =1,
    OP_PREDELCHK ,
    OP_PREDEL ,
    OP_DEL ,
    OP_CHK ,
    OP_ALLOW,
    OP_MAX,
    MAX_RECORDS = 2000000
  } op;
  pid_t tid;

} recordOps[RecordOp::MAX_RECORDS];

std::atomic<int> recordOpsCount[RecordOp::OP_MAX];

#include <sys/syscall.h>
#define gettid() (pid_t)syscall(SYS_gettid)

#ifdef CALL_LOG_ALL_POINTERS
void RecordTheOp(const RecordOp& op)
{
  static thread_local pid_t myPid {gettid()};
  int count = ++counterRecordOp;
  assert(count != RecordOp::MAX_RECORDS);
  recordOps[count] = op;
  recordOpsCount[op.op]++;
  recordOps[count].tid = myPid;

}

void RecordTheOp(RecordOp::OP op, FileHandlerBase* ptr)
{
  RecordTheOp({ptr, op, 0});
}

template<int level=3, class Index = int, class Payload = unsigned char>
struct MyTree
{
    typedef MyTree<level-1> Child;
    typedef Payload PayloadType;
    typedef Index IndexType;
    struct ChildPtr
    {
        std::atomic<Child*> val {nullptr};
    };
    // 256 = 2^8
    enum : size_t  {basecount= Child::basecount, mycount=256, totalcount = mycount*Child::totalcount};
    ChildPtr members[mycount];
    std::atomic<Payload>* get(Index fd)
    {
        assert(fd < totalcount);
        if (auto mem = members[fd/Child::totalcount].val.load())
            return mem->get(fd%Child::totalcount);
        else
            return nullptr;
    }
    std::atomic<Payload>& getMake(Index fd)
    {
        assert(fd < totalcount);
        auto& val = members[fd/Child::totalcount].val;
        if (auto mem = val.load())
            return mem->getMake(fd%Child::totalcount);
        else
        {
            auto mem2 = new Child;
            if (!val.compare_exchange_strong(mem, mem2))
                delete mem2;    // already populated!
            return val.load()->getMake(fd%Child::totalcount);
        }
    }
    // Get an entry and potentially make the next page as well
    std::atomic<Payload>& getPre(Index fd)
    {
        assert(fd < totalcount);
        if ((fd)%Child::totalcount == (fd+basecount)%Child::totalcount)
        {
            auto& val = members[fd/Child::totalcount].val;
            if (auto mem = val.load())
                return mem->getPre(fd%Child::totalcount);
            else
            {
                auto mem2 = new Child;
                if (!val.compare_exchange_strong(mem, mem2))
                    delete mem2;    // already populated!
                return val.load()->getPre(fd%Child::totalcount);
            }
        }
        else
        {
            if (fd < totalcount-basecount)
            {
                auto& val2 = members[fd/Child::totalcount+1].val;
                if (auto mem2 = val2.load())
                {}  // preemptive page already requested
                else
                {
                    auto mem3 = new Child;
                    if (!val2.compare_exchange_strong(mem2, mem3))
                        delete mem3;    // already populated!
                    val2.load()->getMake(fd%Child::totalcount);
                }
            }
            auto& val = members[fd/Child::totalcount].val;
            if (auto mem = val.load())
                return mem->getMake(fd%Child::totalcount);
            else
            {
                auto mem2 = new Child;
                if (!val.compare_exchange_strong(mem, mem2))
                    delete mem2;    // already populated!
                return val.load()->getMake(fd%Child::totalcount);
            }

        }
    }
};

template <class Index, class Payload> struct MyTree<0, Index, Payload>
{
    struct Child
    {
        std::atomic<Payload> val {0};
    };
    // 256 bytes = 2K bits = 2^11
    // 128 bytes = 1K bits = 2^10
    enum : size_t {basecount=65536/8, mycount= basecount, totalcount = mycount};
    Child members[mycount];
    std::atomic<Payload>* get(Index fd)
    {
        return &members[fd].val;
    }
    std::atomic<Payload>& getMake(Index fd)
    {
        return *get(fd);
    }
};

MyTree<6, size_t> myBitTree;

std::pair<std::atomic<unsigned char>*, int> BitLoc(size_t index)
{
    auto b = 1 << (index % 8);
    auto B = index / 8;
    return {&myBitTree.getMake(B),b};
}



size_t addValid(void *p)
{
  RecordTheOp({p, RecordOp::OP_ADD, 0});
  #ifdef LOG_ALL_POINTERS
    auto bitLoc = BitLoc(size_t(p));
    auto v = bitLoc.first->load();
    for (;;)
    {
        assert (!(v& bitLoc.second) && " Address is already hashed!");
        auto v2 = v | bitLoc.second;
        if (bitLoc.first->compare_exchange_strong(v,v2))
          return (size_t)p;
    }
  #else
            return (size_t)p;
  #endif
}

bool clrValid(void *p)
{
  RecordTheOp({p, RecordOp::OP_DEL, 0});
  #ifdef LOG_ALL_POINTERS
    auto bitLoc = BitLoc(size_t(p));
    auto v = bitLoc.first->load();
    for (;;)
    {
        assert ((v& bitLoc.second) && " Address is already hashed!");
        auto v2 = v & ~ bitLoc.second;
        if (bitLoc.first->compare_exchange_strong(v,v2))
            return true;
    }
  #else
            return true;
  #endif
}

bool isValid(void *p)
{
  RecordTheOp({p, RecordOp::OP_CHK, 0});
  #ifdef LOG_ALL_POINTERS
    auto bitLoc = BitLoc(size_t(p));
    auto v = bitLoc.first->load() & bitLoc.second;
    return !!v;
  #else
            return true;
  #endif
}
#endif

class FileHandler: public FileHandlerBase {
    int src_fd_;
    int dst_fd_;
    uintmax_t max_read_;
    std::shared_ptr<std::thread> writer_thread_;
    std::function<void(int, int, int)> free_callback_;
    bool terminated_;
    std::mutex write_mutex_;
    bool is_complete_;
    std::condition_variable cond_var_;
    int index_;
    bool active_;
    bool finished_;
public:
    volatile int closeWhenZero_;

public:
    FileHandler(int index, std::function<void(int, int, int)> free_callback) {
        index_ = index;
        src_fd_ = -1;
        dst_fd_ = -1;
        free_callback_ = free_callback;
        max_read_ = 1;
        terminated_ = false;
        active_ = false;
        finished_ = false;
        writer_thread_ = std::make_shared<std::thread>(&FileHandler::ReadWriteThread, this);
        closeWhenZero_ = -1;
    }

    ~FileHandler() {
    }

    void Finish() {
        {
            std::unique_lock<std::mutex> guard(write_mutex_);
            //LogMessage("Terminate File Handler");
            if(active_ == false) {
                terminated_ = true;
            }
            finished_ = true;
        }
        cond_var_.notify_one();
        writer_thread_->join();
        //CloseIfOpen();
    }

    // void CloseIfOpen() {
    //     if(src_fd_ != -1 && dst_fd_ != -1) {
    //         while (closeWhenZero_)
    //         {   // Current implementation is a busy wait.
    //             // We expect in most cases that the main thread will have finished setting attributes long before the file has finished copying.
    //             std::this_thread::yield();
    //         }
    //         close(src_fd_);
    //         close(dst_fd_);
    //         src_fd_ = -1;
    //         dst_fd_ = -1;
    //     }
    // }

    void Start(int src_fd, int dst_fd, uintmax_t max_read) {
        std::unique_lock<std::mutex> guard(write_mutex_);
        //CloseIfOpen();
        src_fd_ = src_fd;
        dst_fd_ = dst_fd;
        max_read_ = max_read;
#ifdef CALL_LOG_ALL_POINTERS
        closeWhenZero_ = addValid(this);
#else
        closeWhenZero_ = index_ + (dst_fd<<16); // we can store anything we like here, so long as it is non-zero!
#endif
        active_ = true;
        //LogMessage(std::string("Notify: ") + std::to_string(src_fd_) + "->" + std::to_string(dst_fd_));
        cond_var_.notify_one();
    }

    void Terminate() {
        std::unique_lock<std::mutex> guard(write_mutex_);
        terminated_ = true;
        cond_var_.notify_one();
    }

    void ReadWriteThread() {
        bool terminated = false;
        bool finished = false;
        bool active = false;
        while(!terminated && !finished) {
            int src_fd = -1;
            int dest_fd = -1;
            {
                std::unique_lock<std::mutex> guard(write_mutex_);
                cond_var_.wait(guard, [this] { return terminated_ || active_ || finished_; });
                //LogMessage("Check terminated");
                src_fd = src_fd_;
                dest_fd = dst_fd_;
                terminated = terminated_;
                finished = finished_;
                active = active_;
            }
            if(terminated) { break; }
            if(finished && !active) { break; }
            if(src_fd == -1 || dest_fd == -1) {
                LogMessage("Writing to closed");
                break;
            }
            int response = 0;
            bool terminated = false;
            uintmax_t max_read = max_read_;
            LogMessage("Start RW: %d -> %d index: %d", src_fd, dest_fd, index_);

            while (max_read > 0) {
                ssize_t written_size = sendfile(dest_fd, src_fd, NULL, max_read);
                if (written_size < 0) {
                    if (errno != EINVAL && errno != ENOSYS) { SetExitCode(-1); }
                    break;
                }
                else if (written_size == 0) { break; }
                LogMessage("Sent %d bytes: %d -> %d index: %d ", written_size, src_fd, dest_fd, index_);
                max_read -= written_size;
            }
            LogMessage("Finished RW: %d -> %d index: %d", src_fd, dest_fd, index_);
            {
                std::unique_lock<std::mutex> guard(write_mutex_);
                active_= false;
                if(!terminated) {
                  #ifdef CALL_LOG_ALL_POINTERS
                    RecordTheOp(RecordOp::OP_PREDELCHK, this);
                  #endif
                    while (closeWhenZero_)
                    {   // Current implementation is a busy wait.
                        // We expect in most cases that the main thread will have finished setting attributes long before the file has finished copying.
                        std::this_thread::yield();
                    }
                  #ifdef CALL_LOG_ALL_POINTERS
                    RecordTheOp(RecordOp::OP_PREDEL, this);
                    clrValid(this);
                  #endif
                    free_callback_(index_, src_fd_, dst_fd_);
                }
            }
        }
    }
};

class FileHandlerPool {
    private:
        std::mutex file_handler_mutex;
        std::map<int, std::shared_ptr<FileHandler>> file_queue_;
        std::vector<int> free_indexes;
        std::condition_variable cond_var_;
        int max_file_queue_ = 5;
        std::function<void(int, int, int)> free_callback_;
        bool terminated_ {false};

    public:
        FileHandlerPool(int max_queue_size) {
            max_file_queue_ = max_queue_size;
            free_callback_ = std::bind(&FileHandlerPool::FreeFileHandler, this, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3);
            terminated_ = false;

            for(int i = 0; i < max_file_queue_; i++) {
                //LogMessage(std::string("Insert File handler1: ") + std::to_string(i));
                file_queue_.insert({i, std::make_shared<FileHandler>(i, free_callback_)});
                free_indexes.push_back(i);
            }
        }

        ~FileHandlerPool() {
            file_queue_.clear();
        }

        void Finish() {
            std::map<int, std::shared_ptr<FileHandler>>::iterator it;
            for (it = file_queue_.begin(); it != file_queue_.end(); it++)
            {
                it->second->Finish();
            }
            file_queue_.clear();
        }

        std::shared_ptr<FileHandler> QueueFile(int src_fd, int fd, uintmax_t max_read) {
            std::unique_lock<std::mutex> guard(file_handler_mutex);
            cond_var_.wait(guard, [this] { return free_indexes.size() > 0; });
            if(!terminated_) {
                LogMessage("Starting File %d %d free slots: %lu", src_fd, fd, free_indexes.size());
                file_queue_[free_indexes.front()]->Start(src_fd, fd, max_read);
                auto rv = file_queue_[free_indexes.front()];
                free_indexes.erase(free_indexes.begin());
                return rv;
            }
            return nullptr;
        }

        void TerminateHandlers() {
            {
                std::unique_lock<std::mutex> guard(file_handler_mutex);
                if(terminated_ = true) {
                    return;
                }
                terminated_ = true;
            }
            //Terminate and clear up active fds
            for(auto const& file : file_queue_) {
                file.second->Terminate();
            }
            file_queue_.clear();
        }

        void FreeFileHandler(int index, int src_fd, int dest_fd) {
            std::unique_lock<std::mutex> guard(file_handler_mutex);
            //LogMessage(std::string("Free File Handle: ") + std::to_string(src_fd));
            if(src_fd != -1) {
                free_indexes.push_back(index);
                //LogMessage(std::string("Closing File Handles: ") + std::to_string(src_fd) + " " + std::to_string(dest_fd));
                close(src_fd);
                close(dest_fd);
                src_fd = -1;
                dest_fd = -1;
                //LogMessage(std::string("Closed File Handles: ") + std::to_string(src_fd) + " " + std::to_string(dest_fd));
                cond_var_.notify_one();
            }
        }
};

class PoolManager {
    protected:
        std::shared_ptr<FileHandlerPool> handler_pool_;
    public:
        PoolManager() {
            handler_pool_ = std::make_shared<FileHandlerPool>(10);
        }

        ~PoolManager() {
            handler_pool_->Finish();
        }

        std::shared_ptr<FileHandlerPool> GetHandler() {
            return handler_pool_;
        }

        std::shared_ptr<FileHandlerPool> GetHandlerAndReplace() {
            auto old_pool = handler_pool_;
            handler_pool_ = std::make_shared<FileHandlerPool>(10);
            return old_pool;
        }
};

std::shared_ptr<FileHandlerPool> GetFileHandlerPool(bool replace_pool = false) {
    static std::shared_ptr<PoolManager> handler_pool_wrapper = std::make_shared<PoolManager>();
    if (replace_pool) {
        return handler_pool_wrapper->GetHandlerAndReplace();
    }
    return handler_pool_wrapper->GetHandler();
}

int SetExitCode(int exit_code) {
    static int exitcode {0};
    if(exit_code == 0 && exitcode != 0) {
        //LogMessage(std::string("Exiting"));
    }
    else if(exit_code != 0) {
        LogMessage("Setting Non-Zero Exit Code: %d errno: %d", exit_code, errno);
        GetFileHandlerPool()->TerminateHandlers();
        exitcode = exit_code;
    }
    return exitcode;
}

extern "C" void trigger_join(int i) {
    //LogMessage(std::string("Trigger Join"));
    auto handler_pool = GetFileHandlerPool(true);
    handler_pool->Finish();
}

extern "C" FileHandlerBase* queue_file(int src_fd, int fd, uintmax_t max_read, const char* src_name, const char* dst_name) {
    auto handler_pool = GetFileHandlerPool();
    int exit_code = SetExitCode();
    if(SetExitCode() == 0) {
        LogMessage("Queue file src:%s (fd=%d) dst:%s (fd=%d) max-read:%lu", src_name, src_fd, dst_name, fd, max_read);
        auto rv = handler_pool->QueueFile(src_fd, fd, max_read);
        return rv.get();
    } else if(exit_code == -1) {
        LogMessage("ERROR encountered, terminating. error:%d errno:%d", exit_code, errno);
        std::cerr << "cp: Failed to read from file!" << "\n";
        exit(-1);
    } else if(exit_code == -2) {
        LogMessage("ERROR encountered, terminating. error:%d errno:%d", exit_code, errno);
        std::cerr << "cp: Failed to write to file!" << "\n";
        exit(-1);
    }
}




/**
  Detect that this is a cloud special file
*/
extern "C" int file_is_intercepted(int src_fd)
{
  /* NOTE: this may be problematic if we ever spoof these F_GETFL results. We may need to reserve some high bits for our own purposes. */
  int source_fctl = fcntl(src_fd,F_GETFL);
  return (source_fctl != -1) && (source_fctl & OX_PATH);
}


extern "C" int check_job_is_valid(FileHandlerBase*  opaque)
{
  if (!opaque)
    return true;

  FileHandler* base = static_cast<FileHandler*>(opaque);
#ifdef CALL_LOG_ALL_POINTERS
  return isValid(base);
#else
  return true;
#endif

}
extern "C" int allow_job_close(FileHandlerBase*  opaque)
{
  if (!opaque)
    return false; // Not in threaded job mode!

  FileHandler* base = static_cast<FileHandler*>(opaque);
#ifdef CALL_LOG_ALL_POINTERS
  assert (isValid(base));
  RecordTheOp(RecordOp::OP_ALLOW, opaque);
#endif
  base->closeWhenZero_ = 0;
  return true;
}
