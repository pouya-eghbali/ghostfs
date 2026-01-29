#pragma once

#include <condition_variable>
#include <functional>
#include <future>
#include <mutex>
#include <queue>
#include <thread>
#include <vector>

namespace ghostfs {

  // Simple thread pool for parallel crypto operations
  // Pre-creates threads to avoid thread creation overhead per operation
  class ThreadPool {
    std::vector<std::thread> workers;
    std::queue<std::function<void()>> tasks;
    std::mutex queue_mutex;
    std::condition_variable condition;
    bool stop = false;

  public:
    explicit ThreadPool(size_t threads = 0) {
      if (threads == 0) {
        threads = std::thread::hardware_concurrency();
        if (threads == 0) threads = 4;  // Fallback
      }

      for (size_t i = 0; i < threads; ++i) {
        workers.emplace_back([this] {
          while (true) {
            std::function<void()> task;
            {
              std::unique_lock<std::mutex> lock(queue_mutex);
              condition.wait(lock, [this] { return stop || !tasks.empty(); });
              if (stop && tasks.empty()) return;
              task = std::move(tasks.front());
              tasks.pop();
            }
            task();
          }
        });
      }
    }

    ~ThreadPool() {
      {
        std::unique_lock<std::mutex> lock(queue_mutex);
        stop = true;
      }
      condition.notify_all();
      for (std::thread& worker : workers) {
        worker.join();
      }
    }

    // Enqueue a task and return a future for the result
    template <class F> std::future<void> enqueue(F&& f) {
      auto task = std::make_shared<std::packaged_task<void()>>(std::forward<F>(f));
      std::future<void> result = task->get_future();
      {
        std::unique_lock<std::mutex> lock(queue_mutex);
        if (stop) {
          throw std::runtime_error("enqueue on stopped ThreadPool");
        }
        tasks.emplace([task]() { (*task)(); });
      }
      condition.notify_one();
      return result;
    }

    // Non-copyable, non-movable
    ThreadPool(const ThreadPool&) = delete;
    ThreadPool& operator=(const ThreadPool&) = delete;
    ThreadPool(ThreadPool&&) = delete;
    ThreadPool& operator=(ThreadPool&&) = delete;
  };

}  // namespace ghostfs
