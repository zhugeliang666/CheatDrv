#pragma once
#include <cstdint>

namespace memory {
    // 内存块头部结构
    struct MemoryBlock {
        size_t size;           // 块大小
        bool is_used;          // 使用状态
        MemoryBlock* next;     // 下一个块
        uint32_t magic;        // 魔数，用于验证内存块有效性
        MemoryBlock* prev;     // 前一个块，用于双向链表
    };

    class MemoryManager {
    public:
        static MemoryManager& getInstance();

        // 初始化内存池
        bool initialize(void* memory_pool, size_t pool_size);

        // 分配内存
        void* allocate(size_t size);

        // 释放内存
        void free(void* ptr);

        // 获取内存使用情况
        size_t getTotalSize() const;
        size_t getUsedSize() const;
        size_t getFreeSize() const;

        // 验证内存块是否有效
        bool isValidBlock(const MemoryBlock* block) const;

        // 验证指针是否在内存池范围内
        bool isInMemoryPool(const void* ptr) const;

        // 内存碎片整理
        void defragment();

    private:
        MemoryManager() = default;
        ~MemoryManager() = default;

        // 禁止拷贝和赋值
        MemoryManager(const MemoryManager&) = delete;
        MemoryManager& operator=(const MemoryManager&) = delete;

        static constexpr uint32_t MAGIC_NUMBER = 0xDEADBEEF;  // 魔数常量
        static constexpr size_t MIN_BLOCK_SIZE = 16;  // 最小块大小

        void* memory_pool_;     // 内存池起始地址
        size_t total_size_;     // 总大小
        size_t used_size_;      // 已使用大小
        MemoryBlock* first_block_; // 第一个内存块
        MemoryBlock* last_block_;  // 最后一个内存块

        // 内部方法
        void mergeAdjacentBlocks(MemoryBlock* block);
        void compactMemory();
        bool shouldDefragment() const;
    };
}