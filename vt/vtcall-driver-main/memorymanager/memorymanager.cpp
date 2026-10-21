#include "memorymanager.h"
#include <cstring>

namespace memory {
#pragma code_seg(".vm")
    MemoryManager& MemoryManager::getInstance() {
        static MemoryManager instance;
        return instance;
    }

    bool MemoryManager::initialize(void* memory_pool, size_t pool_size) {
        if (!memory_pool || pool_size < sizeof(MemoryBlock)) {
            return false;
        }

        memory_pool_ = memory_pool;
        total_size_ = pool_size;
        used_size_ = 0;

        // 初始化第一个内存块
        first_block_ = static_cast<MemoryBlock*>(memory_pool_);
        first_block_->size = pool_size - sizeof(MemoryBlock);
        first_block_->is_used = false;
        first_block_->next = nullptr;
        first_block_->prev = nullptr;
        first_block_->magic = MAGIC_NUMBER;
        last_block_ = first_block_;

        return true;
    }

    bool MemoryManager::shouldDefragment() const {
        size_t free_blocks = 0;
        size_t total_free_size = 0;
        MemoryBlock* current = first_block_;

        while (current) {
            if (!current->is_used) {
                free_blocks++;
                total_free_size += current->size;
            }
            current = current->next;
        }

        // 如果空闲块数量过多或碎片化严重，则进行整理
        return free_blocks > 10 || (total_free_size > 1024 && free_blocks > 3);
    }

    void MemoryManager::mergeAdjacentBlocks(MemoryBlock* block) {
        if (!block || !isValidBlock(block)) return;

        // 向前合并
        while (block->prev && !block->prev->is_used) {
            MemoryBlock* prev = block->prev;
            prev->size += block->size + sizeof(MemoryBlock);
            prev->next = block->next;
            if (block->next) {
                block->next->prev = prev;
            }
            if (block == last_block_) {
                last_block_ = prev;
            }
            block = prev;
        }

        // 向后合并
        while (block->next && !block->next->is_used) {
            MemoryBlock* next = block->next;
            block->size += next->size + sizeof(MemoryBlock);
            block->next = next->next;
            if (next->next) {
                next->next->prev = block;
            }
            if (next == last_block_) {
                last_block_ = block;
            }
        }
    }

    void MemoryManager::compactMemory() {
        MemoryBlock* current = first_block_;
        while (current) {
            if (!current->is_used) {
                // 移动后续的已使用块
                MemoryBlock* next = current->next;
                while (next && next->is_used) {
                    // 计算移动距离
                    size_t move_size = current->size + sizeof(MemoryBlock);
                    // 移动内存
                    memmove(current, next, next->size + sizeof(MemoryBlock));
                    // 更新指针
                    current->next = next->next;
                    if (next->next) {
                        next->next->prev = current;
                    }
                    if (next == last_block_) {
                        last_block_ = current;
                    }
                    next = current->next;
                }
            }
            current = current->next;
        }
    }

    void MemoryManager::defragment() {
        if (!shouldDefragment()) {
            return;
        }

        // 合并相邻的空闲块
        MemoryBlock* current = first_block_;
        while (current) {
            if (!current->is_used) {
                mergeAdjacentBlocks(current);
            }
            current = current->next;
        }

        // 压缩内存
        compactMemory();
    }

    void* MemoryManager::allocate(size_t size) {
        if (size == 0 || size > total_size_) {
            return nullptr;
        }

        // 对齐到8字节边界
        size = (size + 7) & ~7;

        // 如果碎片化严重，先进行整理
        if (shouldDefragment()) {
            defragment();
        }

        MemoryBlock* current = first_block_;
        while (current) {
            if (!isValidBlock(current)) {
                return nullptr;
            }

            if (!current->is_used && current->size >= size + sizeof(MemoryBlock)) {
                // 如果剩余空间足够大，分割内存块
                if (current->size >= size + sizeof(MemoryBlock) + MIN_BLOCK_SIZE) {
                    MemoryBlock* new_block = reinterpret_cast<MemoryBlock*>(
                        reinterpret_cast<char*>(current) + sizeof(MemoryBlock) + size);
                    new_block->size = current->size - size - sizeof(MemoryBlock);
                    new_block->is_used = false;
                    new_block->next = current->next;
                    new_block->prev = current;
                    new_block->magic = MAGIC_NUMBER;

                    if (current->next) {
                        current->next->prev = new_block;
                    }
                    if (current == last_block_) {
                        last_block_ = new_block;
                    }

                    current->next = new_block;
                    current->size = size;
                }

                current->is_used = true;
                used_size_ += current->size + sizeof(MemoryBlock);
                return reinterpret_cast<char*>(current) + sizeof(MemoryBlock);
            }
            current = current->next;
        }

        return nullptr;
    }

    void MemoryManager::free(void* ptr) {
        if (!ptr || !isInMemoryPool(ptr)) {
            return;
        }

        MemoryBlock* block = reinterpret_cast<MemoryBlock*>(
            reinterpret_cast<char*>(ptr) - sizeof(MemoryBlock));

        if (!isValidBlock(block) || !block->is_used) {
            return;
        }

        block->is_used = false;
        used_size_ -= block->size + sizeof(MemoryBlock);

        // 合并相邻的空闲块
        mergeAdjacentBlocks(block);
    }

    size_t MemoryManager::getTotalSize() const {
        return total_size_;
    }

    size_t MemoryManager::getUsedSize() const {
        return used_size_;
    }

    size_t MemoryManager::getFreeSize() const {
        return total_size_ - used_size_;
    }

    bool MemoryManager::isValidBlock(const MemoryBlock* block) const {
        return block && block->magic == MAGIC_NUMBER;
    }

    bool MemoryManager::isInMemoryPool(const void* ptr) const {
        return ptr >= memory_pool_ &&
            ptr < reinterpret_cast<const char*>(memory_pool_) + total_size_;
    }

} // namespace memory 