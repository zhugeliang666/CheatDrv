#pragma once

#include <ia32.hpp>

#include "spin-lock.h"

// 通用日志级别（通常仅在调试 ERROR 严重故障时启用）
#define HV_LOG_INFO(fmt, ...)    //hv::logger_write(fmt, __VA_ARGS__)
#define HV_LOG_ERROR(fmt, ...)   //hv::logger_write(fmt, __VA_ARGS__)
#define HV_LOG_VERBOSE(fmt, ...) //hv::logger_write(fmt, __VA_ARGS__)

// 特定事件流程日志
#define HV_LOG_MMR_ACCESS(fmt, ...)    // hv::logger_write(fmt, __VA_ARGS__)
#define HV_LOG_INJECT_INT(fmt, ...)     //hv::logger_write(fmt, __VA_ARGS__)
#define HV_LOG_HOST_EXCEPTION(fmt, ...) //hv::logger_write(fmt, __VA_ARGS__)

namespace hv {

struct logger_msg {
  static constexpr uint32_t max_msg_length = 128;

  // ID of the 当前 message
  uint64_t id;

  // timestamp counter of the 当前 message
  uint64_t tsc;

  // process ID of the VCPU that sent the message
  uint32_t aux;

  // null-terminated ascii string
  char data[max_msg_length];
};

struct logger {
  static constexpr uint32_t max_msg_count = 512;

  // signature to find logs in memory easier
  // "hvloggerhvlogger"
  char signature[16];

  spin_lock lock;

  uint32_t msg_start;
  uint32_t msg_count;

  // the total messages sent
  uint64_t total_msg_count;

  // an 数组 of messages
  logger_msg msgs[max_msg_count];
};

// 初始化 the logger
void logger_init();

// 刷新 log messages to the provided 缓冲区
void logger_flush(uint32_t& count, logger_msg* buffer);

// 写入 a printf-style string to the logger using
// a limited subset of printf specifiers:
//   %s, %i, %d, %u, %x, %X, %p
void logger_write(char const* format, ...);

} // namespace hv

