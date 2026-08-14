#ifndef _GLOBALS_H
#define _GLOBALS_H

#ifdef LIBPAX_ESPIDF // ESPIDF
#include "esp_cpu.h"  // PRO_CPU_NUM / APP_CPU_NUM
#include "esp_log.h"
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>
#include <freertos/timers.h>
#else // Arduino IDE
#include <Arduino.h>
#endif

// volatile: written from the weigher task (running on its own pinned
// core), read from application code calling libpax_(wifi|ble)_counter_count()
// on either core, so the compiler must not cache a stale value across calls
extern volatile uint16_t macs_wifi;
extern volatile uint16_t macs_ble;
extern volatile uint8_t channel;  // wifi channel rotation counter, written by the timer task
extern TimerHandle_t WifiChanTimer;

#endif
