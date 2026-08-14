/*
LICENSE

Copyright  2020      Deutsche Bahn Station&Service AG

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

*/
#include "globals.h"
#include "libpax.h"

typedef uint32_t bitmap_t;
enum { BITS_PER_WORD = sizeof(bitmap_t) * CHAR_BIT };
#define WORD_OFFSET(b) ((b) / BITS_PER_WORD)
#define BIT_OFFSET(b) ((b) % BITS_PER_WORD)

// The bitmap requires 2**16 = 65536 entries,
// while using 32 bit integers, we need 65536 / 32 = 2048 integers
#define WORDS_PER_MAP (65536 / BITS_PER_WORD)

// Separate maps per sniff type: a shared map would let a WiFi id and an
// unrelated BLE id collide with each other, doubling the effective
// collision rate whenever both radios are active at once.
// Each map is only allocated when its sniffer is actually built in, so a
// WiFi-only or BLE-only build doesn't waste 8 KiB of DRAM on the other map.
#if defined(LIBPAX_WIFI)
DRAM_ATTR bitmap_t seen_ids_map_wifi[WORDS_PER_MAP];
#endif
#if defined(LIBPAX_BLE)
DRAM_ATTR bitmap_t seen_ids_map_ble[WORDS_PER_MAP];
#endif

volatile uint16_t macs_wifi = 0;
volatile uint16_t macs_ble = 0;

volatile uint8_t channel = 0;  // channel rotation counter

/** remember given id in the bitmap for the given sniff type
 * returns 1 if id is new, 0 if already seen this is since last reset
 * Hot-path critical function - highly optimized
 * Lock-free: a single atomic OR on the target word is all that's needed
 * to safely race against a concurrent weigh_map() scan running on the
 * other core, since that side only ever touches whole words atomically
 * too - no spinlock has to be held across the packet path any more.
 */
static inline IRAM_ATTR int add_to_bucket(uint16_t id, snifftype_t sniff_type) {
  bitmap_t *map;
#if defined(LIBPAX_WIFI) && defined(LIBPAX_BLE)
  map = (sniff_type == MAC_SNIFF_BLE) ? seen_ids_map_ble : seen_ids_map_wifi;
#elif defined(LIBPAX_BLE)
  map = seen_ids_map_ble;
#elif defined(LIBPAX_WIFI)
  map = seen_ids_map_wifi;
#else
  return 0;  // neither sniffer built in, nothing to track
#endif
  uint16_t word_idx = WORD_OFFSET(id);
  bitmap_t bit_mask = ((bitmap_t)1 << BIT_OFFSET(id));

  bitmap_t previous =
      __atomic_fetch_or(&map[word_idx], bit_mask, __ATOMIC_RELAXED);

  return (previous & bit_mask) ? 0 : 1;
}

/** "Weigh" a bitmap word by word: for each 32 bit word, atomically grab it
 * (and, unless peek is set, clear it back to zero in the same atomic step)
 * and popcount the previous value into the running total. Meant to run on
 * a dedicated task/core, concurrently with add_to_bucket() OR-ing new bits
 * into the very same map from the collector core/task: since every word is
 * touched with a single atomic op, a bit set during the scan can never be
 * lost or counted twice. Iterating word-sized chunks instead of bit-by-bit
 * keeps the loop count fixed at WORDS_PER_MAP regardless of how many MACs
 * were actually seen.
 */
static inline uint16_t weigh_map(bitmap_t *map, size_t words, bool peek) {
  uint32_t total = 0;
  for (size_t i = 0; i < words; i++) {
    bitmap_t word = peek ? __atomic_load_n(&map[i], __ATOMIC_ACQUIRE)
                         : __atomic_exchange_n(&map[i], 0, __ATOMIC_ACQ_REL);
    total += __builtin_popcountl(word);
  }
  return (uint16_t)total;
}

/** Weigh both bitmaps and publish the result to macs_wifi / macs_ble.
 * When peek is false (default, periodic counter_mode) each map is cleared
 * for the next counting interval as it is weighed. When peek is true
 * (cumulative counter_mode) the bitmaps are left untouched so counting
 * keeps accumulating across report intervals.
 */
void weigh_buckets(bool peek) {
#if defined(LIBPAX_WIFI)
  macs_wifi = weigh_map(seen_ids_map_wifi, WORDS_PER_MAP, peek);
#endif
#if defined(LIBPAX_BLE)
  macs_ble = weigh_map(seen_ids_map_ble, WORDS_PER_MAP, peek);
#endif
}

void reset_bucket() {
  macs_wifi = 0;
  macs_ble = 0;
#if defined(LIBPAX_WIFI)
  weigh_map(seen_ids_map_wifi, WORDS_PER_MAP, false);
#endif
#if defined(LIBPAX_BLE)
  weigh_map(seen_ids_map_ble, WORDS_PER_MAP, false);
#endif
}

int libpax_wifi_counter_count() { return macs_wifi; }

int libpax_ble_counter_count() { return macs_ble; }

/** Hot-path function called from ISR context for every WiFi/BLE packet.
 * Optimized for minimum cycles per call: only records the MAC in the
 * bitmap, counting itself now happens asynchronously in weigh_buckets(),
 * which runs on the report task/core instead of on every packet.
 */
IRAM_ATTR int mac_add(uint8_t *paddr, snifftype_t sniff_type) {
  // Check locally administered bit first (cheapest check)
  if (!(paddr[0] & 0b10)) return 0;

  // Use last 2 bytes of MAC address as ID (little-endian)
  uint16_t id = (paddr[5] << 8) | paddr[4];

  return add_to_bucket(id, sniff_type);
}
