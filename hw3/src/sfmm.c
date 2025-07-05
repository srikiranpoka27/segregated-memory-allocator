/**
 * Do not submit your assignment with a main function in this file.
 * If you submit with a main function in this file, you will get a zero.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include "debug.h"
#include "sfmm.h"

#define MIN_BLOCK_SIZE 32
#define ALIGNMENT 16

// Global variables for calculating fragmentation and total utilisation
static size_t total_payload = 0;
static size_t total_allocated = 0;
static size_t peak_payload = 0;
static int heap_initialized = 0; // Global variable to check if heap is initialized

static inline size_t align(size_t size) {
    return ALIGNMENT*((size + (ALIGNMENT - 1)) / ALIGNMENT);
}

// Functins to compute header value and find header parameters for a given header
static size_t pack_header(size_t payload_size, size_t block_size, int in_quicklist, int allocated) {
    size_t flags = 0;
    if (allocated) flags |= THIS_BLOCK_ALLOCATED;
    if (in_quicklist) flags |= IN_QUICK_LIST;

    size_t header = ((payload_size & 0xFFFFFFFFUL) << 32) | (block_size & ~0xFUL) | flags;

    return header ^ MAGIC;
}

static size_t get_block_size(sf_header hdr) {
    size_t unobfuscated_header = hdr ^ MAGIC;
    size_t lower_bits = unobfuscated_header & 0xFFFFFFFFULL;
    return lower_bits & ~0xFUL;
}

static size_t get_payload_size(sf_header hdr) {
    size_t unobfuscated_header = hdr ^ MAGIC;
    return unobfuscated_header >> 32;
}

static int is_allocated(sf_header hdr) {
    size_t unobfuscated_header = hdr ^ MAGIC;
    return (unobfuscated_header & THIS_BLOCK_ALLOCATED) != 0;
}

static int is_in_quick_list(sf_header hdr) {
    size_t unobfuscated_header = hdr ^ MAGIC;
    return (unobfuscated_header & IN_QUICK_LIST) != 0;
}

// Function to write a footer to mirror header
static void write_footer(sf_block *bp, size_t payload_size, size_t block_size, int in_quicklist, int allocated) {
    sf_footer *footer = (sf_footer *)((char *)bp + block_size - sizeof(sf_footer));
    *footer = pack_header(payload_size, block_size, in_quicklist, allocated);
}

static void init_free_lists() {
    for (int i = 0; i < NUM_FREE_LISTS; i++) {
        sf_free_list_heads[i].body.links.next = &sf_free_list_heads[i];
        sf_free_list_heads[i].body.links.prev = &sf_free_list_heads[i];
    }
}

// Function to determine which free list index a block of size "size" should go in
static int get_freelist_index(size_t size) {
    size_t bound = MIN_BLOCK_SIZE;
    int index = 0;
    while (index < NUM_FREE_LISTS-1) {
        if (size <= bound) return index;
        bound <<= 1;
        index++;
    }

    return NUM_FREE_LISTS-1;
}

// Insert a free block into the appropriate free list
static void insert_free_block(sf_block *bp) {
    size_t bsize = get_block_size(bp->header);
    int i = get_freelist_index(bsize);

    sf_block *sentinel = &sf_free_list_heads[i];
    bp->body.links.next = sentinel->body.links.next;
    bp->body.links.prev = sentinel;
    sentinel->body.links.next->body.links.prev = bp;
    sentinel->body.links.next = bp;
}

static void remove_free_block(sf_block *bp) {
    if (bp == NULL) return;
    if (bp->body.links.prev) bp->body.links.prev->body.links.next = bp->body.links.next;
    if (bp->body.links.next) bp->body.links.next->body.links.prev = bp->body.links.prev;
}

static void init_quick_lists() {
    for (int i = 0; i < NUM_QUICK_LISTS; i++) {
        sf_quick_lists[i].length = 0;
        sf_quick_lists[i].first = NULL;
    }
}

// Get index if block_size exactly matches a quick_list_size 32+multiples of 16
static int get_quick_list_index(size_t block_size) {
    if (block_size < MIN_BLOCK_SIZE) return -1;

    if ((block_size - MIN_BLOCK_SIZE)%ALIGNMENT != 0) return -1;

    int index = (block_size - MIN_BLOCK_SIZE)/ALIGNMENT;

    if (index < 0 || index >= NUM_QUICK_LISTS) return -1;
    return index;
}

static sf_block *get_next_block(sf_block *bp) {
    size_t size = get_block_size(bp->header);
    sf_block *n = (sf_block *)((char *)bp + size);

    if ((char *)n >= (char *)sf_mem_end() - sizeof(sf_footer)) {
        return NULL;
    }

    return n;
}

static sf_block *get_prev_block(sf_block *bp) {
    sf_footer *footer = (sf_footer *)((char *)bp - sizeof(sf_footer));
    if ((char *)footer < (char *)sf_mem_start() + 8) {
        return NULL;
    }

    size_t prev_size = get_block_size(*footer);
    sf_block *p = (sf_block *)((char *)bp - prev_size);
    if ((char *)p < (char *)sf_mem_start() + 8) {
        return NULL;
    }
    return p;
}

static sf_block *coalesce(sf_block *bp) {
    size_t size = get_block_size(bp->header);

    sf_block *prev = get_prev_block(bp);
    sf_block *next = get_next_block(bp);

    if (prev != NULL) {
        sf_header phdr = prev->header;
        if (!is_allocated(phdr) && !is_in_quick_list(phdr)) {
            remove_free_block(prev);
            size_t psize = get_block_size(phdr);
            bp = prev;
            size += psize;
        }
    }

    if (next != NULL) {
        sf_header nhdr = next->header;
        if (!is_allocated(nhdr) && !is_in_quick_list(nhdr)) {
            remove_free_block(next);
            size += get_block_size(nhdr);
        }
    }

    bp->header = pack_header(0, size, 0, 0);
    write_footer(bp, 0, size, 0, 0);

    return bp;
}

static void add_block_to_quick_list(sf_block *bp, int index) {
    bp->body.links.next = sf_quick_lists[index].first;
    sf_quick_lists[index].first = bp;
    sf_quick_lists[index].length++;
}

static sf_block *pop_quick_list_block(int index) {
    if (sf_quick_lists[index].length == 0) return NULL;
    sf_block *bp = sf_quick_lists[index].first;
    sf_quick_lists[index].first = bp->body.links.next;
    sf_quick_lists[index].length--;
    return bp;
}

static sf_block *get_block_from_quick_list(size_t block_size) {
    int index = get_quick_list_index(block_size);
    if (index < 0) return NULL;
    if (sf_quick_lists[index].length == 0) return NULL;

    sf_block *bp = pop_quick_list_block(index);

    size_t old_payload = get_payload_size(bp->header);
    bp->header = pack_header(old_payload, block_size, 0, 1);
    write_footer(bp, old_payload, block_size, 0, 1);

    return bp;
}

static void flush_quick_list(int index) {
    sf_block *bp = sf_quick_lists[index].first;
    while (bp != NULL) {
        sf_block *next = bp->body.links.next;
        size_t size = get_block_size(bp->header);

        bp->header = pack_header(0, size, 0, 0);
        write_footer(bp, 0, size, 0, 0);

        sf_block *coalesced = coalesce(bp);

        insert_free_block(coalesced);

        bp = next;
    }
    sf_quick_lists[index].length = 0;
    sf_quick_lists[index].first = NULL;
}

static void initialize_heap() {
    void *start = sf_mem_grow();
    if (!start) {
        sf_errno = ENOMEM;
        return;
    }

    init_free_lists();
    init_quick_lists();

    sf_block *prologue = (sf_block *)((char *)start + 8);
    prologue->header = pack_header(0, MIN_BLOCK_SIZE, 0, 1);
    write_footer(prologue, 0, MIN_BLOCK_SIZE, 0, 1);

    size_t free_size = PAGE_SZ - MIN_BLOCK_SIZE - 8;
    sf_block *first_free = (sf_block *)((char *)prologue + MIN_BLOCK_SIZE);
    first_free->header = pack_header(0, free_size, 0, 0);
    write_footer(first_free, 0, free_size, 0, 0);
    insert_free_block(first_free);

    sf_block *epilogue = (sf_block *)((char *)first_free + free_size);
    epilogue->header = pack_header(0, 0, 0, 1);

    heap_initialized = 1;
}

static sf_block *extend_heap(size_t min_size_needed) {
    sf_block *coalesced = NULL;

    while (true) {
        void *addr = sf_mem_grow();
        if (!addr) {
            sf_errno = ENOMEM;
            return NULL;
        }

        sf_block *new_block = (sf_block *)addr;
        new_block->header = pack_header(0, PAGE_SZ, 0, 0);
        write_footer(new_block, 0, PAGE_SZ, 0, 0);

        coalesced = coalesce(new_block);

        size_t csize = get_block_size(coalesced->header);
        sf_block *epilogue = (sf_block *)((char *)coalesced + csize);
        epilogue->header = pack_header(0, 0, 0, 1);

        if (csize >= min_size_needed) break;
    }

    insert_free_block(coalesced);
    return coalesced;
}

void *sf_malloc(size_t size) {
    if (size == 0) return NULL;
    if (!heap_initialized) {
        initialize_heap();
        if (!heap_initialized) return NULL;
    }

    // Calculating the needed payload value and aligning it accordingly
    size_t needed_payload = size;
    size_t block_size = align(size + sizeof(sf_header) + sizeof(sf_footer));
    if (block_size < MIN_BLOCK_SIZE) block_size = MIN_BLOCK_SIZE;

    sf_block *qkblock = get_block_from_quick_list(block_size);
    if (qkblock != NULL) {
        total_payload += needed_payload;
        total_allocated += block_size;
        if (total_payload > peak_payload) peak_payload = total_payload;

        size_t newhdr = pack_header(needed_payload, block_size, 0, 1);
        qkblock->header = newhdr;
        write_footer(qkblock, needed_payload, block_size, 0, 1);
        return qkblock->body.payload;
    }

    int start_index = get_freelist_index(block_size);
    sf_block *found = NULL;
    for (int i = start_index; i < NUM_FREE_LISTS; i++) {
        sf_block *sentinel = &sf_free_list_heads[i];
        sf_block *bp = sentinel->body.links.next;
        while (bp != sentinel) {
            size_t bsize = get_block_size(bp->header);
            if (bsize >= block_size) {
                found = bp;
                break;
            }
            bp = bp->body.links.next;
        }
        if (found) break;
    }

    // If nothing is found in both quick and free lists, extend the heap
    if (!found) {
        sf_block *big_free = extend_heap(block_size);
        if (!big_free) return NULL;
        remove_free_block(big_free);
        found = big_free;
    } else {
        remove_free_block(found);
    }
    // Split if the leftover value is > 32
    size_t fsize = get_block_size(found->header);
    if (fsize - block_size >= MIN_BLOCK_SIZE) {
        size_t remainder_size = fsize - block_size;
        sf_block *remainder = (sf_block *)((char *)found + block_size);
        remainder->header = pack_header(0, remainder_size, 0, 0);
        write_footer(remainder, 0, remainder_size, 0, 0);
        insert_free_block(remainder);

        found->header = pack_header(needed_payload, block_size, 0, 1);
        write_footer(found, needed_payload, block_size, 0, 1);
    } else {
        // If splitting is not possible, over-allocate the entire block
        found->header = pack_header(needed_payload, fsize, 0, 1);
        write_footer(found, needed_payload, fsize, 0, 1);
        block_size = fsize;
    }

    total_payload += needed_payload;
    total_allocated += block_size;
    if (total_payload > peak_payload) peak_payload = total_payload;

    return found->body.payload;
}

void sf_free(void *pp) {
    // Validation
    if (pp == NULL || ((uintptr_t)pp % ALIGNMENT) != 0) abort();

    sf_block *bp = (sf_block *)((char *)pp - sizeof(sf_header));
    sf_header unobfuscated_header = (bp->header) ^ MAGIC;
    size_t block_size = get_block_size(bp->header);

    if (block_size < MIN_BLOCK_SIZE || (block_size % ALIGNMENT) != 0) abort();

    if ((unobfuscated_header & THIS_BLOCK_ALLOCATED) == 0) abort();

    if ((unobfuscated_header & IN_QUICK_LIST) != 0) abort();

    char *start_heap = (char *)sf_mem_start();
    char *end_heap = (char *)sf_mem_end();

    if ((char *)bp < start_heap + 8 || ((char *)bp + block_size) > end_heap) abort();

    size_t old_payload = unobfuscated_header >> 32;
    total_payload -= old_payload;
    total_allocated -= block_size;

    //Check if it can be added to a quick list
    int qk_index = get_quick_list_index(block_size);

    if (qk_index >= 0) {
        if (sf_quick_lists[qk_index].length >= QUICK_LIST_MAX) flush_quick_list(qk_index);

        bp->header = pack_header(0, block_size, 1, 1);
        write_footer(bp, 0, block_size, 1, 1);
        bp->body.links.next = NULL;
        add_block_to_quick_list(bp, qk_index);
    } else {
        // Create a new free block, coalesce it and put it in the free list
        bp->header = pack_header(0, block_size, 0, 0);
        write_footer(bp, 0, block_size, 0, 0);
        sf_block *coalesced = coalesce(bp);
        insert_free_block(coalesced);
    }
}

void *sf_realloc(void *pp, size_t rsize) {
    if (pp == NULL) {
        return sf_malloc(rsize);
    }

    if (rsize == 0) {
        sf_free(pp);
        return NULL;
    }

    if (((uintptr_t)pp % ALIGNMENT) != 0) {
        sf_errno = EINVAL;
        return NULL;
    }
    sf_block *bp = (sf_block *)((char *)pp - sizeof(sf_header));
    sf_header unobfuscated_header = bp->header ^ MAGIC;
    size_t old_block_size = get_block_size(bp->header);
    if (old_block_size < MIN_BLOCK_SIZE || (old_block_size % ALIGNMENT) != 0) {
        sf_errno = EINVAL;
        return NULL;
    }
    if (((unobfuscated_header & THIS_BLOCK_ALLOCATED) == 0) || ((unobfuscated_header & IN_QUICK_LIST) != 0)) {
        sf_errno = EINVAL;
        return NULL;
    }

    char *start_heap = (char *)sf_mem_start();
    char *end_heap = (char *)sf_mem_end();

    if ((char *)bp < start_heap + 8 || ((char *)bp + old_block_size) > end_heap){
        sf_errno = EINVAL;
        return NULL;
    }

    size_t old_payload = unobfuscated_header >> 32;
    size_t new_block_size = align(rsize + sizeof(sf_header));

    if (new_block_size < MIN_BLOCK_SIZE) new_block_size = MIN_BLOCK_SIZE;

    // If new block is smaller or equal, shrink it in place
    if (new_block_size <= old_block_size) {
        size_t leftover = old_block_size - new_block_size;
        if (leftover >= MIN_BLOCK_SIZE) {
            // If splitting needs to be done
            bp->header = pack_header(rsize, new_block_size, 0, 1);
            write_footer(bp, rsize, new_block_size, 0, 1);

            sf_block *rem = (sf_block *)((char *)bp + new_block_size);
            rem->header = pack_header(0, leftover, 0, 0);
            write_footer(rem, 0, leftover, 0, 0);

            sf_block *coalesced = coalesce(rem);
            insert_free_block(coalesced);

            total_payload = total_payload - old_payload + rsize;
            total_allocated = total_allocated - old_block_size + new_block_size;

            if (total_payload > peak_payload) peak_payload = total_payload;
        } else {
            bp->header = pack_header(rsize, old_block_size, 0, 1);
            write_footer(bp, rsize, old_block_size, 0, 1);
            total_payload = total_payload - old_payload + rsize;

            if (total_payload > peak_payload) peak_payload = total_payload;
        }
        return pp;
    } else {
        // If a bigger block is needed, use malloc + memcpy + free
        void *new_ptr = sf_malloc(rsize);
        if (!new_ptr) return NULL;
        size_t copy_size = (old_payload < rsize) ? old_payload : rsize;
        memcpy(new_ptr, pp, copy_size);
        sf_free(pp);
        return new_ptr;
    }

}

double sf_fragmentation() {
    if (total_allocated == 0) return 0.0;
    return (double)total_payload / (double)total_allocated;
}

double sf_utilization() {
    if (!heap_initialized) return 0.0;

    uintptr_t start = (uintptr_t)sf_mem_start();
    uintptr_t end = (uintptr_t)sf_mem_end();

    if (end <= start) return 0.0;
    size_t heap_size = end - start;
    if (heap_size == 0) return 0.0;

    return (double)peak_payload / (double)heap_size;
}
