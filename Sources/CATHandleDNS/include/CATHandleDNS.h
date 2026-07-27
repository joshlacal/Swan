#ifndef SWAN_AT_HANDLE_DNS_H
#define SWAN_AT_HANDLE_DNS_H

#include <stddef.h>
#include <stdint.h>

/// Writes zero or more DNS TXT records as a sequence of two-byte big-endian
/// lengths followed by each record's concatenated character-string bytes.
/// Returns the byte count, -1 for a lookup failure, or -2 for malformed or
/// over-bound DNS data.
int swan_at_handle_query_txt(
    const char *name,
    uint8_t *output,
    size_t output_capacity
);

/// Parses one complete DNS wire response and writes each TXT answer as a
/// two-byte big-endian length followed by the concatenated character-string
/// chunks. Returns bytes written, or a negative value for malformed input.
int swan_at_handle_parse_txt_response(
    const uint8_t *response,
    size_t response_length,
    uint8_t *output,
    size_t output_capacity
);

#endif
