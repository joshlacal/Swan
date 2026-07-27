#include "CATHandleDNS.h"

#include <arpa/nameser.h>
#include <resolv.h>
#include <string.h>

int swan_at_handle_query_txt(
    const char *name,
    uint8_t *output,
    size_t output_capacity
) {
    if (name == NULL || output == NULL || output_capacity == 0) {
        return -2;
    }

    unsigned char answer[65536];
    int answer_length = res_query(
        name,
        ns_c_in,
        ns_t_txt,
        answer,
        (int)sizeof(answer)
    );
    if (answer_length < 0) {
        return -1;
    }

    ns_msg message;
    if (ns_initparse(answer, answer_length, &message) < 0) {
        return -2;
    }

    size_t written = 0;
    int answer_count = ns_msg_count(message, ns_s_an);
    if (answer_count < 0 || answer_count > 128) {
        return -2;
    }
    for (int index = 0; index < answer_count; index++) {
        ns_rr record;
        if (ns_parserr(&message, ns_s_an, index, &record) < 0) {
            return -2;
        }
        if (ns_rr_type(record) != ns_t_txt) {
            continue;
        }

        const unsigned char *cursor = ns_rr_rdata(record);
        size_t remaining = (size_t)ns_rr_rdlen(record);
        size_t record_length = 0;
        while (remaining > 0) {
            size_t chunk_length = cursor[0];
            cursor++;
            remaining--;
            if (chunk_length > remaining || record_length + chunk_length > 4096) {
                return -2;
            }
            record_length += chunk_length;
            cursor += chunk_length;
            remaining -= chunk_length;
        }
        if (record_length > UINT16_MAX || written + 2 + record_length > output_capacity) {
            return -2;
        }

        output[written] = (uint8_t)((record_length >> 8) & 0xff);
        output[written + 1] = (uint8_t)(record_length & 0xff);
        written += 2;

        cursor = ns_rr_rdata(record);
        remaining = (size_t)ns_rr_rdlen(record);
        while (remaining > 0) {
            size_t chunk_length = cursor[0];
            cursor++;
            remaining--;
            memcpy(output + written, cursor, chunk_length);
            written += chunk_length;
            cursor += chunk_length;
            remaining -= chunk_length;
        }
    }
    return (int)written;
}
