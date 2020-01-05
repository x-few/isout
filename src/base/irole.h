#include "isshe_common.h"

typedef struct irole_s irole_t;

typedef void (*irole_process_spawn_cb)(void *ctx);

struct irole_s {
    char                    *name;
    irole_process_spawn_cb  start;
};
