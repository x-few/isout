#ifndef _ISOUT_ISOCKS_MODE_H_
#define _ISOUT_ISOCKS_MODE_H_

#include "isshe_common.h"

#define ISOUT_DEFAULT_PAC_FILE      "/tmp/isout.pac"
#define ISOUT_DEFAULT_URL           "file://localhost/tmp/isout.pac"
#define ISOUT_DEFAULT_COMMAND_MAX   1024

#define ISOUT_PROXY_ON              1
#define ISOUT_PROXY_OFF             0

isshe_int_t isocks_pac_file_generate(isshe_char_t *filename);

isshe_int_t isocks_mode_set();

#endif