#ifndef _ISOUT_IMASTER_PROCESS_H_
#define _ISOUT_IMASTER_PROCESS_H_

#include "isout.h"

#define IMASTER_MAX_ROLES_PROCESS   32
#define IMASTER_INVALID_PID         (-1)
#define IMASTER_NEW_PID             (-1)
#define IMASTER_FORK_CHILD_PID      0
#define IMASTER_INVALID_INDEX       (-1)

#define IMASTER_PROCESS_SPAWN       (-1)
#define IMASTER_PROCESS_RESPAWN     (-2)
#define IMASTER_PROCESS_DETACHED    (-3)
#define IMASTER_PROCESS_NORESPAWN   (-4)
#define IMASTER_PROCESS_DEF_NAME    "undefined name"

#define IMASTER_PROCESS_NORMAL_EXIT  0

//typedef void (*imaster_process_spawn_cb)(void *data);
typedef struct imaster_process_s imaster_process_t;

typedef struct imaster_process_flag_s imaster_process_flag_t;

struct imaster_process_flag_s
{
    isshe_uchar_t       spawn:1;
    isshe_uchar_t       respawn:1;
    isshe_uchar_t       detached:1;
    isshe_uchar_t       exiting:1;
    isshe_uchar_t       exited:1;
};

struct imaster_process_s {
    isshe_char_t            *name;
    isshe_pid_t             pid;
    isshe_int_t             status;
    void                    *ctx;
    irole_process_spawn_cb  proc;
    irole_t                 *role;
    isshe_log_t                  *log;
    isshe_uint_t            respawn_count;
    imaster_process_flag_t  flag;
    // TODO
    //isshe_socket_t channel[2];

};

void imaster_roles_process_init();

isshe_int_t imaster_process_spawn(isshe_log_t *log, isshe_char_t *name,
    irole_process_spawn_cb proc, void *ctx, isshe_pid_t pid_index);

isshe_int_t imaster_roles_process_start(iconfig_t *config);

void imaster_roles_process_respwan(iconfig_t *config);

void imaster_process_status_get(void);

isshe_bool_t is_normal_exit(isshe_int_t status);
isshe_bool_t is_terminating();

isshe_int_t imaster_roles_process_notify(isshe_int_t signo);

isshe_bool_t imaster_roles_process_all_existed();


#endif