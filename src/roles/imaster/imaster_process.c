
#include "isout.h"

irole_t imaster_roles[] = 
{
    { "isocks", isocks_start },
    { NULL, NULL },
};

imaster_process_t imaster_roles_process[IMASTER_MAX_ROLES_PROCESS];


void
imaster_roles_process_init()
{
    isshe_int_t i;
    for (i = 0; i < IMASTER_MAX_ROLES_PROCESS; i++) {
        isshe_memzero(&imaster_roles_process[i], sizeof(imaster_process_t));
        imaster_roles_process[i].pid = IMASTER_INVALID_PID;
    }
}

static isshe_int_t imaster_roles_process_find(isshe_pid_t pid)
{
    isshe_int_t i;
    for (i = 0; i < IMASTER_MAX_ROLES_PROCESS; i++) {
        if (imaster_roles_process[i].pid == pid) {
            return i;
        }
    }
    return IMASTER_INVALID_INDEX;
}


isshe_int_t
imaster_process_spawn(ilog_t *log,
    irole_process_spawn_cb proc,
    void *ctx, isshe_int_t respawn)
{
    isshe_int_t     i;
    isshe_pid_t     pid;

    if (respawn > 0) {
        // 重启具体某个进程
        i = respawn;
    } else {
        // 新启动
        i = imaster_roles_process_find(IMASTER_INVALID_PID);
        if (i == IMASTER_INVALID_INDEX) {
            ilog_alert(log, "no more than %d processes can be spawned",
                        IMASTER_MAX_ROLES_PROCESS);
            return IMASTER_INVALID_INDEX;
        }
    }

    // TODO 设置通信管道

    pid = fork();
    switch (pid)
    {
    case IMASTER_INVALID_PID:
        return IMASTER_INVALID_INDEX;
    case IMASTER_FORK_CHILD_PID:
        proc(ctx);
        return IMASTER_INVALID_INDEX;
    default:
        break;
    }

    imaster_roles_process[i].pid = pid;
    imaster_roles_process[i].exiting = 0;

    switch (respawn)
    {
    case IMASTER_PROCESS_RESPAWN:
        imaster_roles_process[i].respawn = 1;
        break;
    default:
        break;
    }

    return i;
}


isshe_int_t
imaster_roles_process_start(iconfig_t *config)
{
    isshe_json_t    *jsroles_array;
    isshe_json_t    *jsrole;
    irole_t         *role;
    isshe_int_t     array_len;
    isshe_int_t     len;
    isshe_pid_t     index;

    jsroles_array = isshe_json_get_object(config->config_json, "enable_roles");
    array_len = isshe_json_get_array_size(jsroles_array);
    if (!jsroles_array
    || !isshe_json_is_array(jsroles_array)
    || array_len <= 0) {
        ilog_alert(config->log, "config error: no 'enable_roles' field");
        return ISSHE_FAILURE;
    }

    int i;
    for (i = 0; i < array_len; i++) {
        jsrole = isshe_json_get_array(jsroles_array, i);
        if (!jsrole
        || jsrole->type != ISSHE_JSON_STRING
        || strlen(jsrole->vstring) <= 0) {

            ilog_warning(config->log, "config error: 'enable_roles' has invlid role name, ignore...");
            continue;
        }
        len = strlen(jsrole->vstring);
        for (role = imaster_roles; role->name != NULL; role++) {
            if (strlen(role->name) != len
            || isshe_memcmp(role->name, jsrole->vstring, len) != 0) {
                continue;
            }
            index = imaster_process_spawn(config->log, role->start, 
                                        config, IMASTER_PROCESS_RESPAWN);
            if (index == IMASTER_INVALID_INDEX) {
                ilog_alert(config->log, "fork() failed while spawning \"%s\"", role->name);
                continue;
            }
            ilog_notice(config->log, "start %s(%d)",
                        role->name, imaster_roles_process[index].pid);

            imaster_roles_process[index].ctx = (void *)config;
            imaster_roles_process[index].role = role;
        }
    }

    return ISSHE_SUCCESS;
}


void
imaster_process_status_print(ilog_t *log, isshe_int_t index)
{
    isshe_pid_t pid = imaster_roles_process[index].pid;
    isshe_char_t *name = imaster_roles_process[index].role->name;
    int status = imaster_roles_process[index].status;

    if (WTERMSIG(status)) {
#ifdef WCOREDUMP
        ilog_alert(log, "%s(%d) exited on signal %d%s", 
            name, pid, WTERMSIG(status),
            WCOREDUMP(status) ? " (core dumped)" : "");
#else
        ilog_alert(log, "%s(%d) exited on signal %d",
            name, pid, WTERMSIG(status));
#endif
    } else {
        ilog_notice(log, "%s(%d) exited with code %d", 
            name, pid, WEXITSTATUS(status));
    }

    if (WEXITSTATUS(status) != IMASTER_PROCESS_NORMAL_EXIT
        && imaster_roles_process[index].respawn) {
        imaster_roles_process[index].respawn = 0;
        ilog_alert(log, 
            "%s(%d) exited with fatal code %d "
            "and cannot be respawned", 
            name, pid, WEXITSTATUS(status));
    }
}

void imaster_process_status_get(void)
{
    int             status;
    isshe_pid_t     pid;
    isshe_errno_t   errcode;
    ilog_t          *log;
    isshe_int_t     i;

    log = ilog_get();
    while(ISSHE_TRUE) {
        pid = waitpid(-1, &status, WNOHANG);
        ilog_info(log, "waitpid: pid = %d", pid);
        if (pid == 0) {
            // no child exit
            return;
        }

        if (pid == IMASTER_INVALID_PID) {
            // error
            errcode = errno;
            if (errcode == EINTR) {
                continue;
            }

            if (errcode == ECHILD) {
                ilog_info_errno(log, errcode, "waitpid() failed");
                return;
            }

            ilog_alert_errno(log, errcode, "waitpid() failed");
            return;
        }

        // pid > 0
        // TODO 找出来，并关闭相关资源
        i = imaster_roles_process_find(pid);
        if (i == IMASTER_INVALID_INDEX) {
            ilog_alert(log, "(unlikely)can not get exited "
                "process info: pid = %d.", pid);
            continue;
        }
        imaster_roles_process[i].status = status;
        imaster_roles_process[i].exited = ISSHE_TRUE;

        imaster_process_status_print(log, i);
    }
}

void
imaster_roles_process_respwan(iconfig_t *config)
{
    // TODO
    ilog_debug(config->log, "-----respawn!!!-----");
}