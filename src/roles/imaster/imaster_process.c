
#include "isout.h"

irole_t imaster_roles[] = 
{
    { "isocks", isocks_start },
    { "iproxy", iproxy_start },
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

void
imaster_roles_process_free(isshe_int_t index)
{
    imaster_roles_process[index].pid = IMASTER_INVALID_PID;
    if (imaster_roles_process[index].name
            && imaster_roles_process[index].name != IMASTER_PROCESS_DEF_NAME) {
        free(imaster_roles_process[index].name);
        imaster_roles_process[index].name = NULL;
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
imaster_channel_create()
{
    // 新建/设置通讯通道
    return ISSHE_SUCCESS;
}


isshe_int_t
imaster_process_spawn(ilog_t *log, isshe_char_t *name,
    irole_process_spawn_cb proc,
    void *ctx, isshe_pid_t pid_index)
{
    isshe_int_t     i;
    isshe_pid_t     pid;

    if (pid_index != IMASTER_INVALID_INDEX) {
        i = pid_index;
    } else {
        i = imaster_roles_process_find(IMASTER_INVALID_PID);
        if (i == IMASTER_INVALID_INDEX) {
            ilog_alert(log, "no more than %d processes can be spawned",
                        IMASTER_MAX_ROLES_PROCESS);
            return IMASTER_INVALID_INDEX;
        }
        // 清零
        isshe_memzero(&imaster_roles_process[i], sizeof(imaster_process_t));
    }

    pid = fork();
    switch (pid)
    {
    case IMASTER_INVALID_PID:
        return IMASTER_INVALID_INDEX;
    case IMASTER_FORK_CHILD_PID:
        proc(ctx);
        exit(0);    // TODO ?!
    default:
        break;
    }

    if (name) {
        isshe_size_t len = strlen(name) + 1;
        imaster_roles_process[i].name = (isshe_char_t *)malloc(len);
        if (imaster_roles_process[i].name) {
            isshe_memcpy(imaster_roles_process[i].name, name, len);
        } else {
            imaster_roles_process[i].name = IMASTER_PROCESS_DEF_NAME;
        }
    }

    imaster_roles_process[i].ctx = ctx;
    imaster_roles_process[i].proc = proc;
    imaster_roles_process[i].pid = pid;
    imaster_roles_process[i].log = log;
    imaster_roles_process[i].flag.exiting = 0;
    // 默认重启，不需要的话，调用函数进行处理。
    imaster_roles_process[i].flag.respawn = 1;

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
            index = imaster_process_spawn(config->log, role->name, role->start,
                                        config, IMASTER_INVALID_INDEX);
            if (index == IMASTER_INVALID_INDEX) {
                ilog_alert(config->log, "fork() failed while spawning \"%s\"", role->name);
                continue;
            }

            ilog_notice(config->log, "start %s(%d)",
                        role->name, imaster_roles_process[index].pid);
            imaster_roles_process[index].role = role;

            // TODO: imaster_channel_create
            imaster_channel_create();
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
        && imaster_roles_process[index].flag.respawn) {
        imaster_roles_process[index].flag.respawn = 0;
        ilog_alert(log, 
            "%s(%d) exited with fatal code %d "
            "and cannot be respawned", 
            name, pid, WEXITSTATUS(status));
    }
}

isshe_bool_t is_normal_exit(isshe_int_t status)
{
    return (isshe_bool_t)WIFEXITED(status);
}

isshe_bool_t is_terminating()
{
    if (ismaster_signal_is_triggered(ISSHE_SIGNAL_SHUTDOWN)
            || ismaster_signal_is_triggered(ISSHE_SIGNAL_INTERRUPT)
            || ismaster_signal_is_triggered(ISSHE_SIGNAL_TERMINATE)) {
        return ISSHE_TRUE;
    }
    return ISSHE_FALSE;
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
        imaster_roles_process[i].flag.exited = ISSHE_TRUE;
        if (is_normal_exit(status) || is_terminating()) {
            // 正常退出，就不重启了
            imaster_roles_process[i].flag.respawn = ISSHE_FALSE;
        }

        if (!imaster_roles_process[i].flag.respawn) {
            // 回收，给下一个用
            imaster_roles_process_free(i);
        }

        imaster_process_status_print(log, i);
    }
}


void
imaster_roles_process_respwan(iconfig_t *config)
{
    isshe_int_t i;
    isshe_pid_t pid;

    for (i = 0; i < IMASTER_MAX_ROLES_PROCESS; i++) {
        if (imaster_roles_process[i].flag.exited
                && imaster_roles_process[i].flag.respawn) {
            if (imaster_process_spawn(config->log,
                    imaster_roles_process[i].name, imaster_roles_process[i].proc,
                    imaster_roles_process[i].ctx, i) == IMASTER_INVALID_INDEX) {
                ilog_alert(config->log, "respawn %s(%d) failed",
                        imaster_roles_process[i].name,
                        imaster_roles_process[i].pid);
                // 继续下一个
                continue;
            }
            ilog_notice(config->log, "respawn %d to %d", pid, imaster_roles_process[i].pid);
        }
    }
}

isshe_int_t imaster_roles_process_notify(isshe_int_t signo)
{
    // TODO
    // 实现思路：
    // 1. 先用信号进行简单的通知。
    // 2. 后续参考nginx或其他开源项目，使用管道/sockpair/...等途径进行通信。可能需要重写替换事件循环模块(libevent)。
    isshe_int_t i;
    for (i = 0; i < IMASTER_MAX_ROLES_PROCESS; i++) {
        if (imaster_roles_process[i].pid != IMASTER_INVALID_PID
                && !imaster_roles_process[i].flag.exited) {
            isshe_signal_send(imaster_roles_process[i].pid, signo);
        }
    }

    return ISSHE_SUCCESS;
}

isshe_bool_t imaster_roles_process_all_existed()
{
    isshe_int_t i;
    for (i = 0; i < IMASTER_MAX_ROLES_PROCESS; i++) {
        if (imaster_roles_process[i].pid != IMASTER_INVALID_PID) {
            return ISSHE_FALSE;
        }
    }
    return ISSHE_TRUE;
}