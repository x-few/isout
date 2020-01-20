#include "isout.h"

void imaster_start(iconfig_t *config)
{
    sigset_t        set;
    //isshe_char_t    *title;

    // 设置信号处理函数
    imaster_signal_init(config->log);

    // 屏蔽信号
    sigemptyset(&set);
    imaster_signal_mask(config->log, &set);

    // TODO: 设置进程标题
    isshe_process_title_set("isout: imaster");

    imaster_roles_process_init();
    // 起工作进程
    imaster_roles_process_start(config);

    // 清空信号集，sigsuspend则能被所有信号中断
    sigemptyset(&set);
    while(ISSHE_TRUE) {
        // 循环检测进程事件及监控工作进程
        sigsuspend(&set);

        if (ismaster_signal_is_triggered(ISSHE_SIGNAL_RECONFIGURE)) {
            imaster_triggered_signal_del(ISSHE_SIGNAL_RECONFIGURE);
            // TODO
        }

        if (ismaster_signal_is_triggered(ISSHE_SIGNAL_SHUTDOWN)) {
            //imaster_triggered_signal_del(ISSHE_SIGNAL_SHUTDOWN);
            isshe_log_debug(config->log, "triggered ISSHE_SIGNAL_TERMINATE");
        }

        if (ismaster_signal_is_triggered(ISSHE_SIGNAL_INTERRUPT)) {
            // TODO 优雅关闭，参考nginx，延时一段时间后，子进程还不退出，就暴力退出。
            // 触发标记一直保存，直到所有进程退出。
            //imaster_triggered_signal_del(ISSHE_SIGNAL_INTERRUPT);
            isshe_log_debug(config->log, "triggered ISSHE_SIGNAL_KILL");
            imaster_roles_process_notify(ISSHE_SIGNAL_KILL);
        }

        if (ismaster_signal_is_triggered(ISSHE_SIGNAL_TERMINATE)) {
            //imaster_triggered_signal_del(ISSHE_SIGNAL_TERMINATE);
            isshe_log_debug(config->log, "triggered ISSHE_SIGNAL_TERMINATE");
        }

        if (ismaster_signal_is_triggered(ISSHE_SIGNAL_CHILD)) {
            imaster_triggered_signal_del(ISSHE_SIGNAL_CHILD);
            imaster_roles_process_respwan(config);
        }

        if (imaster_roles_process_all_existed()) {
            break;
        }
    }
}