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
    isshe_process_title_set("isout: master");

    imaster_roles_process_init();
    // 起工作进程
    imaster_roles_process_start(config);

    // 清空信号集，sigsuspend则能被所有信号中断
    sigemptyset(&set);
    while(ISSHE_TRUE) {
        // 循环检测进程事件及监控工作进程
        ilog_debug(config->log, "---isshe---: before sigsuspend");
        sigsuspend(&set);
        ilog_debug(config->log, "---isshe---: behind sigsuspend");

        if (ismaster_signal_is_triggered(ISSHE_SIGNAL_RECONFIGURE)) {
            imaster_triggered_signal_del(ISSHE_SIGNAL_RECONFIGURE);
        }

        if (ismaster_signal_is_triggered(ISSHE_SIGNAL_SHUTDOWN)) {
            imaster_triggered_signal_del(ISSHE_SIGNAL_SHUTDOWN);
        }

        if (ismaster_signal_is_triggered(ISSHE_SIGNAL_INTERRUPT)
            || ismaster_signal_is_triggered(ISSHE_SIGNAL_TERMINATE)) {
            
            imaster_triggered_signal_del(ISSHE_SIGNAL_INTERRUPT);
            imaster_triggered_signal_del(ISSHE_SIGNAL_TERMINATE);
            // TODO 关闭并回收所有进程
            // TODO 进行清理工作
            exit(0);
        }

        if (ismaster_signal_is_triggered(ISSHE_SIGNAL_CHILD)) {
            imaster_triggered_signal_del(ISSHE_SIGNAL_CHILD);
            imaster_roles_process_respwan(config);
        }
    }
}