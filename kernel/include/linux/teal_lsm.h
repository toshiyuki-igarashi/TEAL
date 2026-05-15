#ifndef _LINUX_TEAL_LSM_H
#define _LINUX_TEAL_LSM_H

#include <linux/types.h>

#define TEAL_EVENT_FILE_OPEN   1
#define TEAL_EVENT_EXEC        2
#define TEAL_EVENT_CONNECT     3
#define TEAL_EVENT_FILE_WRITE  4
#define TEAL_EVENT_FILE_UNLINK 5
#define TEAL_EVENT_FILE_RENAME 6

typedef int (*teal_decision_func_t)(int event_type, void *ctx);
typedef void (*teal_config_func_t)(int mode);

void teal_register_decision_maker(teal_decision_func_t func);
void teal_unregister_decision_maker(void);
void teal_register_configurator(teal_config_func_t func);

int teal_check_jit_allow(const char *target);
int teal_wait_for_approval(const char *action,
                           const char *target_name,
                           dev_t target_dev,
                           unsigned long target_ino,
                           u8 teal_mode,
                           const char *exec_path,
                           const char *script_path,
                           const char *applet);
int teal_get_current_pid(void);
int teal_get_current_tgid(void);
void teal_get_current_comm(char *buf, size_t len);

/*
 * KUnit test helpers (test-only injection points)
 * These are only available when CONFIG_SECURITY_TEAL_KUNIT_TEST=y
 */
#ifdef CONFIG_SECURITY_TEAL_KUNIT_TEST
u64 teal_kunit_peek_first_pending_id(void);
int teal_kunit_set_decision(u64 id, int decision); /* 1=ALLOW, 2=DENY */
void teal_kunit_clear_all_requests(void);

void teal_kunit_invoke_configurator(int start); /* start: 1 or 0 */
void teal_kunit_clear_configurator(void);

int teal_kunit_invoke_decision(int event, void *ctx);
void teal_kunit_clear_decision_maker(void);
#endif

#endif
