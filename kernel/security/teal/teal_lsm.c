// SPDX-License-Identifier: GPL-2.0-only
/*
 * TEAL (Trusted Execution Analysis Layer) LSM
 *
 * Copyright (c) 2026 Toshiyuki Igarashi
 */
#include <linux/sched/mm.h>
#include <linux/lsm_hooks.h>
#include <linux/security.h>
#include <linux/kernel.h>
#include <linux/err.h>
#include <linux/net.h>
#include <linux/socket.h>
#include <linux/miscdevice.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/wait.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/jiffies.h>
#include <linux/string.h>
#include <linux/sched.h>
#include <linux/dcache.h>
#include <linux/path.h>
#include <linux/types.h>
#include <linux/errno.h>
#include <linux/ioctl.h>
#include <linux/mm.h>
#include <linux/file.h>
#include <linux/timekeeping.h>
#include <linux/cred.h>
#include <linux/uidgid.h>
#include <linux/user_namespace.h>
#include <linux/atomic.h>
#include <linux/capability.h>
#include <linux/binfmts.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/inet.h>
#include <linux/workqueue.h>
#include <linux/kdev_t.h> // MAJOR(), MINOR() マクロ用
#include <linux/rhashtable.h>
#include <linux/rcupdate.h>
#include <linux/magic.h>
#include <linux/anon_inodes.h>
#include <linux/mount.h>
#include <linux/fs_struct.h>
#include <linux/tty.h>

#include <net/genetlink.h>
#include <net/net_namespace.h>
#include <net/netlink.h>
#include <net/sock.h>

// ==========================================
// TEAL Generic Netlink (TLV) 定義
// ==========================================

#define TEAL_GENL_FAMILY_NAME "teal_ctrl"
#define TEAL_GENL_VERSION 1

#define TEAL_PATH_MAX   256   // 運用に合わせて 256/512/1024 など
#define TEAL_TARGET_MAX 256
#define TEAL_ACTION_MAX 16
#define TEAL_SCRIPT_MAX 256
#define TEAL_APPLET_MAX 256
#define TEAL_ARGS_MAX 128

/*
 * 1. コマンド定義 (Message Types)
 */
enum teal_nl_commands {
    TEAL_CMD_UNSPEC = 0,
    TEAL_CMD_REGISTER,      // 1: User -> Kernel: tealdのアタッチ（AUDITモード開始）
    TEAL_CMD_REQ,           // 2: Kernel -> User: 承認要求 (Slow Path)
    TEAL_CMD_INFO,          // 3: Kernel -> User: 状態通知 (Fast Path)
    TEAL_CMD_APPROVE,       // 4: User -> Kernel: 許可
    TEAL_CMD_DENY,          // 5: User -> Kernel: 拒否
    TEAL_CMD_TICKET_ADD,    // 6: User -> Kernel: キャッシュ登録
    TEAL_CMD_MODE_SWITCH,   // 7: User -> Kernel: AUDIT <-> ENFORCE 切替 (START/STOP)
    TEAL_CMD_POLICY_UPDATE, // 8: User -> Kernel: Epoch同期とキャッシュフラッシュ
    __TEAL_CMD_MAX,
};
#define TEAL_CMD_MAX (__TEAL_CMD_MAX - 1)

/*
 * 2. 属性定義 (Attributes / TLV)
 */
enum teal_nl_attrs {
    TEAL_ATTR_UNSPEC = 0,
    TEAL_ATTR_TRANS_ID,     // u64
    TEAL_ATTR_PID,          // u32
    TEAL_ATTR_PPID,         // u32
    TEAL_ATTR_SESSIONID,    // u32
    TEAL_ATTR_UID,          // u32
    TEAL_ATTR_GID,          // u32
    TEAL_ATTR_PROG_DEV,     // u32
    TEAL_ATTR_PROG_INO,     // u64
    TEAL_ATTR_PROGRAM,      // string
    TEAL_ATTR_ACTION,       // string
    TEAL_ATTR_TARGET_DEV,   // u32
    TEAL_ATTR_TARGET_INO,   // u64
    TEAL_ATTR_TARGET,       // string
    TEAL_ATTR_OP,           // u32: 操作マスク
    TEAL_ATTR_EXPIRES_AT,   // u64: 有効期限
    TEAL_ATTR_SCRIPT_DEV,   // u32
    TEAL_ATTR_SCRIPT_INO,   // u64
    TEAL_ATTR_SCRIPT,       // string
    TEAL_ATTR_APPLET,       // string
    TEAL_ATTR_LSM_LABEL,    // string
    TEAL_ATTR_ARGS_HEAD,    // string
    TEAL_ATTR_FLAGS,        // u32
    TEAL_ATTR_INFO_EVT,     // u8
    TEAL_ATTR_USES_LEFT,    // u32
    TEAL_ATTR_TICKET_ID,    // u64
    TEAL_ATTR_EPOCH,        // u32
    TEAL_ATTR_AUDIT_FLG,    // u32
    TEAL_ATTR_APPLET_HASH,  // u64

    // --- RENAME対応用 ---
    TEAL_ATTR_NEW_TARGET_DEV, // 29
    TEAL_ATTR_NEW_TARGET_INO, // 30
    TEAL_ATTR_NEW_TARGET,     // 31

    // --- ログインコンテキスト（TTY）用 ---
    TEAL_ATTR_SESSION_TTY,    // 32

    __TEAL_ATTR_MAX,
};
#define TEAL_ATTR_MAX (__TEAL_ATTR_MAX - 1)

/*
 * 3. 属性のバリデーションポリシー (受信時の安全保証)
 * カーネルがパニックを起こさないよう、受信するデータの型と長さをカーネル側で厳格にチェックします。
 */
static const struct nla_policy teal_nl_policy[TEAL_ATTR_MAX + 1] = {
    [TEAL_ATTR_TRANS_ID]    = { .type = NLA_U64 },
    [TEAL_ATTR_UID]         = { .type = NLA_U32 },
    [TEAL_ATTR_PROG_DEV]    = { .type = NLA_U32 },
    [TEAL_ATTR_PROG_INO]    = { .type = NLA_U64 },
    [TEAL_ATTR_SCRIPT_DEV]  = { .type = NLA_U32 },
    [TEAL_ATTR_SCRIPT_INO]  = { .type = NLA_U64 },
    [TEAL_ATTR_TARGET_DEV]  = { .type = NLA_U32 },
    [TEAL_ATTR_TARGET_INO]  = { .type = NLA_U64 },
    [TEAL_ATTR_OP]          = { .type = NLA_U32 },
    [TEAL_ATTR_EXPIRES_AT]  = { .type = NLA_U64 },
    [TEAL_ATTR_ACTION]      = { .type = NLA_NUL_STRING, .len = TEAL_ACTION_MAX },
    [TEAL_ATTR_APPLET_HASH] = { .type = NLA_U64 },
    [TEAL_ATTR_USES_LEFT]   = { .type = NLA_U32 },
    [TEAL_ATTR_TICKET_ID]   = { .type = NLA_U64 },
    [TEAL_ATTR_EPOCH]       = { .type = NLA_U32 },
    [TEAL_ATTR_AUDIT_FLG]   = { .type = NLA_U32 },

    // --- RENAME対応用 ---
    [TEAL_ATTR_NEW_TARGET_DEV] = { .type = NLA_U32 },
    [TEAL_ATTR_NEW_TARGET_INO] = { .type = NLA_U64 },
    [TEAL_ATTR_NEW_TARGET]     = { .type = NLA_NUL_STRING, .len = 256 }, 
};

struct teal_request {
    u64 id;
    pid_t pid;
    pid_t ppid;
    pid_t sessionid;
    uid_t uid;
    gid_t gid;

    dev_t prog_dev;
    unsigned long prog_ino;

    dev_t target_dev;
    unsigned long target_ino;

    // 移動先のデバイス番号と inode 番号
    dev_t new_target_dev;
    unsigned long new_target_ino;

    dev_t script_dev;
    unsigned long script_ino;

    char program[TEAL_PATH_MAX];        // exec path（ELF or interpreter）
    char action[TEAL_ACTION_MAX];       // "READ"/"WRITE"/"EXEC" etc
    char target[TEAL_TARGET_MAX];       // file path or "-" for EXEC
    char new_target[TEAL_TARGET_MAX];   // 移動先の絶対パス文字列
    char script[TEAL_SCRIPT_MAX];       // shebang script or ""
    char applet[TEAL_APPLET_MAX];       // kernel's comm (task name)
    char args_head[TEAL_ARGS_MAX];      // 引数の要約 (先頭128バイト)

    int decision;
    u32 flags;
    struct list_head list;
};

/* --- フェーズ2で実装するコールバック関数のプロトタイプ宣言 --- */
static int teal_nl_recv_register(struct sk_buff *skb, struct genl_info *info);
static int teal_nl_recv_approve(struct sk_buff *skb, struct genl_info *info);
static int teal_nl_recv_deny(struct sk_buff *skb, struct genl_info *info);
static int teal_nl_recv_ticket_add(struct sk_buff *skb, struct genl_info *info);
static int teal_nl_recv_mode_switch(struct sk_buff *skb, struct genl_info *info);
static int teal_nl_recv_policy_update(struct sk_buff *skb, struct genl_info *info);
static int teal_genl_send_req(struct teal_request *req, u8 teal_mode);

/*
 * 4. オペレーション定義 (コマンドと実行関数の紐付け)
 */
static const struct genl_ops teal_nl_ops[] = {
    {
        .cmd = TEAL_CMD_REGISTER,
        .validate = GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP,
        .doit = teal_nl_recv_register,
    },
    {
        .cmd = TEAL_CMD_APPROVE,
        .validate = GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP,
        .doit = teal_nl_recv_approve,
        .policy = teal_nl_policy,
    },
    {
        .cmd = TEAL_CMD_DENY,
        .validate = GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP,
        .doit = teal_nl_recv_deny,
        .policy = teal_nl_policy,
    },
    {
        .cmd = TEAL_CMD_TICKET_ADD,
        .validate = GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP,
        .doit = teal_nl_recv_ticket_add,
        .policy = teal_nl_policy,
    },
    {
        .cmd = TEAL_CMD_MODE_SWITCH,
        .validate = GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP,
        .doit = teal_nl_recv_mode_switch,
        .policy = teal_nl_policy,
    },
    {
        .cmd = TEAL_CMD_POLICY_UPDATE,
        .validate = GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP,
        .doit = teal_nl_recv_policy_update,
        .policy = teal_nl_policy,
    },
};

/*
 * 5. ファミリー定義
 */
static struct genl_family teal_nl_family = {
    .name = TEAL_GENL_FAMILY_NAME,
    .version = TEAL_GENL_VERSION,
    .maxattr = TEAL_ATTR_MAX,
    .policy = teal_nl_policy,
    .module = THIS_MODULE,
    .ops = teal_nl_ops,
    .n_ops = ARRAY_SIZE(teal_nl_ops),
    .resv_start_op = __TEAL_CMD_MAX,
};

/* tealdのポートID (0は未接続状態) */
static atomic_t teal_daemon_portid = ATOMIC_INIT(0);

/*
 * REGISTER / NETLINK_URELEASE の状態遷移はこのspinlockで直列化する。
 * notifierからも呼ばれるため、spinlock区間ではsleepしない。
 */
static DEFINE_SPINLOCK(teal_daemon_state_lock);

/* REGISTERと切断後cleanupを直列化する（sleep可能な処理専用）。 */
static DEFINE_MUTEX(teal_daemon_lifecycle_mutex);
static void teal_daemon_disconnect_workfn(struct work_struct *work);
static DECLARE_WORK(teal_daemon_disconnect_work,
                    teal_daemon_disconnect_workfn);

/*
 * 登録済みtealdのNetlinkソケットから
 * 送信された制御コマンドだけを許可する。
 */
static inline int
teal_nl_check_authorized(const struct genl_info *info)
{
    u32 registered_portid;

    if (!info)
        return -EINVAL;

    /* TEALはinit_netでのみ通信する */
    if (genl_info_net(info) != &init_net)
        return -EPERM;

    registered_portid =
        (u32)atomic_read(&teal_daemon_portid);

    /* tealdが未登録 */
    if (registered_portid == 0)
        return -ENOTCONN;

    /* 登録済みtealdとは異なるソケット */
    if (info->snd_portid != registered_portid)
        return -EPERM;

    return 0;
}

// --- プロトタイプ宣言 ---
void teal_register_decision_maker(int (*callback)(int, void*));
void teal_unregister_decision_maker(void);
void teal_register_configurator(void (*callback)(int));
int teal_get_current_pid(void);
int teal_get_current_tgid(void);
void teal_get_current_comm(char *buf, size_t len);
int teal_wait_for_approval(const char *action,
                           const char *target_name,
                           u64 target_dev,
                           u64 target_ino,
                           const char *new_target,
                           u64 new_target_dev,
                           u64 new_target_ino,
                           u8 teal_mode,
                           const char *exec_path,
                           const char *script_path,
                           const char *applet,
                           const char *args);
static void teal_gc_worker(struct work_struct *work);

/* event typeの定義　teal_decision_makerで使用する */
enum teal_event_type {
    TEAL_EVENT_READ     = 1,
    TEAL_EVENT_WRITE    = 2,
    TEAL_EVENT_EXECUTE  = 4,
    TEAL_EVENT_DELETE = 8,
    TEAL_EVENT_UNLINK = 16,
    TEAL_EVENT_RENAME = 32,
    TEAL_EVENT_CHMOD = 64,
    TEAL_EVENT_CHOWN = 128,
    TEAL_EVENT_CONNECT  = 256,
};

/**
 * Rust 引き渡しコンテキスト
 */
struct teal_rs_ctx {
    const char *target;
    const char *program;
    const char *script;
    const char *args;
    dev_t target_dev;
    unsigned long target_ino;
};

/**
 * リネームフック専用の Rust 引き渡しコンテキスト
 */
struct teal_rs_rename_ctx {
    const char *program;
    const char *script;
    const char *args;

    // 移動元 (Source) 情報
    const char *old_target;
    dev_t old_target_dev;
    unsigned long old_target_ino;

    // 移動先 (Destination) 情報
    const char *new_target;
    dev_t new_target_dev;
    unsigned long new_target_ino;
};

/**
 * 識別子（デバイス番号とiノード番号）のペア
 */
struct teal_id_pair {
    __u64 dev;
    __u64 ino;
};

/**
 * TICKET_ADD メッセージを格納する構造体
 */
struct teal_ticket_add_payload {
    struct list_head list;
    __u32 uid;
    __u32 op;
    struct teal_id_pair org;
    struct teal_id_pair script;
    __u64 applet_hash;
    struct teal_id_pair obj;      // 移動元 (Source)
    struct teal_id_pair new_obj;  // 移動先 (Destination)
    __u64 expires_at;
    atomic_t uses_left;
    __u64 ticket_id;
    __u32 epoch;
    __u32 audit_flags;
    __u32 flags;

    struct rcu_head rcu;
    // 削除時にハッシュテーブルからも消せるようにするためのポインタ
    void *cache_entry; 

    bool invalidated;
};

// ==========================================
//  キャッシュ用ハッシュテーブルの定義
// ==========================================
struct teal_inode_cache {
    struct rhlist_head node;      // 重複キー対応のリストヘッド
    struct rcu_head rcu;
    struct teal_id_pair obj_key;  // 検索キー (devとino)
    struct teal_ticket_add_payload *ticket; // 元のチケットへのポインタ
};

struct rhltable teal_ticket_ht;

static const struct rhashtable_params teal_cache_params = {
    .key_offset = offsetof(struct teal_inode_cache, obj_key),
    .key_len = sizeof(struct teal_id_pair),
    .head_offset = offsetof(struct teal_inode_cache, node),
    .automatic_shrinking = true,
};

/* チケットを保持するリストのヘッド */
static LIST_HEAD(teal_ticket_list);

/* リスト操作を守るためのスピンロック */
static DEFINE_MUTEX(teal_ticket_update_mutex);

enum ticket_event_type {
    TICKET_CONSUMED = 1,
    TICKET_EXPIRED  = 2,
};

/* ユーザー空間への通知専用構造体 */
struct teal_log_entry {
    struct list_head list;          // 通知待ちリスト用

    enum ticket_event_type type;    // チケットが処理された内容
    u64 ticket_id;              // どのチケットか
    u32 uid;                    // 誰が使ったか
    u32 uses_left_snapshot;     // その時点での残り回数
    u64 timestamp;              // 実行時刻

    unsigned long org_ino;      // Origin (実行プロセス)
    dev_t org_dev;
    unsigned long obj_ino;      // Object (ターゲットファイル)
    dev_t obj_dev;
    unsigned long new_obj_ino;
    dev_t new_obj_dev;
};

// チケットの振る舞いフラグ
#define TEAL_TICKET_FLG_SILENT_IO  0x01
#define TEAL_TICKET_FLG_INHERIT    0x02
#define TEAL_TICKET_FLG_NAMELESS_IPC    0x04

// per-task exec meta（task->security 直置き）
#define TEAL_TASK_META_MAGIC 0x5445414Cull /* 'TEAL' */

struct teal_task_meta {
    unsigned long magic;
    char program[TEAL_PATH_MAX];
    char script[TEAL_SCRIPT_MAX];
    char args_head[TEAL_ARGS_MAX];
    struct teal_id_pair program_id;
    struct teal_id_pair script_id;

    /* 上位32bit: epoch、下位32bit: flags */
    atomic64_t privilege_state;

    /* EXEC確定待ち: bprm_checkでは旧メタデータを変更しない */
    char pending_program[TEAL_PATH_MAX];
    char pending_script[TEAL_SCRIPT_MAX];
    char pending_args[TEAL_ARGS_MAX];
    struct teal_id_pair pending_program_id;
    struct teal_id_pair pending_script_id;
    bool pending_exec_valid;
};

// TEALが必要とするBlobサイズを定義
struct lsm_blob_sizes teal_blob_sizes __ro_after_init = {
    .lbs_task = sizeof(struct teal_task_meta),
};

static inline struct teal_task_meta *
teal_task_meta_of(const struct task_struct *task)
{
    if (!task || !task->security)
        return NULL;

    return (struct teal_task_meta *)
        ((char *)task->security + teal_blob_sizes.lbs_task);
}


// --- Rust連携用ポインタ ---
static int (*teal_decision_maker)(int event_type, void *ctx) = NULL;
static void (*teal_configurator)(int mode) = NULL;

void teal_register_decision_maker(int (*callback)(int, void*)) {
    teal_decision_maker = callback;
    printk(KERN_INFO "TEAL-LSM: Decision maker registered.\n");
}
EXPORT_SYMBOL(teal_register_decision_maker);

void teal_unregister_decision_maker(void) {
    teal_decision_maker = NULL;
    printk(KERN_INFO "TEAL-LSM: Decision maker unregistered.\n");
}
EXPORT_SYMBOL(teal_unregister_decision_maker);

void teal_register_configurator(void (*callback)(int)) {
    pr_info("[teal] register configurator: %ps\n", callback);
    teal_configurator = callback;

    /* 初期状態を STOP に揃える */
    if (teal_configurator) {
        pr_info("[teal] init configurator with STOP(0)\n");
        teal_configurator(0);
    }
}
EXPORT_SYMBOL(teal_register_configurator);

int teal_get_current_pid(void) {
    return current->pid;
}
EXPORT_SYMBOL(teal_get_current_pid);

int teal_get_current_tgid(void) {
    return current->tgid;
}
EXPORT_SYMBOL(teal_get_current_tgid);

void teal_get_current_comm(char *buf, size_t len)
{
    if (!buf || len < TASK_COMM_LEN)
        return;

    /* current->comm は TASK_COMM_LEN の NUL 終端文字列 */
    memcpy(buf, current->comm, TASK_COMM_LEN);
    buf[TASK_COMM_LEN - 1] = '\0';

}
EXPORT_SYMBOL(teal_get_current_comm);

static atomic_t teal_daemon_tgid = ATOMIC_INIT(-1);

/* tealdとの同期が成立した現在のPolicy Epoch */
static atomic_t teal_current_epoch = ATOMIC_INIT(0);
/* 最後に確定したEpoch。切断・REGISTERではリセットしない。
 * teal_ticket_update_mutexで保護する。0は未使用。
 */
static u32 teal_last_epoch;


// --- 待機キュー & JIT管理 ---
// teal_request.flags definition
#define TEAL_REQ_F_AUDIT      (1U << 0)
#define TEAL_REQ_F_DELIVERED  (1U << 1)
#define TEAL_REQ_F_TRUNC      (1U << 2)   // ★追加

// ==========================================
// TEAL デュアルレーン・データ構造定義
// ==========================================

// --- Control Lane (特急・同期レーン) 用 ---
static LIST_HEAD(teal_ctl_list);                             // ENFORCEモードのREQを入れるリスト
static DEFINE_SPINLOCK(teal_ctl_lock);                       // Controlレーン専用ロック
static DECLARE_WAIT_QUEUE_HEAD(teal_ctl_wait_queue);         // Decision Worker (teald) および カーネルプロセス を待機させるキュー

// --- 共通管理用 ---
static atomic64_t teal_next_id = ATOMIC64_INIT(1);           // 競合を防ぐアトミックなID発番機

#define TEAL_MODE_ENFORCE  0
#define TEAL_MODE_AUDIT    1

static void teal_req_detach_free(struct teal_request *req);
static int teal_req_wait(struct teal_request *req);
static inline int teal_decision_to_rc(int decision);
static struct teal_request *teal_req_build(const char *action,
                                           const char *target_name,
                                           u64 target_dev,
                                           u64 target_ino,
                                           const char *new_target,
                                           u64 new_target_dev,
                                           u64 new_target_ino,
                                           const char *exec_path,
                                           const char *script_path,
                                           const char *applet,
                                           const char *args);
static int teal_req_enqueue(struct teal_request *req, u8 teal_mode);

// --- 待機ロジック (Rustから呼ばれる) ---
int teal_wait_for_approval(const char *action,
                           const char *target_name,
                           u64 target_dev,
                           u64 target_ino,
                           const char *new_target,
                           u64 new_target_dev,
                           u64 new_target_ino,
                           u8 teal_mode,
                           const char *exec_path,
                           const char *script_path,
                           const char *applet,
                           const char *args)
{
    struct teal_request *req;
    int decision;
    int rc;

    might_sleep();

    /* 防御的プログラミング (サニタイズ) */
    if (IS_ERR_OR_NULL(action))      action = "unknown";
    if (IS_ERR_OR_NULL(target_name)) target_name = "unknown";
    // RENAME以外では空で来るため、安全なデフォルト値 "-" をセット
    if (IS_ERR_OR_NULL(new_target))  new_target = "-"; 
    
    if (IS_ERR_OR_NULL(exec_path))   exec_path = "unknown";
    if (IS_ERR_OR_NULL(script_path)) script_path = "none";
    if (IS_ERR_OR_NULL(applet))      applet = "none";

    /*
     * exec_path : 実行バイナリの絶対パス（例: /bin/sh, /usr/bin/python）
     * script_path : スクリプト実体（例: foo.sh, bar.py）
     * バイナリ直実行の場合は NULL ("none"に置換済み)
     */
    req = teal_req_build(action, target_name, target_dev, target_ino, 
                         new_target, new_target_dev, new_target_ino,
                         exec_path, script_path, applet, args);
    if (!req)
        return -ENOMEM;

    rc = teal_req_enqueue(req, teal_mode);
    if (rc < 0) {
        /* * 送信失敗時は、プロセスを止めないために特別に許可（0）を返してリクエストを解放する。
         * ただし、teald未接続（-ENOTCONN）による意図的なFail-Safe移行の通信スキップ時は、
         * ログストームを防ぐためエラーメッセージを出力しない。
         */
        if (rc != -ENOTCONN) {
            pr_warn_ratelimited(
                "TEAL: Failed to send request (rc=%d). Fail-safe: ALLOW. "
                "action=%s target=%s prog=%s script=%s applet=%s\n", 
                rc, action, target_name, exec_path, script_path, applet
            );
        }
        kfree(req);
        return 0; 
    }

    /*
     * AUDIT: do not block.
     * teald will read + decide + log, then CONSUME to reclaim.
     */
    if (req->flags & TEAL_REQ_F_AUDIT) {
        kfree(req); // AUDITは待ちリストに入っていないのでここでfree
        return 0;
    }

    decision = teal_req_wait(req);
    teal_req_detach_free(req);

    return teal_decision_to_rc(decision);
}
EXPORT_SYMBOL(teal_wait_for_approval);

static inline struct teal_task_meta *teal_task_meta_current(void)
{
    return teal_task_meta_of(current);
}

/*
 * 現在のPolicy Epochで有効なSelf-Baking権限を取得する。
 *
 * privilege_state:
 *   upper 32 bits: epoch
 *   lower 32 bits: flags
 *
 * Return:
 *   有効な権限フラグ、または0
 */
static inline u32 teal_get_active_ticket_flags(void)
{
    struct teal_task_meta *meta;
    u64 state;
    u32 epoch;
    u32 flags;
    u32 current_epoch;

    meta = teal_task_meta_current();

    if (!meta || meta->magic != TEAL_TASK_META_MAGIC)
        return 0;

    state = (u64)atomic64_read(&meta->privilege_state);

    epoch = (u32)(state >> 32);
    flags = (u32)state;

    current_epoch = (u32)atomic_read(&teal_current_epoch);

    /* 未同期、または旧epochの権限は使用しない */
    if (current_epoch == 0 || epoch != current_epoch)
        return 0;

    return flags;
}

#define TEAL_BAKE_FLAGS_MASK \
    (TEAL_TICKET_FLG_SILENT_IO | \
     TEAL_TICKET_FLG_NAMELESS_IPC | \
     TEAL_TICKET_FLG_INHERIT)

/*
 * チケットのSelf-Baking権限を現在のタスクに記録する。
 *
 * 通常チケット:
 *   uses_leftの減算が成功した後に呼び出す。
 *
 * ticket_id == 0:
 *   管理対象外チケットなので回数消費なしで呼び出す。
 *
 * 同一epoch:
 *   フラグをOR結合する。
 *
 * epoch不一致:
 *   古いフラグを引き継がない。
 */
static inline void teal_bake_ticket_flags(
    const struct teal_ticket_add_payload *ticket)
{
    struct teal_task_meta *meta;
    u64 old_state;
    u64 new_state;
    u64 prev;
    u32 old_epoch;
    u32 old_flags;
    u32 current_epoch;
    u32 new_flags;
    u32 bake_flags;

    if (!ticket)
        return;

    bake_flags = ticket->flags & TEAL_BAKE_FLAGS_MASK;

    if (!bake_flags)
        return;

    meta = teal_task_meta_current();

    if (!meta || meta->magic != TEAL_TASK_META_MAGIC)
        return;

    current_epoch = (u32)atomic_read(&teal_current_epoch);

    if (current_epoch == 0 ||
        READ_ONCE(ticket->epoch) != current_epoch)
        return;

    for (;;) {
        old_state =
            (u64)atomic64_read(&meta->privilege_state);

        old_epoch = (u32)(old_state >> 32);
        old_flags = (u32)old_state;

        /*
         * 同一epochなら既存フラグを継承。
         * 異なるepochなら旧フラグを破棄。
         */
        if (old_epoch == current_epoch)
            new_flags = old_flags | bake_flags;
        else
            new_flags = bake_flags;

        new_state =
            ((u64)current_epoch << 32) | new_flags;

        /*
         * POLICY_UPDATEによってepochが変更された
         * 場合は、新しい状態を書き込まない。
         */
        if ((u32)atomic_read(&teal_current_epoch) !=
            current_epoch)
            return;

        /*
         * CASによる原子的な状態更新。
         * 複数の更新が競合してもフラグを失わない。
         */
        prev = (u64)atomic64_cmpxchg(
            &meta->privilege_state,
            (s64)old_state,
            (s64)new_state
        );

        if (prev == old_state)
            return;

        cpu_relax();
    }
}

static struct teal_request *teal_req_build(const char *action,
                                           const char *target_name,
                                           u64 target_dev,
                                           u64 target_ino,
                                           const char *new_target,
                                           u64 new_target_dev,
                                           u64 new_target_ino,
                                           const char *exec_path,
                                           const char *script_path,
                                           const char *applet,
                                           const char *args)
{
    struct teal_request *req;
    const struct cred *cred;
    uid_t host_uid;
    struct teal_task_meta *m;
    bool need_prog_recovery = false;

    if (IS_ERR_OR_NULL(target_name) || target_name[0] == '\0')
        return NULL;

    req = kzalloc(sizeof(*req), GFP_KERNEL);
    if (!req)
        return NULL;

    /* 基本情報のセット */
    cred = current_cred();
    host_uid = from_kuid_munged(&init_user_ns, cred->euid);
    req->pid = current->tgid;
    rcu_read_lock();
    req->ppid = task_tgid_vnr(rcu_dereference(current->real_parent));
    rcu_read_unlock();
    req->sessionid = task_session_vnr(current);
    req->uid = host_uid;
    req->gid = from_kgid_munged(&init_user_ns, cred->egid);

    // ==========================================
    // ★ メタデータの取得と欠落チェック
    // ==========================================
    m = teal_task_meta_current();
    if (m && m->magic == TEAL_TASK_META_MAGIC) {
        req->prog_dev = m->program_id.dev;
        req->prog_ino = m->program_id.ino;
        req->script_dev = m->script_id.dev;
        req->script_ino = m->script_id.ino;

        /* IDが0、またはパスが未設定ならリカバリが必要と判断 */
        if (req->prog_dev == 0 || (exec_path && exec_path[0] == '-'))
            need_prog_recovery = true;
    } else {
        need_prog_recovery = true;
    }

    // ==========================================
    // ★ 保険：実行ファイルから情報を直接解決する
    // ==========================================
    if (need_prog_recovery) {
        struct file *exe = get_task_exe_file(current);
        if (exe) {
            struct inode *inode = file_inode(exe);
            req->prog_dev = inode->i_sb->s_dev;
            req->prog_ino = inode->i_ino;

            /* パス名が "-" または NULL の場合のみ d_path で解決を試みる */
            if (!exec_path || exec_path[0] == '-' || exec_path[0] == '\0') {
                char *tbuf = __getname();
                if (tbuf) {
                    char *p = d_path(&exe->f_path, tbuf, PATH_MAX);
                    if (!IS_ERR(p)) {
                        strscpy(req->program, p, sizeof(req->program));
                        exec_path = req->program; /* 下段のコピー処理で上書きされないようにする */
                    }
                    __putname(tbuf);
                }
            }
            fput(exe);

            /* ついでにタスクメタデータ(キャッシュ)も修復しておくと、次回から高速化される */
            if (m && m->magic == TEAL_TASK_META_MAGIC) {
                m->program_id.dev = req->prog_dev;
                m->program_id.ino = req->prog_ino;
                if (exec_path && exec_path[0] != '-')
                    strscpy(m->program, exec_path, sizeof(m->program));
            }
        }
    }

    /* ターゲット情報とアクションのセット */
    req->target_dev = target_dev;
    req->target_ino = target_ino;
    // 新しいターゲット情報をセット
    req->new_target_dev = new_target_dev;
    req->new_target_ino = new_target_ino;

    strscpy(req->action, !IS_ERR_OR_NULL(action) ? action : "-", sizeof(req->action));
    strscpy(req->target, target_name, sizeof(req->target));
    
    // 新しいパス情報を構造体にコピー
    if (!IS_ERR_OR_NULL(new_target) && new_target[0])
        strscpy(req->new_target, new_target, sizeof(req->new_target));
    else
        strscpy(req->new_target, "-", sizeof(req->new_target));

    /* パス情報の最終コピー */
    if (!IS_ERR_OR_NULL(exec_path) && exec_path[0] && exec_path != req->program)
        strscpy(req->program, exec_path, sizeof(req->program));
    else if (!req->program[0])
        strscpy(req->program, "-", sizeof(req->program));

    if (!IS_ERR_OR_NULL(script_path) && script_path[0])
        strscpy(req->script, script_path, sizeof(req->script));
    else
        strscpy(req->script, "-", sizeof(req->script));

    if (!IS_ERR_OR_NULL(applet) && applet[0])
        strscpy(req->applet, applet, sizeof(req->applet));

    // ==========================================
    // ★ 引数 (args_head) のセット
    // ==========================================
    /* 1. 明示的に渡された args を最優先 (bprm_check からの最新引数など) */
    if (!IS_ERR_OR_NULL(args) && args[0] != '\0' && args[0] != '-') {
        strscpy(req->args_head, args, sizeof(req->args_head));
    }
    /* 2. 引数が渡されなかった場合の保険: 既存タスクメタデータから補完 */
    else if (m && m->magic == TEAL_TASK_META_MAGIC && m->args_head[0] != '\0') {
        strscpy(req->args_head, m->args_head, sizeof(req->args_head));
    }
    /* 3. どちらも無ければ "-" */
    else {
        strscpy(req->args_head, "-", sizeof(req->args_head));
    }

    return req;
}

#define TEAL_DECISION_TIMEOUT_HZ    msecs_to_jiffies(3000)  // 3000ms = 3秒
#define TEAL_DECISION_APPROVE       1                       // 0 (ALLOW)

int teal_req_wait(struct teal_request *req)
{
    long remaining;

    // 無期限待ちではなく、最大3秒でタイムアウトさせる
    remaining = wait_event_interruptible_timeout(
        teal_ctl_wait_queue,
        READ_ONCE(req->decision) != 0,
        TEAL_DECISION_TIMEOUT_HZ
    );

    if (remaining == 0) {
        // タイムアウト発生: デーモン無応答のため Fail-Safe ALLOW
        pr_warn_ratelimited(
            "TEAL: Request timed out (daemon unresponsive). Fail-safe: ALLOW. "
            "action=%s target=%s prog=%s\n",
            req->action, req->target, req->program
        );
        return TEAL_DECISION_APPROVE;
    } else if (remaining < 0) {
        return -EINTR;
    }

    return req->decision;
}

static int teal_req_enqueue(struct teal_request *req, u8 teal_mode)
{
    int rc;
    req->id = atomic64_inc_return(&teal_next_id);

    if (teal_mode == TEAL_MODE_AUDIT) {
        req->flags |= TEAL_REQ_F_AUDIT;
        /* AUDITモード: リストに入れずに即送信 */
        return teal_genl_send_req(req, teal_mode);
    } else {
        /* ENFORCEモード: 判定を待つためにリストに登録 */
        spin_lock(&teal_ctl_lock);
        list_add_tail(&req->list, &teal_ctl_list);
        spin_unlock(&teal_ctl_lock);

        /* Netlinkで判定要求を送信 */
        rc = teal_genl_send_req(req, teal_mode);
        
        /* ★ 送信に失敗した場合、リストから外さないとプロセスが永遠に眠り続ける */
        if (rc < 0) {
            spin_lock(&teal_ctl_lock);
            list_del(&req->list);
            spin_unlock(&teal_ctl_lock);
        }
        return rc;
    }
}

static void teal_req_detach_free(struct teal_request *req)
{
    spin_lock(&teal_ctl_lock);
    list_del(&req->list);
    spin_unlock(&teal_ctl_lock);
    kfree(req);
}

static inline int teal_decision_to_rc(int decision)
{
    if (decision == 1)
        return 0;          /* approved */
    if (decision < 0)
        return decision;   /* already errno */
    if (decision == 2)
        return -EACCES;    /* legacy denied */
    if (decision == 0)
        return -EIO;       /* should not happen: still pending */
    return -EIO;           /* unknown positive */
}

static struct workqueue_struct *teal_wq;

static int handle_approve_deny(u64 id, bool approve)
{
    int new_dec = approve ? 1 : -EACCES;
    struct teal_request *req;

    spin_lock(&teal_ctl_lock);

    list_for_each_entry(req, &teal_ctl_list, list) {
        if (req->id == id && req->decision == 0) {
            WRITE_ONCE(req->decision, new_dec);
            spin_unlock(&teal_ctl_lock);

            wake_up_interruptible(&teal_ctl_wait_queue);
            return 0;
        }
    }

    spin_unlock(&teal_ctl_lock);
    return -ENOENT;
}

/**
 * handle_ticket_add - チケットを検証し、リストに追加する
 * @ticket: create_ticketで生成された構造体へのポインタ
 *
 * Return: 0 (成功), またはエラーコード
 */
static int handle_ticket_add(struct teal_ticket_add_payload *ticket)
{
    struct teal_inode_cache *entry;
    int ret;

    if (!ticket)
        return -EINVAL;

    if (atomic_read(&ticket->uses_left) == 0) {
        kfree(ticket);
        wake_up_all(&teal_ctl_wait_queue);
        return 0;
    }

    /* 1. キャッシュエントリを先に確保 */
    entry = kzalloc(sizeof(*entry), GFP_KERNEL);
    if (!entry) {
        kfree(ticket);
        return -ENOMEM;
    }

    entry->obj_key = ticket->obj;
    entry->ticket = ticket;

    /* 2. チケット更新処理の排他制御 */
    mutex_lock(&teal_ticket_update_mutex);

    /* 3. epochの最終確認 */
    if (ticket->epoch == 0 ||
        ticket->epoch != (u32)atomic_read(&teal_current_epoch)) {
        ret = -ESTALE;
        goto err_unlock;
    }

    /* 4. ハッシュテーブルへの登録 */
    ret = rhltable_insert(&teal_ticket_ht,
                         &entry->node,
                         teal_cache_params);
    if (ret)
        goto err_unlock;

    /* 5. リストへの登録 */
    ticket->cache_entry = entry;
    list_add_tail(&ticket->list, &teal_ticket_list);

    mutex_unlock(&teal_ticket_update_mutex);

    /* 6. 正常に登録できた場合だけ待機プロセスへ通知 */
    wake_up_all(&teal_ctl_wait_queue);

    return 0;

err_unlock:
    mutex_unlock(&teal_ticket_update_mutex);
    kfree(entry);
    kfree(ticket);
    return ret;
}

// ==========================================
// TEAL Generic Netlink: 受信 (User -> Kernel)
// ==========================================

/*
 * 【キュー初期化ヘルパー】
 * teald のアタッチ(起動)時やデタッチ時に、カーネル内に残っている
 * 古いリクエストや未送信ログを安全に破棄する。
 */
static void teal_flush_all_queues_locked(void) {
    struct teal_request *req, *tmp_req;
    struct teal_ticket_add_payload *ticket, *tmp_tick;

    /* 1. 承認待ちリクエスト（Control Lane）の解放 */
    spin_lock(&teal_ctl_lock);
    list_for_each_entry_safe(req, tmp_req, &teal_ctl_list, list) {
        if (req->decision == 0) {
            WRITE_ONCE(req->decision, -EACCES);     // 拒否として解除
        }
    }
    spin_unlock(&teal_ctl_lock);
    
    /* 待機中の全プロセスを一斉に起こす */
    wake_up_all(&teal_ctl_wait_queue);

    /* 2. チケットキャッシュ（Fast Path）の全解放 */
    list_for_each_entry_safe(ticket, tmp_tick, &teal_ticket_list, list) {
        // ハッシュテーブル（索引）からの削除
        if (ticket->cache_entry) {
            struct teal_inode_cache *entry = ticket->cache_entry;
            int ret;

            ret = rhltable_remove(
                &teal_ticket_ht,
                &entry->node,
                teal_cache_params
            );

            if (ret) {
                pr_err_ratelimited(
                    "TEAL: rhltable_remove failed (ret=%d, ticket_id=%llu)\n",
                    ret,
                    (unsigned long long)ticket->ticket_id
                );
                continue;
            }

            kfree_rcu(entry, rcu);
        }

        list_del(&ticket->list);
        kfree_rcu(ticket, rcu);
    }

    pr_info("TEAL: All queues and ticket caches flushed. Falling back to slow path.\n");
}

static void teal_flush_all_queues(void)
{
    mutex_lock(&teal_ticket_update_mutex);
    teal_flush_all_queues_locked();
    mutex_unlock(&teal_ticket_update_mutex);
}

/*
 * コマンド: TEAL_CMD_REGISTER
 * teald が起動した際の一番最初の挨拶。ここでポートIDを登録し、監査ループを回避する。
 */
/*
 * 切断通知では状態を即時無効化し、キャッシュ破棄はworkqueueへ委譲する。
 * 新しいREGISTERが先行した場合はREGISTER側がフラッシュ済みなので、
 * cleanup workerが新セッションのチケットを消さないよう判定する。
 */
/* REGISTERへの通常応答。TEAL_ATTR_EPOCHは次に使用すべきEpoch。 */
static int teal_nl_send_register_reply(struct genl_info *info, u32 next_epoch)
{
    struct sk_buff *reply;
    void *hdr;
    int ret;

    reply = genlmsg_new(NLMSG_DEFAULT_SIZE, GFP_KERNEL);
    if (!reply)
        return -ENOMEM;

    hdr = genlmsg_put_reply(reply, info, &teal_nl_family,
                            0, TEAL_CMD_REGISTER);
    if (!hdr) {
        nlmsg_free(reply);
        return -EMSGSIZE;
    }

    ret = nla_put_u32(reply, TEAL_ATTR_EPOCH, next_epoch);
    if (ret) {
        genlmsg_cancel(reply, hdr);
        nlmsg_free(reply);
        return ret;
    }

    genlmsg_end(reply, hdr);
    return genlmsg_reply(reply, info);
}

static void teal_daemon_disconnect_workfn(struct work_struct *work)
{
    unsigned long flags;
    bool disconnected;

    mutex_lock(&teal_daemon_lifecycle_mutex);
    spin_lock_irqsave(&teal_daemon_state_lock, flags);
    disconnected = atomic_read(&teal_daemon_portid) == 0;
    spin_unlock_irqrestore(&teal_daemon_state_lock, flags);

    if (disconnected)
        teal_flush_all_queues();

    mutex_unlock(&teal_daemon_lifecycle_mutex);
}

static int teal_nl_recv_register(struct sk_buff *skb,
                                 struct genl_info *info)
{
    unsigned long flags;
    u32 portid, next_epoch;
    int ret = 0;

    if (!info)
        return -EINVAL;

    portid = info->snd_portid;
    if (genl_info_net(info) != &init_net)
        return -EPERM;
    if (!portid)
        return -EINVAL;
    if (!capable(CAP_MAC_ADMIN) && !capable(CAP_SYS_ADMIN))
        return -EPERM;

    /* REGISTERと旧セッションのcleanupを直列化する。 */
    mutex_lock(&teal_daemon_lifecycle_mutex);
    mutex_lock(&teal_ticket_update_mutex);

    spin_lock_irqsave(&teal_daemon_state_lock, flags);
    if (atomic_read(&teal_daemon_portid) != 0)
        ret = -EBUSY;
    spin_unlock_irqrestore(&teal_daemon_state_lock, flags);
    if (ret)
        goto out_ticket_unlock;

    /* 32bit Epochは再利用しない。使い切ったら再起動等が必要。 */
    if (teal_last_epoch == U32_MAX) {
        ret = -EOVERFLOW;
        goto out_ticket_unlock;
    }
    next_epoch = teal_last_epoch + 1;

    /* 次の登録を公開する前にキャッシュと待機要求を破棄。 */
    atomic_set(&teal_current_epoch, 0);
    teal_flush_all_queues_locked();

    spin_lock_irqsave(&teal_daemon_state_lock, flags);
    if (atomic_read(&teal_daemon_portid) != 0) {
        ret = -EBUSY;
    } else {
        atomic_set(&teal_daemon_tgid, current->tgid);
        atomic_set(&teal_daemon_portid, portid);
    }
    spin_unlock_irqrestore(&teal_daemon_state_lock, flags);

out_ticket_unlock:
    mutex_unlock(&teal_ticket_update_mutex);
    if (ret)
        goto out_lifecycle_unlock;

    /* 通常のNetlink応答。NLM_F_ACKのACKとは別メッセージ。 */
    ret = teal_nl_send_register_reply(info, next_epoch);
    if (ret) {
        /* 応答不能時は、この登録がまだ生きていれば取り消す。 */
        spin_lock_irqsave(&teal_daemon_state_lock, flags);
        if ((u32)atomic_read(&teal_daemon_portid) == portid) {
            atomic_set(&teal_daemon_portid, 0);
            atomic_set(&teal_daemon_tgid, 0);
            atomic_set(&teal_current_epoch, 0);
        }
        spin_unlock_irqrestore(&teal_daemon_state_lock, flags);
        goto out_lifecycle_unlock;
    }

    pr_info("TEAL: teald registered: portid=%u tgid=%d next_epoch=%u\n",
            portid, current->tgid, next_epoch);

out_lifecycle_unlock:
    mutex_unlock(&teal_daemon_lifecycle_mutex);
    return ret;
}

/* Netlinkソケットの解放通知。ここではsleepしない。 */
static int teal_nl_notifier(struct notifier_block *nb,
                            unsigned long event, void *_ptr)
{
    struct netlink_notify *n = _ptr;
    unsigned long flags;
    bool disconnected = false;

    if (event != NETLINK_URELEASE || !n ||
        n->protocol != NETLINK_GENERIC || n->net != &init_net)
        return NOTIFY_DONE;

    spin_lock_irqsave(&teal_daemon_state_lock, flags);
    if (n->portid &&
        n->portid == (u32)atomic_read(&teal_daemon_portid)) {
        /* 先に失効させ、以後のPort ID認証を拒否する。 */
        atomic_set(&teal_daemon_portid, 0);
        atomic_set(&teal_daemon_tgid, 0);
        /* FAST PATHの旧チケット/Self-Bakingを即時失効する。 */
        atomic_set(&teal_current_epoch, 0);
        disconnected = true;
    }
    spin_unlock_irqrestore(&teal_daemon_state_lock, flags);

    if (disconnected) {
        pr_info("TEAL: teald portid=%u disconnected\n", n->portid);
        schedule_work(&teal_daemon_disconnect_work);
    }
    return NOTIFY_DONE;
}

static struct notifier_block teal_nl_nb = {
    .notifier_call = teal_nl_notifier,
};

/*
 * コマンド: TEAL_CMD_APPROVE
 */
static int teal_nl_recv_approve(struct sk_buff *skb, struct genl_info *info)
{
    u64 trans_id;
    int rc;

    /* 送信元認証 */
    rc = teal_nl_check_authorized(info);
    if (rc)
        return rc;

    if (!info->attrs[TEAL_ATTR_TRANS_ID])
        return -EINVAL;

    trans_id = nla_get_u64(info->attrs[TEAL_ATTR_TRANS_ID]);
    
    /* 既存の handle_approve_deny 関数をそのまま再利用 */
    return handle_approve_deny(trans_id, true);
}

/*
 * コマンド: TEAL_CMD_DENY
 */
static int teal_nl_recv_deny(struct sk_buff *skb, struct genl_info *info)
{
    u64 trans_id;
    int rc;

    /* 送信元認証 */
    rc = teal_nl_check_authorized(info);
    if (rc)
        return rc;

    if (!info->attrs[TEAL_ATTR_TRANS_ID])
        return -EINVAL;

    trans_id = nla_get_u64(info->attrs[TEAL_ATTR_TRANS_ID]);
    
    return handle_approve_deny(trans_id, false);
}

/*
 * コマンド: TEAL_CMD_TICKET_ADD
 * 従来の sscanf による文字解析を完全に廃止し、バイナリ属性から直接読み出す。
 */
static int teal_nl_recv_ticket_add(struct sk_buff *skb, struct genl_info *info)
{
    struct teal_ticket_add_payload *ticket;
    int rc;

    /* 送信元認証 */
    rc = teal_nl_check_authorized(info);
    if (rc)
        return rc;

    /* 必須属性がすべて揃っているかチェック */
    if (!info->attrs[TEAL_ATTR_UID] ||
        !info->attrs[TEAL_ATTR_OP] ||
        !info->attrs[TEAL_ATTR_PROG_INO] ||
        !info->attrs[TEAL_ATTR_PROG_DEV] ||
        !info->attrs[TEAL_ATTR_TARGET_INO] ||
        !info->attrs[TEAL_ATTR_TARGET_DEV] ||
        !info->attrs[TEAL_ATTR_EXPIRES_AT] ||
        !info->attrs[TEAL_ATTR_TICKET_ID] ||
        !info->attrs[TEAL_ATTR_EPOCH] ||
        !info->attrs[TEAL_ATTR_SCRIPT_DEV] ||
        !info->attrs[TEAL_ATTR_SCRIPT_INO] ||
        !info->attrs[TEAL_ATTR_APPLET_HASH] ||
        !info->attrs[TEAL_ATTR_USES_LEFT] ||
        !info->attrs[TEAL_ATTR_AUDIT_FLG]
    ) {
        pr_warn("TEAL: TICKET_ADD missing required attributes\n");
        return -EINVAL;
    }

    ticket = kzalloc(sizeof(*ticket), GFP_KERNEL);
    if (!ticket)
        return -ENOMEM;

    /* TLVから値を安全に抽出（コロンやスペースのパースは一切不要！） */
    ticket->uid          = nla_get_u32(info->attrs[TEAL_ATTR_UID]);
    ticket->op           = nla_get_u32(info->attrs[TEAL_ATTR_OP]);
    
    ticket->org.dev      = nla_get_u32(info->attrs[TEAL_ATTR_PROG_DEV]);
    ticket->org.ino      = nla_get_u64(info->attrs[TEAL_ATTR_PROG_INO]);
    
    ticket->script.dev   = nla_get_u32(info->attrs[TEAL_ATTR_SCRIPT_DEV]);
    ticket->script.ino   = nla_get_u64(info->attrs[TEAL_ATTR_SCRIPT_INO]);
    
    ticket->applet_hash  = nla_get_u64(info->attrs[TEAL_ATTR_APPLET_HASH]);
    
    ticket->obj.dev      = nla_get_u32(info->attrs[TEAL_ATTR_TARGET_DEV]);
    ticket->obj.ino      = nla_get_u64(info->attrs[TEAL_ATTR_TARGET_INO]);

    // 移動先の取得
    // リネーム以外の操作では送られてこない（属性がNULLの）可能性があるため、安全にチェックして取得
    if (info->attrs[TEAL_ATTR_NEW_TARGET_DEV]) {
        ticket->new_obj.dev = nla_get_u32(info->attrs[TEAL_ATTR_NEW_TARGET_DEV]);
    } else {
        ticket->new_obj.dev = 0;
    }
    if (info->attrs[TEAL_ATTR_NEW_TARGET_INO]) {
        ticket->new_obj.ino = nla_get_u64(info->attrs[TEAL_ATTR_NEW_TARGET_INO]);
    } else {
        ticket->new_obj.ino = 0;
    }

    ticket->expires_at   = nla_get_u64(info->attrs[TEAL_ATTR_EXPIRES_AT]);
    atomic_set(&ticket->uses_left, nla_get_u32(info->attrs[TEAL_ATTR_USES_LEFT]));
    ticket->ticket_id    = nla_get_u64(info->attrs[TEAL_ATTR_TICKET_ID]);  // 仕様上は u64 だが構造体が u32 の場合キャスト
    ticket->epoch        = nla_get_u32(info->attrs[TEAL_ATTR_EPOCH]);
    ticket->audit_flags  = nla_get_u32(info->attrs[TEAL_ATTR_AUDIT_FLG]);

    if (info->attrs[TEAL_ATTR_FLAGS]) {
        ticket->flags = nla_get_u32(info->attrs[TEAL_ATTR_FLAGS]);
    } else {
        ticket->flags = 0; // 属性が無い場合は安全側に倒す
    }

    /* 既存の登録処理へ流す */
    return handle_ticket_add(ticket);
}

/*
 * コマンド: TEAL_CMD_MODE_SWITCH
 * teald から START (ENFORCE) / STOP (AUDIT) のモード切り替えを受け取る。
 */
static int teal_nl_recv_mode_switch(struct sk_buff *skb, struct genl_info *info)
{
    u32 mode;
    int rc;

    /* 送信元認証 */
    rc = teal_nl_check_authorized(info);
    if (rc)
        return rc;

    /* モードフラグが属性として含まれているかチェック */
    if (!info->attrs[TEAL_ATTR_FLAGS])
        return -EINVAL;

    mode = nla_get_u32(info->attrs[TEAL_ATTR_FLAGS]); // 0: AUDIT, 1: ENFORCE

    /* Rust側のコンフィギュレータを呼び出し、システム全体のモードを更新 */
    if (teal_configurator) {
        teal_configurator(mode);
        pr_info("TEAL: Mode switched to %s by teald.\n", mode == 1 ? "ENFORCE" : "AUDIT");
    } else {
        pr_warn("TEAL: Mode switch requested, but no configurator registered.\n");
    }

    return 0;
}

/*
 * コマンド: TEAL_CMD_POLICY_UPDATE
 * teald から新しい Epoch を受け取り、カーネル内のチケットキャッシュおよび
 * 保留中リクエストキューを一括フラッシュして Fast Path を初期化する。
 */
static int teal_nl_recv_policy_update(struct sk_buff *skb,
                                       struct genl_info *info)
{
    unsigned long flags;
    u32 new_epoch, old_epoch;
    int rc;

    rc = teal_nl_check_authorized(info);
    if (rc)
        return rc;
    if (!info->attrs[TEAL_ATTR_EPOCH])
        return -EINVAL;

    new_epoch = nla_get_u32(info->attrs[TEAL_ATTR_EPOCH]);
    mutex_lock(&teal_ticket_update_mutex);

    old_epoch = (u32)atomic_read(&teal_current_epoch);
    /* 0(未同期)からもlast_epoch+1のみ許す。旧番号を再使用しない。 */
    if (new_epoch == 0 || teal_last_epoch == U32_MAX ||
        new_epoch != teal_last_epoch + 1) {
        rc = -EINVAL;
        goto out_unlock;
    }

    /* 切断との競合に備え、セッションの照合とEpoch公開を
     * notifierと同じspinlockで不可分に行う。
     */
    spin_lock_irqsave(&teal_daemon_state_lock, flags);
    if (genl_info_net(info) != &init_net ||
        (u32)atomic_read(&teal_daemon_portid) != info->snd_portid) {
        rc = -ENOTCONN;
    } else {
        teal_last_epoch = new_epoch;
        atomic_set(&teal_current_epoch, new_epoch);
        rc = 0;
    }
    spin_unlock_irqrestore(&teal_daemon_state_lock, flags);
    if (rc)
        goto out_unlock;

    teal_flush_all_queues_locked();
    pr_info("TEAL: Policy epoch %u -> %u\n", old_epoch, new_epoch);

out_unlock:
    mutex_unlock(&teal_ticket_update_mutex);
    return rc;
}

// ==========================================
// TEAL Generic Netlink: 送信 (Kernel -> User)
// ==========================================

static atomic_t teal_nl_seq = ATOMIC_INIT(0); // カーネル発信メッセージのシーケンス番号

/*
 * 【送信ヘルパー】REQ (承認依頼 / 監査ログ) メッセージの送信
 * 対象: Slow Path (ENFORCEモードの判定待ち、およびAUDITモードのログ送出)
 */
static int teal_genl_send_req(struct teal_request *req, u8 teal_mode)
{
    struct sk_buff *skb;
    void *hdr;
    u32 portid = atomic_read(&teal_daemon_portid);
    int rc;

    /* teald が未接続の場合は送信しない（Fail-Safeモード処理へ委ねる） */
    if (portid == 0) {
        pr_debug("TEAL: No daemon registered. Allowing request by default.\n");
        return -ENOTCONN;
    }

    /* メッセージバッファの確保 (最大属性サイズを見積もって NLMSG_DEFAULT_SIZE を使用) */
    skb = genlmsg_new(NLMSG_DEFAULT_SIZE, GFP_ATOMIC);
    if (!skb)
        return -ENOMEM;

    /* Netlinkヘッダの構築 (Command: TEAL_CMD_REQ) */
    hdr = genlmsg_put(skb, 0, atomic_inc_return(&teal_nl_seq), &teal_nl_family, 0, TEAL_CMD_REQ);
    if (!hdr) {
        nlmsg_free(skb);
        return -EMSGSIZE;
    }

    /* TLVデータのパッキング (文字列のエスケープ不要！) */
    nla_put_u64_64bit(skb, TEAL_ATTR_TRANS_ID, req->id, TEAL_ATTR_UNSPEC);
    nla_put_u32(skb, TEAL_ATTR_PID, req->pid);
    nla_put_u32(skb, TEAL_ATTR_PPID, req->ppid);
    nla_put_u32(skb, TEAL_ATTR_SESSIONID, req->sessionid);
    nla_put_u32(skb, TEAL_ATTR_UID, req->uid);
    nla_put_u32(skb, TEAL_ATTR_GID, req->gid);
    
    nla_put_u32(skb, TEAL_ATTR_PROG_DEV, req->prog_dev);
    nla_put_u64_64bit(skb, TEAL_ATTR_PROG_INO, req->prog_ino, TEAL_ATTR_UNSPEC);
    nla_put_string(skb, TEAL_ATTR_PROGRAM, req->program[0] ? req->program : "-");
    
    nla_put_u32(skb, TEAL_ATTR_TARGET_DEV, req->target_dev);
    nla_put_u64_64bit(skb, TEAL_ATTR_TARGET_INO, req->target_ino, TEAL_ATTR_UNSPEC);
    nla_put_string(skb, TEAL_ATTR_TARGET, req->target[0] ? req->target : "-");

    // RENAME用の移動先コンテキストをパッキング
    nla_put_u32(skb, TEAL_ATTR_NEW_TARGET_DEV, req->new_target_dev);
    nla_put_u64_64bit(skb, TEAL_ATTR_NEW_TARGET_INO, req->new_target_ino, TEAL_ATTR_UNSPEC);
    nla_put_string(skb, TEAL_ATTR_NEW_TARGET, req->new_target[0] ? req->new_target : "-");

    nla_put_u32(skb, TEAL_ATTR_SCRIPT_DEV, req->script_dev);
    nla_put_u64_64bit(skb, TEAL_ATTR_SCRIPT_INO, req->script_ino, TEAL_ATTR_UNSPEC);
    nla_put_string(skb, TEAL_ATTR_SCRIPT, req->script[0] ? req->script : "-");
    
    nla_put_string(skb, TEAL_ATTR_APPLET, req->applet[0] ? req->applet : "-");
    nla_put_string(skb, TEAL_ATTR_ACTION, req->action[0] ? req->action : "-");
    
    /* Alpha版のダミー送信 */
    nla_put_string(skb, TEAL_ATTR_LSM_LABEL, "-");
    nla_put_string(skb, TEAL_ATTR_ARGS_HEAD, req->args_head[0] ? req->args_head : "");
    
    nla_put_u32(skb, TEAL_ATTR_FLAGS, req->flags);

    // ========================================================================
    // カレントプロセスからのTTY情報の安全な抽出とパッキング
    // ========================================================================
    struct tty_struct *tty = get_current_tty();
    if (tty) {
        // tty_name() は文字列(const char *)を直接返す
        const char *t_name = tty_name(tty);

        // 文字列としてNetlinkパケットに詰め込む (安全のためNULLチェックを入れる)
        nla_put_string(skb, TEAL_ATTR_SESSION_TTY, t_name ? t_name : "");

        // ★超重要: get_current_tty() で取得した参照カウントを必ず減らす！
        tty_kref_put(tty); 
    } else {
        // TTYを持たないバックグラウンドプロセス (cron, デーモン等) の場合は空文字列を送る
        nla_put_string(skb, TEAL_ATTR_SESSION_TTY, "");
    }
    // ========================================================================

    genlmsg_end(skb, hdr);

    /* teald のポートへ直接発射 (Unicast) */
    rc = genlmsg_unicast(&init_net, skb, portid);
    return rc;
}

/*
 * 【送信ヘルパー】INFO (チケット消費・期限切れ) メッセージの送信
 * 対象: Fast Path (CONSUMED / EXPIRED)
 */
static int teal_genl_send_info(struct teal_log_entry *log)
{
    struct sk_buff *skb;
    void *hdr;
    u32 portid = atomic_read(&teal_daemon_portid);
    int rc;

    if (portid == 0)
        return -ESRCH;

    /* Fast Path から呼ばれるため、GFP_ATOMIC で高速に確保 */
    skb = genlmsg_new(NLMSG_DEFAULT_SIZE, GFP_ATOMIC);
    if (!skb)
        return -ENOMEM;

    hdr = genlmsg_put(skb, 0, atomic_inc_return(&teal_nl_seq), &teal_nl_family, 0, TEAL_CMD_INFO);
    if (!hdr) {
        nlmsg_free(skb);
        return -EMSGSIZE;
    }

    /* 文字列（パス）を含めず、IDと数値のみで構成された軽量なパッキング */
    nla_put_u8(skb, TEAL_ATTR_INFO_EVT, (log->type == TICKET_CONSUMED) ? 0 : 1);
    nla_put_u64_64bit(skb, TEAL_ATTR_TICKET_ID, log->ticket_id, TEAL_ATTR_UNSPEC);
    nla_put_u32(skb, TEAL_ATTR_UID, log->uid);
    nla_put_u32(skb, TEAL_ATTR_USES_LEFT, log->uses_left_snapshot);
    
    nla_put_u32(skb, TEAL_ATTR_PROG_DEV, log->org_dev);
    nla_put_u64_64bit(skb, TEAL_ATTR_PROG_INO, log->org_ino, TEAL_ATTR_UNSPEC);
    nla_put_u32(skb, TEAL_ATTR_TARGET_DEV, log->obj_dev);
    nla_put_u64_64bit(skb, TEAL_ATTR_TARGET_INO, log->obj_ino, TEAL_ATTR_UNSPEC);
    nla_put_u32(skb, TEAL_ATTR_NEW_TARGET_DEV, log->new_obj_dev);
    nla_put_u64_64bit(skb, TEAL_ATTR_NEW_TARGET_INO, log->new_obj_ino, TEAL_ATTR_UNSPEC);

    genlmsg_end(skb, hdr);

    rc = genlmsg_unicast(&init_net, skb, portid);
    return rc;
}

// --- LSM フック実装 ---

static atomic_t teal_disabled = ATOMIC_INIT(0);

static inline bool teal_is_disabled(void)
{
    return atomic_read(&teal_disabled) != 0;
}

static inline void teal_disable_once(const char *why)
{
    if (atomic_cmpxchg(&teal_disabled, 0, 1) == 0) {
        pr_err("TEAL: disabled for safety: %s\n", why);
        pr_err("TEAL: TEAL is configured as a standalone LSM. "
               "Do not stack with other LSMs that use task->security.\n");
    }
}

// ------------------------------
// bypass 判定
// ------------------------------

static inline bool teal_should_bypass_current(void)
{
    int dtgid = atomic_read(&teal_daemon_tgid);
    if (dtgid > 0 && (int)current->tgid == dtgid)
        return true;
    if (current->flags & PF_KTHREAD)
        return true;
    return false;
}

static inline bool teal_should_bypass_all(void)
{
    struct file *exe;

    if (teal_is_disabled()) return true;
    if (!READ_ONCE(teal_decision_maker)) {
        return true;
    }
    if (teal_should_bypass_current()) return true;

    // 実行元を持たない特殊コンテキスト（終了処理中など）は保護対象外として許可
    exe = get_task_exe_file(current);
    if (!exe) return true;
    fput(exe);  // チェックするだけなのでスグ返す

    return false;
}

static bool is_ticket_matched(struct teal_ticket_add_payload *ticket, u64 now,
                             struct inode *obj_inode, struct teal_id_pair *org_id,
                             enum teal_event_type ev, struct teal_id_pair *new_id)
{
    u32 current_epoch = (u32)atomic_read(&teal_current_epoch);

    if (current_epoch == 0 ||
        READ_ONCE(ticket->epoch) != current_epoch) {
        return false;
    }

    // A) 有効期限チェック
    if (now > ticket->expires_at) {
        return false;
    }

    // B) 回数制限チェック (0なら無効)
    if (atomic_read(&ticket->uses_left) == 0) {
        return false;
    }

    // C) UID チェック
    // ★ silent_io 特権チケット、または UID がワイルドカード (0xFFFFFFFF) の場合は不問とする
    bool is_wildcard_uid = (ticket->uid == (u32)-1);
    bool is_silent_io    = (ticket->flags & TEAL_TICKET_FLG_SILENT_IO);

    if (!is_wildcard_uid && !is_silent_io) {
        if (ticket->uid != from_kuid(current_user_ns(), current_uid())) {
            return false;
        }
    }

    // D) Operation チェック
    if ((ticket->op & ev) == 0) {
        return false;
    }

    // E) Object (ターゲットファイル) の一致確認
    if (ticket->obj.ino != obj_inode->i_ino || 
        ticket->obj.dev != obj_inode->i_sb->s_dev) {
        return false;
    }

    // E-2) evがTEAL_EVENT_RENAMEの時は、移動先の識別子も一致確認を行う
    if (ev == TEAL_EVENT_RENAME) {
        // 呼び出し側から移動先の情報が提供されていない、もしくはチケット側に移動先情報がセットされていない場合は不一致
        if (!new_id || ticket->new_obj.ino == 0 || ticket->new_obj.dev == 0)
            return false;

        if (ticket->new_obj.ino != new_id->ino ||
            ticket->new_obj.dev != new_id->dev)
            return false;
    }

    // F) Origin (実行プロセス) の一致確認
    if (ticket->org.ino != org_id->ino || 
        ticket->org.dev != org_id->dev) {
        return false;
    }

    // G) Script の一致確認
    if (ticket->script.ino != 0 && ticket->script.dev != 0) {
        pr_warn_ratelimited("TEAL: Script support will be implemented in the Beta version.");
        return false; 
    }

    return true;
}

#define TEAL_TICKET_FLG_PARENT_MATCH  (1U << 4) // 親ディレクトリ包括チケットフラグ

/**
 * __check_ticket_for_inode - 特定の1つの inode に対するチケット検索・消費処理
 * @is_parent_check: 親ディレクトリとしての照合かどうかのフラグ
 */
static bool __check_ticket_for_inode(struct inode *target_inode, enum teal_event_type ev,
                                     struct teal_id_pair *new_id, bool is_parent_check)
{
    struct teal_task_meta *meta;
    struct teal_id_pair *org_id;
    struct teal_id_pair key;
    struct rhlist_head *list, *tmp;
    struct teal_inode_cache *entry;
    u64 now;
    bool match = false;

    if (!target_inode) return false;

    meta = teal_task_meta_current();
    if (!meta) return false;
    org_id = &meta->program_id;

    now = ktime_get_real_seconds();

    key.dev = target_inode->i_sb->s_dev;
    key.ino = target_inode->i_ino;

    rcu_read_lock();
    list = rhltable_lookup(&teal_ticket_ht, &key, teal_cache_params);

    rhl_for_each_entry_rcu(entry, tmp, list, node) {
        struct teal_ticket_add_payload *ticket = entry->ticket;

        if (is_parent_check &&
            !(ticket->flags & TEAL_TICKET_FLG_PARENT_MATCH))
            continue;

        if (!is_ticket_matched(ticket, now, target_inode,
                               org_id, ev, new_id))
            continue;

        if (ticket->ticket_id == 0) {
            /* EXECチケットで旧タスクへ権限を焼き付けない */
            if (ev != TEAL_EVENT_EXECUTE)
                teal_bake_ticket_flags(ticket);
            match = true;
            break;
        }

        int current_uses =
            atomic_dec_if_positive(&ticket->uses_left);

        if (current_uses >= 0) {
            /* EXECはexec確定後に旧権限を全クリアする */
            if (ev != TEAL_EVENT_EXECUTE)
                teal_bake_ticket_flags(ticket);
            match = true;

            if (entry->ticket->audit_flags == 2 || 
               (entry->ticket->audit_flags == 0 && current_uses == 0)) {
                struct teal_log_entry *log = kmalloc(sizeof(*log), GFP_ATOMIC);
                if (log) {
                    log->type = TICKET_CONSUMED;
                    log->ticket_id = entry->ticket->ticket_id;
                    log->uid = entry->ticket->uid;
                    log->uses_left_snapshot = (u32)current_uses;
                    log->timestamp = now;
                    log->org_ino = entry->ticket->org.ino;
                    log->org_dev = entry->ticket->org.dev;
                    log->obj_ino = entry->ticket->obj.ino;
                    log->obj_dev = entry->ticket->obj.dev;
                    log->new_obj_ino = entry->ticket->new_obj.ino;
                    log->new_obj_dev = entry->ticket->new_obj.dev;

                    teal_genl_send_info(log);
                    kfree(log);
                }
            }
            break;
        }
    }
    rcu_read_unlock();

    return match;
}

#define TEAL_MAX_PARENT_TRAVERSE 8  // 遡る親階層の最大深さ（4〜8階層）

/**
 * teal_check_ticket_match - ターゲット自身および親ディレクトリ群（最大8階層）のチケットを検証
 * @obj_inode: アクセス対象ファイルの inode
 * @dentry: 対象ファイルの dentry（親を遡るために使用。NULL の場合は自身のみ照合）
 * @ev: イベントタイプ
 * @new_id: リネーム用 (通常は NULL)
 */
static bool teal_check_ticket_match(struct inode *obj_inode, struct dentry *dentry,
                                    enum teal_event_type ev, struct teal_id_pair *new_id)
{
    // 1. ファイル自身のチケット照合 (最優先・O(1))
    if (__check_ticket_for_inode(obj_inode, ev, new_id, false)) {
        return true;
    }

    // 2. ヒットしなかった場合、親・祖父・曾祖父ディレクトリ...の包括チケット照合
    if (dentry) {
        struct dentry *curr = dentry;
        int depth = 0;

        // ルートに達するか、上限（8階層）に達するまで親を辿る
        while (curr && !IS_ROOT(curr) && depth < TEAL_MAX_PARENT_TRAVERSE) {
            struct dentry *parent = curr->d_parent;
            struct inode *p_inode;

            if (!parent || parent == curr)
                break;

            p_inode = d_inode(parent);
            if (p_inode && p_inode != obj_inode) {
                // 親包括フラグ (TEAL_TICKET_FLG_PARENT_MATCH) を持つチケットと照合
                if (__check_ticket_for_inode(p_inode, ev, new_id, true)) {
                    return true; // 包括許可ヒット！即時 Fast Path 通過
                }
            }

            curr = parent;
            depth++;
        }
    }

    return false;
}

static DECLARE_DELAYED_WORK(teal_gc_work, teal_gc_worker);

// GCワーカー関数の本体
static void teal_gc_worker(struct work_struct *work)
{
    struct teal_ticket_add_payload *ticket, *tmp;
    struct teal_log_entry *log;
    struct teal_log_entry *log_tmp;
    LIST_HEAD(log_list);

    u64 now = ktime_get_real_seconds();
    u32 current_epoch;

    /*
     * TICKET_ADD / POLICY_UPDATE / GC の直列化
     */
    mutex_lock(&teal_ticket_update_mutex);

    current_epoch = (u32)atomic_read(&teal_current_epoch);

    list_for_each_entry_safe(ticket, tmp, &teal_ticket_list, list) {

        bool epoch_mismatch =
            ticket->epoch != current_epoch;

        bool expired =
            now > ticket->expires_at;

        bool consumed =
            atomic_read(&ticket->uses_left) == 0;

        if (!epoch_mismatch && !expired && !consumed)
            continue;

        /*
         * 有効期限切れの場合のみ EXPIRED ログを生成
         */
        if (!epoch_mismatch &&
            expired &&
            !consumed &&
            ticket->ticket_id != 0 &&
            ticket->audit_flags != 1) {

            log = kmalloc(sizeof(*log), GFP_ATOMIC);

            if (log) {
                memset(log, 0, sizeof(*log));

                log->type = TICKET_EXPIRED;
                log->ticket_id = ticket->ticket_id;
                log->uid = ticket->uid;
                log->uses_left_snapshot =
                    (u32)atomic_read(&ticket->uses_left);

                log->timestamp = now;

                log->org_ino = ticket->org.ino;
                log->org_dev = ticket->org.dev;

                log->obj_ino = ticket->obj.ino;
                log->obj_dev = ticket->obj.dev;

                log->new_obj_ino = ticket->new_obj.ino;
                log->new_obj_dev = ticket->new_obj.dev;

                list_add_tail(&log->list, &log_list);
            }
        }

        /*
         * ハッシュテーブルから削除
         */
        if (ticket->cache_entry) {
            struct teal_inode_cache *entry = ticket->cache_entry;
            int ret;

            ret = rhltable_remove(
                &teal_ticket_ht,
                &entry->node,
                teal_cache_params
            );

            if (ret) {
                pr_err_ratelimited(
                    "TEAL: GC rhltable_remove failed: %d\n",
                    ret
                );
                continue;
            }

            kfree_rcu(entry, rcu);
        }

        list_del(&ticket->list);
        kfree_rcu(ticket, rcu);
    }

    mutex_unlock(&teal_ticket_update_mutex);

    /*
     * Netlink送信はロック解除後に実行
     */
    list_for_each_entry_safe(log, log_tmp, &log_list, list) {
        list_del(&log->list);
        teal_genl_send_info(log);
        kfree(log);
    }

    queue_delayed_work(
        teal_wq,
        &teal_gc_work,
        msecs_to_jiffies(60000)
    );
}

/* bprm_check_securityで候補情報を記録する。実行元の現行値は触らない。 */
static void teal_exec_meta_stage(const char *program, const char *script,
                                 const char *args, dev_t prog_dev,
                                 unsigned long prog_ino)
{
    struct teal_task_meta *m = teal_task_meta_current();

    if (!m || m->magic != TEAL_TASK_META_MAGIC)
        return;

    WRITE_ONCE(m->pending_exec_valid, false);
    strscpy(m->pending_program, program ? program : "-",
            sizeof(m->pending_program));
    strscpy(m->pending_script, script ? script : "-",
            sizeof(m->pending_script));
    strscpy(m->pending_args, args ? args : "-",
            sizeof(m->pending_args));
    m->pending_program_id.dev = prog_dev;
    m->pending_program_id.ino = prog_ino;
    m->pending_script_id.dev = 0;
    m->pending_script_id.ino = 0;
    WRITE_ONCE(m->pending_exec_valid, true);
}

/* 資格情報がcommitされた実行移行時にのみ、旧権限を失効させる。 */
static void teal_bprm_committed_creds(const struct linux_binprm *bprm)
{
    struct teal_task_meta *m = teal_task_meta_current();

    if (!m || m->magic != TEAL_TASK_META_MAGIC)
        return;

    /* execによる別プログラムへのSelf-Baking権限の持ち越しを禁止 */
    atomic64_set(&m->privilege_state, 0);

    if (READ_ONCE(m->pending_exec_valid)) {
        strscpy(m->program, m->pending_program, sizeof(m->program));
        strscpy(m->script, m->pending_script, sizeof(m->script));
        strscpy(m->args_head, m->pending_args, sizeof(m->args_head));
        m->program_id = m->pending_program_id;
        m->script_id = m->pending_script_id;
    } else {
        /* check hookを通らない特殊経路のフェイルセーフ */
        struct inode *inode = bprm && bprm->file ?
                              file_inode(bprm->file) : NULL;
        strscpy(m->program, bprm && bprm->filename ?
                bprm->filename : "-", sizeof(m->program));
        strscpy(m->script, "-", sizeof(m->script));
        strscpy(m->args_head, "-", sizeof(m->args_head));
        m->program_id.dev = inode ? inode->i_sb->s_dev : 0;
        m->program_id.ino = inode ? inode->i_ino : 0;
        m->script_id.dev = 0;
        m->script_id.ino = 0;
    }

    WRITE_ONCE(m->pending_exec_valid, false);
}

static int teal_task_alloc(
    struct task_struct *task,
    unsigned long clone_flags)
{
    struct teal_task_meta *child_m;
    struct teal_task_meta *parent_m;
    u64 parent_state;
    u32 parent_epoch;
    u32 parent_flags;
    u32 current_epoch;

    child_m = teal_task_meta_of(task);
    if (!child_m)
        return -ENOMEM;

    parent_m = teal_task_meta_current();

    /*
     * LSMが割り当てたTEAL領域を初期化
     * task->security自体は変更しない
     */
    memset(child_m, 0, sizeof(*child_m));

    child_m->magic = TEAL_TASK_META_MAGIC;

    strscpy(child_m->program, "-",
            sizeof(child_m->program));
    strscpy(child_m->script, "-",
            sizeof(child_m->script));
    strscpy(child_m->args_head, "-",
            sizeof(child_m->args_head));

    atomic64_set(&child_m->privilege_state, 0);

    /*
     * 親タスクから実行元情報を継承
     */
    if (parent_m &&
        parent_m->magic == TEAL_TASK_META_MAGIC) {

        strscpy(child_m->program,
                parent_m->program,
                sizeof(child_m->program));

        strscpy(child_m->script,
                parent_m->script,
                sizeof(child_m->script));

        strscpy(child_m->args_head,
                parent_m->args_head,
                sizeof(child_m->args_head));

        child_m->program_id = parent_m->program_id;
        child_m->script_id = parent_m->script_id;

        /*
         * Self-Baking権限の継承
         */
        parent_state =
            (u64)atomic64_read(
                &parent_m->privilege_state);

        parent_epoch = (u32)(parent_state >> 32);
        parent_flags = (u32)parent_state;

        current_epoch =
            (u32)atomic_read(&teal_current_epoch);

        if (current_epoch != 0 &&
            parent_epoch == current_epoch &&
            (parent_flags & TEAL_TICKET_FLG_INHERIT)) {

            atomic64_set(
                &child_m->privilege_state,
                parent_state
            );
        }
    }

    return 0;
}

static void teal_get_bprm_args_head(struct linux_binprm *bprm, char *out, size_t out_len)
{
    int ret;
    int argc;
    size_t i;

    if (!out || out_len == 0)
        return;

    out[0] = '\0';
    if (!bprm || bprm->argc <= 0 || !bprm->mm) {
        strscpy(out, "-", out_len);
        return;
    }

    /*
     * bprm_check 時点の current->mm は親プロセス (bash 等) のままなので、
     * copy_from_user ではなく、新プロセスの bprm->mm を直接読み出せる access_remote_vm を使う。
     */
    ret = access_remote_vm(bprm->mm, bprm->p, out, out_len - 1, 0);
    if (ret <= 0) {
        strscpy(out, "-", out_len);
        return;
    }

    out[ret] = '\0';

    /*
     * スタック上の引数は "arg0\0arg1\0arg2\0..." と連続して格納されている。
     * argc 個分の境界 '\0' をスペース ' ' に置き換えて 1 つの引数文字列に整形する。
     */
    argc = bprm->argc;
    for (i = 0; i < (size_t)ret - 1; i++) {
        if (out[i] == '\0') {
            argc--;
            if (argc <= 0) {
                /* 全引数の終端に到達（環境変数領域まで巻き込まないようにここで打ち切る） */
                out[i] = '\0';
                break;
            }
            out[i] = ' ';
        }
    }
    out[out_len - 1] = '\0';
}

static int teal_bprm_check(struct linux_binprm *bprm)
{
    int rc = 0;
    char args_buf[TEAL_ARGS_MAX] = "-";
    char *buf = NULL;
    const char *target = "unknown";
    const char *exec_path = "-";
    const char *script_path = "-";
    dev_t prog_dev = 0;
    unsigned long prog_ino = 0;
    struct teal_task_meta *meta;
    struct teal_rs_ctx rctx;

    if (!bprm || !bprm->file)
        return 0;

    /* check時点の実行元を保持してEXEC判定に使う */
    meta = teal_task_meta_current();
    if (meta && meta->magic == TEAL_TASK_META_MAGIC) {
        exec_path = meta->program;
        script_path = meta->script;
    }

    prog_dev = file_inode(bprm->file)->i_sb->s_dev;
    prog_ino = file_inode(bprm->file)->i_ino;

    buf = __getname();
    if (buf) {
        char *p = d_path(&bprm->file->f_path, buf, PATH_MAX);
        if (!IS_ERR(p))
            target = p;
    } else if (bprm->filename) {
        target = bprm->filename;
    }

    teal_get_bprm_args_head(bprm, args_buf, sizeof(args_buf));

    if (!teal_should_bypass_all() &&
        !teal_check_ticket_match(file_inode(bprm->file), NULL,
                                 TEAL_EVENT_EXECUTE, NULL)) {
        rctx.target = target;
        rctx.program = exec_path;
        rctx.script = script_path;
        rctx.args = args_buf;
        rctx.target_dev = prog_dev;
        rctx.target_ino = prog_ino;

        rc = teal_decision_maker(TEAL_EVENT_EXECUTE, (void *)&rctx);
    }

    if (rc == 0) {
        /* 複数回checkされた場合は最後の許可候補で更新する */
        teal_exec_meta_stage(target, "-", args_buf, prog_dev, prog_ino);
    } else if (meta && meta->magic == TEAL_TASK_META_MAGIC) {
        WRITE_ONCE(meta->pending_exec_valid, false);
    }

    if (buf)
        __putname(buf);
    return rc;
}

static inline int teal_event_from_file_open(const struct file *file, enum teal_event_type *out_ev)
{
    if (file->f_mode & FMODE_WRITE) {
        *out_ev = TEAL_EVENT_WRITE;
        return 0;
    }
    if (file->f_mode & FMODE_READ) {
        *out_ev = TEAL_EVENT_READ;
        return 0;
    }
    return -EINVAL;
}

static inline void teal_free_path_buf(char *buf)
{
    if (buf)
        __putname(buf);
}

static inline char *teal_resolve_path_alloc(const struct file *file, char **out_buf)
{
    char *buf = __getname();
    char *p;

    if (!buf)
        return ERR_PTR(-ENOMEM);

    p = d_path(&file->f_path, buf, PATH_MAX);
    if (IS_ERR(p)) {
        __putname(buf);
        return p; 
    }

    *out_buf = buf;
    return p;
}

#include <linux/magic.h>

static int teal_file_open(struct file *file)
{
    int rc = 0;
    enum teal_event_type ev;
    const char *exec_path = "-";
    const char *script_path = "-";
    char *buf = NULL;
    const char *target_path = "unknown";
    
    struct inode *inode;
    dev_t target_dev = 0;
    unsigned long target_ino = 0;

    // ==========================================================
    // 0. 最優先: TEAL全体がバイパスモードなら一切の処理をスキップ
    // ==========================================================
    if (teal_should_bypass_all()) return 0;

    if (!file) return 0;
    inode = file_inode(file);
    if (!inode || !inode->i_sb) return 0;

    // 対象のファイルシステム(マジックナンバー)を取得
    unsigned long magic = inode->i_sb->s_magic;

    // ==========================================================
    // 【Tier 1】全プロセス無条件バイパス (システム維持のため必須)
    // ==========================================================
    if (magic == PIPEFS_MAGIC || magic == ANON_INODE_FS_MAGIC ||
        (S_ISCHR(inode->i_mode) && MAJOR(inode->i_rdev) == 1 && 
         (MINOR(inode->i_rdev) == 3 || MINOR(inode->i_rdev) == 5 || MINOR(inode->i_rdev) == 7))) {
        /* 
         * 1:3 = /dev/null
         * 1:5 = /dev/zero
         * 1:7 = /dev/full
         * これらは情報漏洩やシステム破壊のリスクがないため無条件許可する。
         */
        return 0; 
    }

    // ==========================================================
    // 【Tier 2】SILENT_IO 特権プロセス専用バイパス (v1.9)
    // ==========================================================
    if (teal_get_active_ticket_flags() &
        TEAL_TICKET_FLG_SILENT_IO) {

        if (magic == TMPFS_MAGIC ||      // /tmp, /dev/shm 等
            magic == SOCKFS_MAGIC ||     // UNIXドメインソケット等
            magic == PROC_SUPER_MAGIC || // /proc へのアクセスを特権プロセスのみバイパス
            (file->f_flags & O_TMPFILE)) // 匿名一時ファイル作成フラグ
        {
            /*
             * 共有空間の一時ファイルやソケットは通常監視するが、
             * SILENT_IO 特権を持つ安全な巨大プロセス(soffice.bin等)のみ
             * 即座に許可し、ログストームを防ぐ。
             */
            return 0; 
        }
    }

    // ==========================================================
    // 3. 従来のキャッシュ判定 (D-000000 や 通常の許可キャッシュ)
    // ==========================================================
    if (teal_event_from_file_open(file, &ev) != 0) {
        return 0; 
    }

    // ★ dentry を渡すことで、内部で自身＋最大8階層の親を高速検証
    if (teal_check_ticket_match(inode, file->f_path.dentry, ev, NULL)) {
        return 0; // キャッシュヒットにより即時許可！
    }

    // ==========================================================
    // 4. Slow Path (パスを解決して teald へ送信)
    // ==========================================================
    const char *args = "-";
    struct teal_task_meta *meta = teal_task_meta_current();
    if (meta) {
        if (meta->program[0] != '\0')   exec_path = meta->program;
        if (meta->script[0] != '\0')    script_path = meta->script;
        if (meta->args_head[0] != '\0') args = meta->args_head;
    }

    char *p = teal_resolve_path_alloc(file, &buf); 
    if (!IS_ERR_OR_NULL(p)) {
        target_path = p;
    }

    // 上で inode は取得済みなので再利用
    target_dev = inode->i_sb->s_dev;
    target_ino = inode->i_ino;

    struct teal_rs_ctx rctx = {
        .target     = target_path,
        .program    = exec_path,
        .script     = script_path,
        .args       = args,
        .target_dev = target_dev,
        .target_ino = target_ino,
    };
    
    rc = teal_decision_maker(ev, (void *)&rctx);

    if (buf) {
        teal_free_path_buf(buf);
    }
    
    return rc;
}

static int teal_sockaddr_to_string(const struct sockaddr *sa, int addrlen,
                                   char *out, size_t out_len)
{
    if (!out || out_len == 0)
        return -EINVAL;

    strscpy(out, "-", out_len);

    if (!sa || addrlen < sizeof(struct sockaddr))
        return -EINVAL;

    switch (sa->sa_family) {
    case AF_INET: {
        const struct sockaddr_in *sin = (const struct sockaddr_in *)sa;
        char ip[INET_ADDRSTRLEN];

        snprintf(ip, sizeof(ip), "%pI4", &sin->sin_addr);
        snprintf(out, out_len, "%s:%u", ip, ntohs(sin->sin_port));
        return 0;
    }
    case AF_INET6: {
        const struct sockaddr_in6 *sin6 = (const struct sockaddr_in6 *)sa;
        char ip[INET6_ADDRSTRLEN];

        snprintf(ip, sizeof(ip), "%pI6c", &sin6->sin6_addr);
        snprintf(out, out_len, "[%s]:%u", ip, ntohs(sin6->sin6_port));
        return 0;
    }
    default:
        return -EAFNOSUPPORT;
    }
}

/**
 * ソケット接続(CONNECT)用のキャッシュ検索と自己上書き(Self-Baking)
 */
static bool teal_check_socket_ticket_match(struct socket *sock, struct sockaddr *address, int addrlen, enum teal_event_type ev)
{
    struct teal_task_meta *meta;
    struct teal_id_pair *org_id;
    struct teal_id_pair key;
    struct rhlist_head *list, *tmp;
    struct teal_inode_cache *entry;
    u64 now;
    bool match = false;

    meta = teal_task_meta_current();
    if (!meta) return false;
    org_id = &meta->program_id;
    
    now = ktime_get_real_seconds();

    // ==========================================================
    //  キャッシュキーの設定 (Network / SubjectOnly用)
    // ==========================================================
    // 現在のアーキテクチャでは、Mozc等のローカルIPCは SubjectOnly ルールとして
    // 評価され、teald は target_dev=0, target_ino=0 でチケットを発行しています。
    // そのため、まずは dev=0, ino=0 をキーとしてキャッシュを探します。
    key.dev = 0;
    key.ino = 0;

    // ==========================================================
    //  O(1) RCU 爆速検索
    // ==========================================================
    rcu_read_lock();
    list = rhltable_lookup(&teal_ticket_ht, &key, teal_cache_params);
    
    rhl_for_each_entry_rcu(entry, tmp, list, node) {

        struct teal_ticket_add_payload *ticket = entry->ticket;
        int current_uses;
        struct teal_log_entry *log;
        u32 current_epoch =
            (u32)atomic_read(&teal_current_epoch);

        if (current_epoch == 0 ||
            READ_ONCE(ticket->epoch) != current_epoch)
            continue;

        // ==========================================================
        //  安全なインライン・マッチング (obj_inode を使わない)
        // ==========================================================
        // 1. オペレーション (CONNECT) が許可されているか
        if (!(entry->ticket->op & ev)) continue;
        
        // 2. 有効期限が切れていないか
        if (entry->ticket->expires_at < now) continue;
        
        // 3. 実行元 (Mozcなど) の inode が、チケットの宛先(org)と一致するか
        if (entry->ticket->org.ino != org_id->ino || 
            entry->ticket->org.dev != org_id->dev) continue;

        // ↑ すべての条件をクリアした場合、マッチ成功！

        // ==========================================================
        // 以降は消費(Consume)ロジック
        // ==========================================================
        /* ticket_id == 0: 管理対象外 */
        if (ticket->ticket_id == 0) {
            teal_bake_ticket_flags(ticket);
            match = true;
            break;
        }

        /* 通常チケット */
        current_uses = atomic_dec_if_positive(&ticket->uses_left);

        if (current_uses >= 0) {
            teal_bake_ticket_flags(ticket);
            match = true;

            if (entry->ticket->audit_flags == 2 || (entry->ticket->audit_flags == 0 && current_uses == 0)) {
                log = kmalloc(sizeof(*log), GFP_ATOMIC);
                if (log) {
                    log->type = TICKET_CONSUMED;
                    log->ticket_id = entry->ticket->ticket_id;
                    log->uid = entry->ticket->uid;
                    log->uses_left_snapshot = (u32)current_uses;
                    log->timestamp = now;
                    log->org_ino = entry->ticket->org.ino;
                    log->org_dev = entry->ticket->org.dev;
                    
                    log->obj_ino = entry->ticket->obj.ino; 
                    log->obj_dev = entry->ticket->obj.dev;

                    // RENAME対応: ネットワーク(CONNECT)用チケットであっても、
                    // 拡張したログ構造体のメンバー(new_obj_*)を安全に初期化する。
                    // ネットワーク系のチケットでは当然 0 (None) になります。
                    log->new_obj_ino = entry->ticket->new_obj.ino;
                    log->new_obj_dev = entry->ticket->new_obj.dev;

                    teal_genl_send_info(log);
                    kfree(log);
                }
            }
            break; // ループを抜ける
        }
    }
    rcu_read_unlock();

    return match;
}

static int teal_socket_connect(struct socket *sock, struct sockaddr *address, int addrlen)
{
    int rc = 0;
    
    // ★ デフォルトの安全な値を設定
    const char *exec_path = "-";
    const char *script_path = "-";
    const char *args = "-";
    char target[128];

    // ==========================================================
    // 0. 最優先: TEAL全体がバイパスモードなら一切の処理をスキップ
    // ==========================================================
    if (teal_should_bypass_all())
        return 0;

    // ==========================================================
    // 【Tier 2】NAMELESS_IPC / SILENT_IO 特権プロセス専用バイパス
    // ==========================================================
    u32 flags = teal_get_active_ticket_flags();

    if (flags & (TEAL_TICKET_FLG_NAMELESS_IPC |
                 TEAL_TICKET_FLG_SILENT_IO)) {
        // AF_UNIX (ローカルIPC) であれば即座にバイパス
        if (sock && sock->sk && sock->sk->sk_family == AF_UNIX) {
            return 0; 
        }
    }

    // ==========================================================
    // 3. キャッシュ判定 (Fast Path) & フラグの自己上書き (Self-Baking)
    // ==========================================================
    // teald から発行された「dev=0, ino=0 (SubjectOnly)」のチケットが
    // キャッシュに存在するかどうかを確認します。
    if (teal_check_socket_ticket_match(sock, address, addrlen, TEAL_EVENT_CONNECT)) {
        return 0;
    }

    // ==========================================================
    // 4. Slow Path (パス・アドレスを解決して teald へ送信)
    // ※ ネットワークソケット(IPv4/IPv6)や、特権を持たないプロセスのIPCはここへ落ちる
    // ==========================================================

    // ★ ゼロコピーでの安全な取得
    struct teal_task_meta *meta = teal_task_meta_current();
    if (meta) {
        // NULLチェックを行い、有効ならポインタをコピー
        if (meta->program[0]) exec_path = meta->program;
        if (meta->script[0])  script_path = meta->script;
        if (meta->args_head[0]) args = meta->args_head;
    }

    // ネットワークの宛先はバッファコピーされるため常に安全
    if (teal_sockaddr_to_string(address, addrlen, target, sizeof(target)) != 0) {
        strscpy(target, "-", sizeof(target));
    }

    struct teal_rs_ctx rctx = {
        .target     = target,
        .program    = exec_path,
        .script     = script_path,
        .args       = args,
        .target_dev = 0,
        .target_ino = 0,
    };

    rc = teal_decision_maker(TEAL_EVENT_CONNECT, (void *)&rctx);
    return rc;
}

/**
 * 削除系フックの共通処理（パス解決、サブジェクト抽出、キャッシュ判定、Slow Path転送）
 */
static int teal_handle_path_deletion(const struct path *dir, struct dentry *dentry, enum teal_event_type event_type)
{
    int ret = 0;
    char *page = NULL;
    char *resolved_path = ""; 
    struct path target_path;
    struct teal_rs_ctx ctx;

    // 実行元（サブジェクト）の初期値
    const char *exec_path = "-";
    const char *script_path = "-";
    const char *args = "-";
    struct teal_task_meta *meta;

    // 1. 最優先バイパスチェック
    if (teal_should_bypass_all()) {
        return 0;
    }

    // 2. O(1) Fast Path チェック (チケットキャッシュ判定)
    if (d_is_positive(dentry)) {
        if (teal_check_ticket_match(d_inode(dentry), dentry, event_type, NULL)) {
            return 0;
        }
    }

    // --- ここから下は Slow Path（teald への問い合わせ処理） ---

    // 3. 現在のプロセス(current)の実行元プログラムおよびスクリプト情報を安全に取得
    meta = teal_task_meta_current();
    if (meta) {
        if (meta->program[0])   exec_path = meta->program;
        if (meta->script[0])    script_path = meta->script;
        if (meta->args_head[0]) args = meta->args_head;
    }

    // 4. パス解決用のメモリをヒープから安全に確保
    page = (char *)__get_free_page(GFP_KERNEL);
    if (!page) {
        pr_warn("TEAL: __get_free_page failed in path deletion hook\n");
    }

    // 5. 親のマウント情報と対象のdentryから struct path を再構成
    target_path.mnt = dir->mnt;
    target_path.dentry = dentry;

    // 絶対パスの解決
    if (page) {
        resolved_path = d_path(&target_path, page, PAGE_SIZE);
        if (IS_ERR(resolved_path)) {
            resolved_path = ""; 
        }
    }

    // 6. Rust空間（teal_rs）に引き渡す構造体の完全なパッキング
    memset(&ctx, 0, sizeof(ctx));
    ctx.target = resolved_path;
    ctx.program = exec_path;
    ctx.script = script_path;
    ctx.args = args;

    if (d_is_positive(dentry)) {
        ctx.target_dev = dentry->d_sb->s_dev;
        ctx.target_ino = d_inode(dentry)->i_ino;
    }

    // 7. 登録されたコールバック（Rust側）を呼び出して判定を実行する
    if (teal_decision_maker) {
        ret = teal_decision_maker(event_type, (void *)&ctx);
    }

    // 8. メモリの解放
    if (page) {
        free_page((unsigned long)page);
    }

    return ret;
}

/**
 * ファイル削除フック (unlink)
 */
static int teal_path_unlink(const struct path *dir, struct dentry *dentry)
{
    return teal_handle_path_deletion(dir, dentry, TEAL_EVENT_UNLINK);
}

/**
 * ディレクトリ削除フック (rmdir)
 */
static int teal_path_rmdir(const struct path *dir, struct dentry *dentry)
{
    return teal_handle_path_deletion(dir, dentry, TEAL_EVENT_DELETE);
}

/**
 * リネーム専用の Slow Path 処理（パス解決、両方のメタデータ抽出、teald転送）
 */
static int teal_handle_path_rename_slow(const struct path *old_dir, struct dentry *old_dentry,
                                        const struct path *new_dir, struct dentry *new_dentry)
{
    int ret = 0;
    char *old_page = NULL, *new_page = NULL;
    char *resolved_old = "", *resolved_new = "";
    struct path old_path, new_path;
    struct teal_rs_rename_ctx ctx;

    const char *exec_path = "-";
    const char *script_path = "-";
    const char *args = "-";
    struct teal_task_meta *meta;

    // 1. サブジェクト情報取得
    meta = teal_task_meta_current();
    if (meta) {
        if (meta->program[0])   exec_path = meta->program;
        if (meta->script[0])    script_path = meta->script;
        if (meta->args_head[0]) args = meta->args_head;
    }

    // 2. パス解決用メモリの確保 (2ファイル分必要)
    old_page = (char *)__get_free_page(GFP_KERNEL);
    new_page = (char *)__get_free_page(GFP_KERNEL);

    // 3. struct path の再構成
    old_path.mnt = old_dir->mnt;
    old_path.dentry = old_dentry;
    new_path.mnt = new_dir->mnt;
    new_path.dentry = new_dentry;

    // 4. 絶対パスの解決 (移動元と移動先)
    if (old_page) {
        resolved_old = d_path(&old_path, old_page, PAGE_SIZE);
        if (IS_ERR(resolved_old)) resolved_old = "";
    }
    if (new_page) {
        resolved_new = d_path(&new_path, new_page, PAGE_SIZE);
        if (IS_ERR(resolved_new)) resolved_new = "";
    }

    // 5. 構造体のパッキング
    memset(&ctx, 0, sizeof(ctx));
    ctx.program = exec_path;
    ctx.script = script_path;
    ctx.args = args;

    // 移動元 ID
    if (old_dentry && d_is_positive(old_dentry)) {
        ctx.old_target_dev = old_dentry->d_sb->s_dev;
        ctx.old_target_ino = d_inode(old_dentry)->i_ino;
    }
    ctx.old_target = resolved_old;

    // 移動先 ID
    if (new_dir && new_dir->mnt) {
        ctx.new_target_dev = new_dir->mnt->mnt_sb->s_dev;
        if (new_dentry && d_is_positive(new_dentry)) {
            ctx.new_target_ino = d_inode(new_dentry)->i_ino;
        } else {
            ctx.new_target_ino = 0; // 新規作成リネーム時は 0
        }
    }
    ctx.new_target = resolved_new;

    // 6. 判定実行（リネームイベントとして発射）
    if (teal_decision_maker) {
        ret = teal_decision_maker(TEAL_EVENT_RENAME, (void *)&ctx);
    }

    // 7. メモリ解放
    if (old_page) free_page((unsigned long)old_page);
    if (new_page) free_page((unsigned long)new_page);

    return ret;
}

/**
 * ファイル移動/リネームフック (LSM path_rename 実装)
 */
static int teal_path_rename(const struct path *old_dir, struct dentry *old_dentry,
                            const struct path *new_dir, struct dentry *new_dentry,
                            unsigned int flags)
{
    struct inode *old_inode;
    struct teal_id_pair dst_id = {0};
    
    // 全体バイパスチェック
    if (teal_should_bypass_all()) return 0;

    // 移動元の inode を安全に取得
    if (!old_dentry || !d_is_positive(old_dentry)) return 0;
    old_inode = d_inode(old_dentry);
    if (!old_inode) return 0;

    // ==========================================================
    // 【Tier 1】 Fast Path: チケットキャッシュ判定
    // ==========================================================
    if (new_dir && new_dir->mnt && new_dentry) {
        // 移動先(Destination)のデバイスIDを取得
        dst_id.dev = new_dir->mnt->mnt_sb->s_dev;

        if (d_is_positive(new_dentry)) {
            // ケースA: 上書きリネーム（すでに移動先にファイルが存在する）
            // この場合は移動先の inode 番号が確定しているため、厳密な Fast Path 検証が可能
            dst_id.ino = d_inode(new_dentry)->i_ino;

            // 構築した dst_id を渡してキャッシュマッチング（リネーム先まで厳密に検証）
            if (teal_check_ticket_match(old_inode, NULL, TEAL_EVENT_RENAME, &dst_id)) {
                return 0; // キャッシュヒットにより即時許可
            }
        } else {
            // ケースB: 新規作成リネーム（移動先にまだファイルがない）
            // この時点では移動先 inode が 0 (確定していない) ため、
            // キャッシュを用いた O(1) 判定を安全にスキップして Slow Path（teald）に判断を委ねる
        }
    }

    // ==========================================================
    // 【Tier 2】 Slow Path: キャッシュミスまたは新規リネーム時は teald へ転送
    // ==========================================================
    return teal_handle_path_rename_slow(old_dir, old_dentry, new_dir, new_dentry);
}

/**
 * 属性変更系フックの共通処理（CHMOD / CHOWN 用）
 */
static int teal_handle_attr_change(struct dentry *dentry, enum teal_event_type event_type)
{
    int ret = 0;
    char *page = NULL;
    char *resolved_path = ""; 
    struct path target_path;
    struct teal_rs_ctx ctx;

    // 実行元（サブジェクト）の初期値
    const char *exec_path = "-";
    const char *script_path = "-";
    const char *args = "-";
    struct teal_task_meta *meta;

    // 1. 最優先バイパスチェック
    if (teal_should_bypass_all()) {
        return 0;
    }

    // 2. O(1) Fast Path チェック (チケットキャッシュ判定)
    if (d_is_positive(dentry)) {
        if (teal_check_ticket_match(d_inode(dentry), dentry, event_type, NULL)) {
            return 0;
        }
    }

    // --- ここから下は Slow Path（teald への問い合わせ処理） ---

    // 3. 現在のプロセス(current)の実行元プログラムおよびスクリプト情報を取得
    meta = teal_task_meta_current();
    if (meta) {
        if (meta->program[0])   exec_path = meta->program;
        if (meta->script[0])    script_path = meta->script;
        if (meta->args_head[0]) args = meta->args_head;
    }

    // 4. パス解決用のメモリ確保
    page = (char *)__get_free_page(GFP_KERNEL);
    if (!page) {
        pr_warn("TEAL: __get_free_page failed in inode setattr hook\n");
    }

    // 5. dentry から struct path を構成
    if (current->fs) {
        target_path.mnt = current->fs->root.mnt; 
        target_path.dentry = dentry;

        // 絶対パスの解決
        if (page) {
            resolved_path = d_path(&target_path, page, PAGE_SIZE);
            if (IS_ERR(resolved_path)) {
                pr_warn("TEAL_DEBUG: [ERR] d_path failed with error code %ld\n", PTR_ERR(resolved_path));
                resolved_path = ""; 
            }
        }
    } else {
        pr_warn("TEAL_DEBUG: [ERR] current->fs is NULL. Cannot resolve path.\n");
    }

    // 6. Rust空間（teal_rs）に引き渡す構造体のパッキング
    memset(&ctx, 0, sizeof(ctx));
    ctx.target = resolved_path;
    ctx.program = exec_path;
    ctx.script = script_path;
    ctx.args = args;

    if (d_is_positive(dentry)) {
        ctx.target_dev = dentry->d_sb->s_dev;
        ctx.target_ino = d_inode(dentry)->i_ino;
    }

    // 7. 登録されたコールバック（Rust側）を呼び出して判定
    if (teal_decision_maker) {
        ret = teal_decision_maker(event_type, (void *)&ctx);
    } else {
        ret = 0; // コールバック未登録時はデフォルト許可
    }

    // 8. メモリの解放
    if (page) {
        free_page((unsigned long)page);
    }

    return ret;
}

static int teal_inode_setattr(struct dentry *dentry, struct iattr *attr) {
    int event_type = 0;

    if (!attr) return 0;

    // 権限変更 (Chmod)
    if (attr->ia_valid & ATTR_MODE) {
        event_type |= TEAL_EVENT_CHMOD;
    }
    // 所有者変更 (Chown)
    if (attr->ia_valid & (ATTR_UID | ATTR_GID)) {
        event_type |= TEAL_EVENT_CHOWN;
    }

    // 属性変更がなければ何もせず許可
    if (event_type == 0) {
        return 0;
    }

    // 共通ヘルパー関数を呼び出してロジックを統合
    return teal_handle_attr_change(dentry, event_type);
}

// ------------------------------
// LSM hooks
// ------------------------------

static const struct lsm_id teal_lsmid = {
    .name = "teal",
    .id = LSM_ID_UNDEF,
};

/* ==========================================
 * フックの登録 (モジュール初期化用配列)
 * ========================================== */
static struct security_hook_list teal_hooks[] __ro_after_init = {
    LSM_HOOK_INIT(task_alloc, teal_task_alloc),
    LSM_HOOK_INIT(file_open, teal_file_open),
    LSM_HOOK_INIT(socket_connect, teal_socket_connect),
    LSM_HOOK_INIT(bprm_check_security, teal_bprm_check),
    LSM_HOOK_INIT(bprm_committed_creds, teal_bprm_committed_creds),
    LSM_HOOK_INIT(path_unlink, teal_path_unlink),
    LSM_HOOK_INIT(path_rmdir, teal_path_rmdir),
    LSM_HOOK_INIT(path_rename, teal_path_rename),
    LSM_HOOK_INIT(inode_setattr, teal_inode_setattr),
};

static void teal_task_meta_init_current(void)
{
    struct teal_task_meta *m =
        teal_task_meta_current();

    if (!m)
        return;

    memset(m, 0, sizeof(*m));

    m->magic = TEAL_TASK_META_MAGIC;

    strscpy(m->program, "-",
            sizeof(m->program));
    strscpy(m->script, "-",
            sizeof(m->script));
    strscpy(m->args_head, "-",
            sizeof(m->args_head));

    atomic64_set(&m->privilege_state, 0);
}

static int __init teal_lsm_init(void)
{
    int rc;

    rc = rhltable_init(
        &teal_ticket_ht,
        &teal_cache_params
    );
    if (rc)
        return rc;

    teal_task_meta_init_current();

    security_add_hooks(
        teal_hooks,
        ARRAY_SIZE(teal_hooks),
        &teal_lsmid
    );

    netlink_register_notifier(&teal_nl_nb);

    return 0;
}

static int __init teal_res_init(void)
{
    int rc;

    teal_wq = alloc_workqueue("teal_cmd_wq", WQ_UNBOUND | WQ_MEM_RECLAIM, 0);
    if (!teal_wq)
        return -ENOMEM;

    // --- Generic Netlinkを登録 ---
    rc = genl_register_family(&teal_nl_family);
    if (rc) {
        pr_err("TEAL: genl_register_family failed (rc=%d)\n", rc);
        destroy_workqueue(teal_wq);
        teal_wq = NULL;
        return rc;
    }

    schedule_delayed_work(&teal_gc_work, msecs_to_jiffies(60000));
    pr_info("TEAL: Netlink family '%s' registered. GC worker started.\n", TEAL_GENL_FAMILY_NAME);
    return 0;
}

static void teal_cache_free_cb(void *ptr, void *arg) {
    kfree(ptr);
}

static void __exit teal_exit(void)
{
    // 1. まず待機中のプロセスをすべて解放する
    // これをしないと、判定待ちの sh や cat が rmmod 後にフリーズします
    teal_flush_all_queues();

    // 2. Netlink 通知の解除
    netlink_unregister_notifier(&teal_nl_nb);
    cancel_work_sync(&teal_daemon_disconnect_work);

    cancel_delayed_work_sync(&teal_gc_work);
    
    rhltable_free_and_destroy(&teal_ticket_ht, teal_cache_free_cb, NULL);
    
    // 3. Netlinkファミリーの登録解除
    genl_unregister_family(&teal_nl_family);
    
    if (teal_wq) {
        destroy_workqueue(teal_wq);
    }
    
    pr_info("TEAL: Module unloaded and all queues flushed.\n");
}

late_initcall(teal_res_init);

module_exit(teal_exit);

DEFINE_LSM(teal) = {
    .name = "teal",
    .blobs = &teal_blob_sizes,
    .init = teal_lsm_init, 
};

MODULE_LICENSE("GPL");
