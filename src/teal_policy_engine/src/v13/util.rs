use nix::unistd::{Uid, User};
use anyhow::{Context, Result};
use std::borrow::Cow;

/// ユーザー名から UID を取得する (REGISTER コマンド等で使用)
///
/// # Errors
/// ユーザーが見つからない場合は ERR_RESOLVE_FAILED 相当のエラーを返す
pub fn name_to_uid(name: &str) -> Result<u32> {
    User::from_name(name)
        .with_context(|| format!("Failed to call getpwnam for {}", name))?
        .map(|u| u.uid.as_raw())
        .ok_or_else(|| anyhow::anyhow!("User not found: {}", name))
}

/// UID からユーザー名を取得する (LIST/SHOW/監査ログ等で使用)
///
/// # Errors
/// システムに存在しない UID の場合はエラーを返す
pub fn uid_to_name(uid: u32) -> Result<String> {
    User::from_uid(Uid::from_raw(uid))
        .with_context(|| format!("Failed to call getpwuid for UID {}", uid))?
        .map(|u| u.name)
        .ok_or_else(|| anyhow::anyhow!("UID not found: {}", uid))
}

/// カーネルの起動後の時間を文字列に変換
pub fn ktime_prefix() -> String {
    // dmesg と合わせるなら MONOTONIC（起動後秒）
    // サスペンド時間も含めたいなら CLOCK_BOOTTIME に変える
    let mut ts: libc::timespec = libc::timespec { tv_sec: 0, tv_nsec: 0 };
    unsafe {
        libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts);
    }
    format!("[{:>6}.{:06}] ", ts.tv_sec, (ts.tv_nsec / 1_000) as i64)
}

/// &strの文字列を小文字に変換し&strを返す
pub fn lower<'a>(s: &'a str) -> Cow<'a, str> {
    if s.chars().all(|c| !c.is_uppercase()) {
        Cow::Borrowed(s)
    } else {
        Cow::Owned(s.to_lowercase())
    }
}


#[cfg(test)]
mod tests_name_to_uid {
    use super::*;

    #[test]
    fn test_name_to_uid_success_root() {
        // 大抵の Unix 系システムには "root" ユーザーが存在し、UID は 0 です
        let result = name_to_uid("root");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 0);
    }

    #[test]
    fn test_name_to_uid_not_found() {
        // ほぼ確実に存在しないユーザー名でテストします
        let username = "non_existent_user_9999";
        let result = name_to_uid(username);
        
        assert!(result.is_err());
        // エラーメッセージにユーザー名が含まれていることを確認します
        let err_msg = format!("{}", result.unwrap_err());
        assert!(err_msg.contains(username));
        assert!(err_msg.contains("User not found"));
    }

    #[test]
    fn test_name_to_uid_empty_string() {
        // 空文字の場合もエラーになることを確認します
        let result = name_to_uid("");
        assert!(result.is_err());
    }
}

#[cfg(test)]
mod tests_uid_to_name {
    use super::*;
    use nix::unistd::getuid;

    #[test]
    fn test_uid_to_name_success_root() {
        // UID 0 は常に "root" であることが期待されます
        let result = uid_to_name(0);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "root");
    }

    #[test]
    fn test_uid_to_name_success_current_user() {
        // 現在の実行ユーザーの UID を取得して変換をテストします
        let current_uid = getuid().as_raw();
        let result = uid_to_name(current_uid);
        
        assert!(result.is_ok());
        let name = result.unwrap();
        assert!(!name.is_empty());
    }

    #[test]
    fn test_uid_to_name_not_found() {
        // おそらく存在しないであろう大きな UID 番号でテストします
        let invalid_uid = 999_999;
        let result = uid_to_name(invalid_uid);
        
        assert!(result.is_err());
        // エラーメッセージに解決に失敗した UID が含まれていることを確認します
        let err_msg = format!("{}", result.unwrap_err());
        assert!(err_msg.contains(&invalid_uid.to_string()));
        assert!(err_msg.contains("UID not found"));
    }
}

