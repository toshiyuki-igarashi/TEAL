// teald/src/verify/checker_alloy.rs

use std::collections::HashMap;
use std::io::Write;
use std::io::Read;

use quick_xml::reader::Reader;
use quick_xml::events::Event;
use colored::*;
use tempfile::NamedTempFile;

use crate::verify::ast::TealIrModel;
use crate::verify::transpiler_alloy::sanitize;

#[derive(Default, Debug, Clone)]
pub struct ReqData {
    pub roles: Vec<String>,
    pub prog: String,
    pub obj: String,
    pub op: String,
    pub rule_id: String,
}

pub struct AlloyChecker {
    alloy_jar_path: String,
}

impl AlloyChecker {
    pub fn new(jar_path: &str) -> Self {
        Self {
            alloy_jar_path: jar_path.to_string(),
        }
    }

    /// 全てのアサーションを順次実行し、検証結果を収集する
    pub fn run_all_checks(&self, als_code: &str) -> anyhow::Result<Vec<RawCounterExample>> {
        let mut results = Vec::new();

        // 1. コード内から実行すべきゴール名を抽出 (check文を探す)
        let goal_names = self.extract_goal_names(als_code);

        // 2. 各ゴールごとに専門関数 run_alloy を呼び出し
        for goal in goal_names {
            match self.run_alloy(als_code, &goal)? {
                Some(xml_content) => {
                    // --- 【反例あり】 脆弱性が発見されたケース ---
                    let mut ce = self.parse_xml(&xml_content);
                    ce.is_violated = true;
                    ce.goal_name = goal; 
                    results.push(ce);
                }
                None => {
                    // --- 【反例なし】 数学的に安全が証明されたケース ---
                    results.push(RawCounterExample {
                        goal_name: goal,
                        is_violated: false,
                        ..RawCounterExample::default()
                    });
                }
            }
        }
        Ok(results)
    }

    /// 単一のゴールに対して Alloy を実行し、XMLまたは安全判定を返す
    /// 戻り値: 
    ///   Ok(Some(XML)) -> 反例あり
    ///   Ok(None)      -> 安全（反例なし）
    ///   Err(...)      -> 実行失敗（Java未インストールやモデルの論理エラー等）
    fn run_alloy(&self, als_code: &str, goal_name: &str) -> anyhow::Result<Option<String>> {
        // 1. Alloyコード (.als) を一時ファイルに書き出す
        let mut temp_als = NamedTempFile::new()?;
        write!(temp_als, "{}", als_code)?;
        let als_path = temp_als.path().to_str().unwrap();

        // 2. 反例出力用の XML パスを準備
        // .path() でパスだけ取得し、NamedTempFile オブジェクトを保持することで
        // この関数が終わるまでファイルが削除されないようにします
        let temp_xml = NamedTempFile::new()?;
        let xml_path = temp_xml.path().to_str().unwrap();

        // 3. Java プロセスを実行
        let output = std::process::Command::new("java")
            .arg("-jar").arg(&self.alloy_jar_path)
            .arg(als_path).arg(goal_name).arg(xml_path)
            .output()?;

        // 4. プロセス自体の失敗（Java未インストール、メモリ不足等）
        if !output.status.success() {
            let err_msg = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!("Alloy実行エラー: {}", err_msg);
        }

        let stdout = String::from_utf8_lossy(&output.stdout);

        // 5. XMLファイルの存在と内容を確認
        // 反例がない場合はファイルが作られない可能性を考慮し、存在チェックを行う
        if std::path::Path::new(xml_path).exists() {
            let mut xml_content = String::new();
            let mut file = std::fs::File::open(xml_path)?;
            file.read_to_string(&mut xml_content)?;

            // --- 反例の有無の判定 ---
            if xml_content.contains("<instance") {
                return Ok(Some(xml_content));
            }
        }

        // 6. XMLがない場合、stdoutを確認して「本当に安全」なのか「Alloy内部の論理エラー」なのかを判定
        // これにより、Alloy側がパースエラー等で沈黙した場合の「偽の安全」を防ぐ
        if stdout.contains("No counterexample found") {
            Ok(None) 
        } else {
            anyhow::bail!(
                "Alloyが期待通りの出力を返しませんでした。モデルの論理エラーの可能性があります。\nStdout: {}", 
                stdout
            );
        }
    }

    /// Alloy コードの中から check 文を探してゴール名のリストを作る補助関数
    fn extract_goal_names(&self, als_code: &str) -> Vec<String> {
        als_code.lines()
            .filter(|line| line.trim().starts_with("check "))
            .filter_map(|line| {
                // "check ShadowBypass for 5" -> "ShadowBypass"
                line.split_whitespace().nth(1).map(|s| s.to_string())
            })
            .collect()
    }
}

#[derive(Default)]
pub struct RawCounterExample {
    pub goal_name: String,      // 検証ゴールの識別名
    pub is_violated: bool,      // 脆弱性が見つかったか
    pub rule_id: String,        // 原因となった rule_id
    pub object_atom: String,
    pub subject_atom: String,   // 従来の表示用 ("Role_admin + Prog: /tmp/malware")
    pub subject_roles: Vec<String>, // Roleを個別に保持
    pub subject_origin: String,     // プログラム(origin)を個別に保持
    pub action: String,
    pub path_map: HashMap<String, String>, // アトム名 -> 生パス
}

impl AlloyChecker {
    /// XMLをパースして反例データを抽出
    fn parse_xml(&self, xml_content: &str) -> RawCounterExample {
        let mut reader = Reader::from_str(xml_content);
        let mut ce = RawCounterExample {
            goal_name: "unknown".to_string(), // 初期値
            is_violated: true,
            rule_id: String::new(),
            subject_atom: String::new(),
            object_atom: String::new(),
            subject_roles: Vec::new(),
            subject_origin: String::new(),
            action: String::new(),
            path_map: HashMap::new(),
        };

        // 全てのリクエストデータを一時保存するマップ
        let mut req_map: HashMap<String, ReqData> = HashMap::new();

        let mut current_field = String::new();
        // 犯人を特定するための変数
        let mut current_skolem = String::new(); 
        let mut culprit_req_id = String::new(); 

        let mut buf = Vec::new();
        
        loop {
            match reader.read_event_into(&mut buf) {
                // --- <instance command="..."> からゴール名を取り出す ---
                Ok(Event::Start(ref e)) if e.name().as_ref() == b"instance" => {
                    if let Some(cmd_attr_res) = e.attributes()
                        .find(|a| a.as_ref().unwrap().key.as_ref() == b"command") 
                    {
                        let attr = cmd_attr_res.unwrap(); 
                        let cmd_str = String::from_utf8_lossy(&attr.value);
                        ce.goal_name = cmd_str.split_whitespace().nth(1)
                            .unwrap_or("unknown").to_string();
                    }
                }
                // --- <field> タグ (通常のデータ) ---
                Ok(Event::Start(ref e)) if e.name().as_ref() == b"field" => {
                    current_field = e.attributes()
                        .find(|a| a.as_ref().unwrap().key.as_ref() == b"label")
                        .map(|a| String::from_utf8_lossy(&a.unwrap().value).into_owned())
                        .unwrap_or_default();
                    current_skolem.clear(); // skolemではないのでクリア
                }
                // <skolem> タグ (真の犯人を教えてくれるタグ)
                Ok(Event::Start(ref e)) if e.name().as_ref() == b"skolem" => {
                    current_skolem = e.attributes()
                        .find(|a| a.as_ref().unwrap().key.as_ref() == b"label")
                        .map(|a| String::from_utf8_lossy(&a.unwrap().value).into_owned())
                        .unwrap_or_default();
                    current_field.clear(); // fieldではないのでクリア
                }
                // --- <tuple> タグ (中身のアトム) ---
                Ok(Event::Start(ref e)) if e.name().as_ref() == b"tuple" => {
                    let atoms = self.extract_atoms(&mut reader);
                    
                    // もし現在 <skolem> の中なら、犯人IDを記録する！
                    if !current_skolem.is_empty() && current_skolem.ends_with("_r") {
                        if !atoms.is_empty() && atoms[0].starts_with("Request") {
                            culprit_req_id = atoms[0].clone();
                        }
                    } 
                    // 通常の <field> データなら ReqData に保存する
                    else if !current_field.is_empty() {
                        self.process_tuple(&current_field, atoms, &mut ce, &mut req_map);
                    }
                }
                Ok(Event::Eof) => break,
                _ => (),
            }
            buf.clear();
        }

        // HashMapをランダムにループするのをやめ、犯人をピンポイントで引き抜く！
        // (もし skolem から取れなかった場合の保険として "Request$0" を指定しておく)
        if culprit_req_id.is_empty() {
            culprit_req_id = "Request$0".to_string(); 
        }

        if let Some(req) = req_map.get(&culprit_req_id) {
            ce.rule_id = req.rule_id.clone();
            ce.object_atom = req.obj.clone();
            ce.action = req.op.clone();

            // 生のデータをそのまま保持する
            ce.subject_roles = req.roles.clone();
            ce.subject_origin = req.prog.clone();

            // Subjectの文字列を綺麗に組み立てる
            let mut subj_parts = Vec::new();
            if !req.roles.is_empty() {
                subj_parts.push(req.roles.join(" + "));
            }
            if !req.prog.is_empty() {
                subj_parts.push(format!("Prog: {}", req.prog));
            }
            ce.subject_atom = subj_parts.join(" + ");
        }

        ce
    }

    /// <tuple> 内の <atom label="..."> をすべて抽出する
    fn extract_atoms(&self, reader: &mut Reader<&[u8]>) -> Vec<String> {
        let mut atoms = Vec::new();
        let mut buf = Vec::new();

        loop {
            match reader.read_event_into(&mut buf) {
                // <atom label="xxx" /> または <atom label="xxx"></atom> を検知
                Ok(Event::Start(ref e)) | Ok(Event::Empty(ref e)) if e.name().as_ref() == b"atom" => {
                    if let Some(label) = e.attributes()
                        .find(|a| a.as_ref().unwrap().key.as_ref() == b"label")
                        .map(|a| String::from_utf8_lossy(&a.unwrap().value).into_owned()) 
                    {
                        atoms.push(label);
                    }
                }
                // </tuple> に到達したら終了
                Ok(Event::End(ref e)) if e.name().as_ref() == b"tuple" => break,
                // エラーまたは EOF
                Ok(Event::Eof) => break,
                _ => (),
            }
            buf.clear();
        }
        atoms
    }

    fn process_tuple(
        &self, 
        field_label: &str, 
        atoms: Vec<String>, 
        ce: &mut RawCounterExample,
        req_map: &mut HashMap<String, ReqData>
    ) {
        if atoms.len() < 2 { return; }

        let id = atoms[0].clone();

        // --- Request に関するデータの場合 ---
        if id.starts_with("Request") {
            let val = self.strip_id(&atoms[1]);
            // 辞書に Request$0 などが存在しなければ作成し、取得する
            let req = req_map.entry(id).or_default();

            match field_label {
                "triggered_by" => req.rule_id = val,
                "role" | "roles" => req.roles.push(val),
                "origin_program" => req.prog = val,
                "path" | "object" => req.obj = val,
                "op" => req.op = val,
                _ => {}
            }
        } 
        else {
            if field_label == "path" {
                ce.path_map.insert(atoms[0].clone(), atoms[1].clone());
            }
        }
    }

    fn strip_id(&self, atom: &str) -> String {
        atom.split('$').next().unwrap_or(atom).to_string()
    }
}

/// デコード済みの違反（反例）情報
pub struct DecodedViolation {
    pub goal_name: String,
    pub counter_example_math: String,
    pub subject_info: String,
    pub object_path: String,
    pub action: String,
    pub triggered_rule_id: String,
    pub rule_description: String,
}

impl DecodedViolation {
    pub fn render_terminal(&self) {
        println!("\n{}", "------------------------------------------------------------".bright_black());
        println!("{}", format!("❌ [VERIFY FAILURE] Goal: `{}`", self.goal_name).red().bold());
        println!("{} {}\n", "Result:".bold(), "Vulnerability found (Counter-example detected)".yellow());

        // 数学的証明の表示
        println!("{}", "Counter-example:".bright_white().bold());
        println!("  {}\n", self.counter_example_math.cyan().italic());

        // 攻撃パスの表示
        println!("{}", "Detected Attack Path:".bright_white().bold());
        println!("  - {} {}", "Subject:".bold(), self.subject_info);
        println!("  - {} {}", "Object: ".bold(), self.object_path);
        println!("  - {} {}", "Action: ".bold(), self.action);
        println!();

        // 原因分析の表示
        println!("{}", "Root Cause Analysis:".bright_white().bold());
        println!("  - {} \"{}\"", "rule_id:".bold(), self.triggered_rule_id);
        println!("    {}", self.rule_description.dimmed());
        println!("{}", "------------------------------------------------------------".bright_black());
    }
}

impl AlloyChecker {
    /// 生の反例データを、IRモデルの情報を使って人間が読める形式に翻訳する
    /// 脆弱性情報のデコード (数学的証明と合体)
    pub fn decode_violation(
        &self,
        raw: &RawCounterExample,
        model: &TealIrModel,
        _math_proofs: &HashMap<String, String> // 使わないので _ をつけたまま無視
    ) -> DecodedViolation {
        // 1. Alloy 固有の $0 サフィックスを除去
        let clean_rule_id = raw.rule_id.split('$').next().unwrap_or("unknown");
        let clean_obj_atom = raw.object_atom.split('$').next().unwrap_or(&raw.object_atom);

        // 2. パス(Object)のクリーンアップ ("Obj__etc_shadow" -> "/etc/shadow")
        // path_map にあれば使い、なければプレフィックスを削って "_" を "/" に戻す
        let object_path = raw.path_map.get(clean_obj_atom)
            .map(|s| s.trim_matches('"').to_string())
            .unwrap_or_else(|| {
                let s = clean_obj_atom.strip_prefix("Obj_").unwrap_or(clean_obj_atom);
                s.replace("_", "/") // "_etc_shadow" -> "/etc/shadow"
            });

        // 3. ルールIDの逆引き (Alloy用ID -> 元の JSON ID)
        let original_rule_id = model.rules.iter()
            .find(|r| sanitize(&r.id) == clean_rule_id)
            .map(|r| r.id.as_str()).unwrap_or(clean_rule_id);

        // 4. Role と Action のクリーンアップ ("Role_admin" -> "admin", "Op_READ" -> "READ")
        let clean_action = raw.action.split('$').next().unwrap_or(&raw.action)
            .strip_prefix("Op_").unwrap_or(&raw.action);

        let clean_roles: Vec<String> = raw.subject_roles.iter()
            .map(|r| r.split('$').next().unwrap_or(r))
            .map(|r| r.strip_prefix("Role_").unwrap_or(r).to_string())
            .collect();

        let role_str = if clean_roles.is_empty() {
            "None".to_string()
        } else {
            clean_roles.join(", ")
        };

        let origin_str = if raw.subject_origin.is_empty() {
            "None".to_string()
        } else {
            format!("'{}'", raw.subject_origin)
        };

        // 5. 反例の数式を動的に生成（綺麗な文字列で組み立てる）
        let counter_example_math = format!(
            "\\exists r \\in Requests :\n    (object.path = '{}'\n      \\land action.op = {}\n      \\land subject.role = {}\n      \\land subject.origin = {}\n      \\land AccessAllowed(r))",
            object_path,
            clean_action,
            role_str,
            origin_str
        );

        DecodedViolation {
            goal_name: raw.goal_name.clone(),
            counter_example_math,
            object_path: object_path.clone(), // Detected Attack Path の Object に使用
            triggered_rule_id: original_rule_id.to_string(),
            subject_info: role_str,           // Detected Attack Path の Subject に使用
            action: clean_action.to_string(), // Detected Attack Path の Action に使用
            rule_description: "ポリシー内の論理条件が重なり、このアクセスパスが成立しています。".into(),
        }
    }
}

impl AlloyChecker {
    /// Alloy Visualizerを起動して、反例を視覚的にデバッグする (同期/待機型)
    pub fn open_gui(&self, als_code: &str, policy_name: &str) -> anyhow::Result<()> {
        use std::io::Write;
        use anyhow::Context;

        // 1. ファイル書き出し (ポリシー名をファイル名に含めて識別しやすくする)
        let file_path = format!("verify_debug_{}.als", policy_name.replace("-", "_"));
        let mut file = std::fs::File::create(&file_path)
            .context("Alloyデバッグファイルの生成に失敗しました")?;
        file.write_all(als_code.as_bytes())?;

        println!("\n{}", "------------------------------------------------------------".bright_black());
        println!("{} Alloy Visualizer を起動中...", "=>".bright_cyan().bold());
        println!("   {} {}", "Model File:".bold(), file_path);

        // 2. Alloy GUIの起動 (第一引数にファイルを渡すとGUIが開く標準的な挙動)
        let mut child = std::process::Command::new("java")
            .arg("-jar")
            .arg(&self.alloy_jar_path)
            .arg(&file_path) 
            .spawn() // プロセスを起動
            .context("Alloy Visualizer の起動に失敗しました。JavaのインストールとJARのパスを確認してください。")?;

        println!("=> {}", "GUIが開きました。Alloy上で 'Execute' を押し、グラフを確認してください。".yellow());
        println!("   (確認が終わったら、Alloyのウィンドウを閉じて戻ってください)");

        // 3. 同期処理: GUIが閉じられるまで待機 (Wait)
        // これにより、読み込み中の一時ファイルが消えるのを防ぎ、UXを安定させます
        child.wait()?;

        Ok(())
    }
}
