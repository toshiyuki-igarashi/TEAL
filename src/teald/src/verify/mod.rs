// SPDX-License-Identifier: MIT
/*
 * TEAL Daemon (teald)
 *
 * Copyright (c) 2026 Toshiyuki Igarashi
 */
pub mod ast;
pub mod transpiler_alloy;
pub mod checker_alloy;

use colored::*;
use anyhow::Result;
use serde::{Deserialize, Serialize};

use crate::verify::ast::TealIrModel;
use crate::verify::transpiler_alloy::AlloyTranspiler;
use crate::verify::checker_alloy::AlloyChecker;

/// BDD形式の検証ゴール定義 (goal.yaml からデシリアライズされる)
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct VerifyGoal {
    pub name: String,
    pub target: String,             // 守るべきリソース (例: "/etc/shadow")
    
    #[serde(default)]               // 省略された場合は空のVecになる
    pub action: Vec<String>,        // 例: ["READ", "WRITE"]
    
    pub expected_effect: String,    // "deny", "need_approval", "allow"

    // --- Subject 関連 ---
    #[serde(default)]
    pub role_set: Option<Vec<String>>,
    #[serde(default)]
    pub user: Option<String>,
    #[serde(default)]
    pub uid: Option<u32>,
    #[serde(default)]
    pub program: Option<String>,
    #[serde(default)]
    pub script: Option<String>,
    #[serde(default)]
    pub applet: Option<String>,
}

/// 検証パイプライン全体を制御するエグゼキューター（司令塔）
pub struct VerifyExecutor {
    transpiler: AlloyTranspiler,
    checker: AlloyChecker,
}

impl VerifyExecutor {
    /// 新しいエグゼキューターを初期化
    /// jar_path: alloy-cli.jar へのパス
    pub fn new(jar_path: &str) -> Self {
        Self {
            transpiler: AlloyTranspiler::new(),
            checker: AlloyChecker::new(jar_path),
        }
    }

    /// 検証メインルーチン：トランスパイルからレポート出力までを実行
    pub fn execute(&mut self, model: &TealIrModel, visualize: bool, debug: bool) -> Result<()> {
        println!("{}", "=> TEALポリシーの論理整合性を検証します...".bright_blue().bold());

        // --- デバッグモード：中間モデル(IR)の出力 ---
        if debug {
            let ir_debug_path = "debug_model.ir.json";
            let json = serde_json::to_string_pretty(model)?;
            std::fs::write(ir_debug_path, json)?;
            println!("{} Debug IR saved to: {}", "DEBUG".magenta().bold(), ir_debug_path);
        }

        // 1. トランスパイルして「コード」と「証明式」を取得
        println!("  {} 中間論理モデルから Alloy モデルを構築中...", "-> [1/2]".cyan());
        let als_code = self.transpiler.transpile(model);
        // ここで LaTeX 形式の証明（HashMap）を受け取る
        let math_proofs = self.transpiler.get_assertion_proofs();

        // --- デバッグモード：生成された Alloy コードの出力 ---
        if debug {
            let als_debug_path = "debug_logic.als";
            std::fs::write(als_debug_path, &als_code)?;
            println!("{} Debug Alloy code saved to: {}", "DEBUG".magenta().bold(), als_debug_path);
        }

        // 2. Alloyを実行して「生の結果リスト」を取得
        println!("  {} SATソルバを実行して全論理空間を探索中...", "-> [2/2]".cyan());
        let check_results = self.checker.run_all_checks(&als_code)?;

        // --- 3. 結果のレンダリング (ここで翻訳と表示を行う) ---
        let mut failure_count = 0;

        // 3. ループで回してデコードと表示
        for res in check_results {
            if res.is_violated {
                failure_count += 1;
                let violation = self.checker.decode_violation(&res, model, &math_proofs);
                violation.render_terminal(); // プロフェッショナルレポート出力
            } else {
                println!("  {} Goal: `{}` は、与えられたモデル範囲では反例が見つかりませんでした。", "✅ [PASS]".green(), res.goal_name);
            }
        }
        
        // --- ステップ 4: 総括の表示とGUI連携 ---
        if failure_count > 0 {
            println!("\n{} {} 件の脆弱性（意図しないアクセスパス）が検出されました。", 
                "⚠️".yellow().bold(), failure_count);
            
            if visualize {
                // フィックスされた同期型 open_gui を呼び出し
                println!("{} --visualize が指定されています。Alloy GUIを起動します...", "💡".bright_white());
                self.checker.open_gui(&als_code, &model.name)?;
            } else {
                println!("{} ヒント: 反例を視覚的に確認するには `--visualize` オプションを付けてください。", 
                    "💡".bright_white());
            }
        } else {
            println!("\n{} すべての検証ゴールに対して、安全性が数学的に証明されました。", 
                "✨".green().bold());
        }

        Ok(())
    }
}

