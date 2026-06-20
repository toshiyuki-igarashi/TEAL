// SPDX-License-Identifier: MIT
/*
 * TEAL Daemon (teald)
 *
 * Copyright (c) 2026 Toshiyuki Igarashi
 */
use serde::Serialize;
use std::collections::HashSet;
use teal_policy_engine::types::Effect;
use teal_policy_engine::raw::{RawPolicyV13, RawRule};
use crate::verify::VerifyGoal;


/// 検証用中間モデルのルート
#[derive(Debug, Serialize)]
pub struct TealIrModel {
    pub name: String,
    pub entities: Vec<Entity>,
    pub rules: Vec<IrRule>,
    pub assertions: Vec<IrAssertion>,
    pub managed_paths: Vec<String>, // ポリシーによって管理されるリソースパスのリスト
}

/// 主体(Subject)や客体(Object)を抽象化したエンティティ
#[derive(Debug, Serialize, PartialEq, Eq, Hash, Clone)]
pub struct Entity {
    pub name: String,
    pub category: EntityCategory,
}

#[derive(Debug, Serialize, PartialEq, Eq, Hash, Clone)]
pub enum EntityCategory {
    // Subject関連
    User,
    Uid,
    Role,
    Program,
    Script,
    Applet,
    
    // Object関連
    ResourcePath,
    
    // Action関連
    Operation,
}

/// ポリシールールの論理表現
#[derive(Debug, Serialize)]
pub struct IrRule {
    pub id: String,
    pub effect: Effect,
    pub condition: IrExpr,
}

/// ツールに依存しない論理式ツリー
#[derive(Debug, Serialize)]
pub enum IrExpr {
    /// 論理積 (A and B and ...)
    And(Vec<IrExpr>),
    
    /// 論理和 (A or B or ...)
    Or(Vec<IrExpr>),
    
    /// 属性と値の完全一致比較 (attribute = value)
    /// 例: Eq("subject.user", "alice")
    Eq(String, String),
    
    /// 文字列マッチングや範囲指定などの複雑な条件
    /// 前回設計した IrTerm (Match, In, Range等) を格納します
    Term(IrTerm),
}

/// 検証ゴールから生成される、Alloyへの証明要求（assert）
#[derive(Debug, Serialize)]
pub enum IrAssertion {
    /// 指定された条件(condition)において、アクセスが許可される経路は存在しないことを証明
    AssertDeny { name: String, condition: IrExpr },

    /// 指定された条件において許可されているなら、必ずチケット（承認）を持っていることを証明
    /// （チケットなしでのバイパス経路を探す）
    AssertNeedApprovalBypass { name: String, condition: IrExpr },

    /// 指定された条件において、許可される経路が少なくとも一つ存在することを証明
    AssertAllow { name: String, condition: IrExpr },
}

impl IrAssertion {
    /// 内部の論理式を取得するヘルパー
    pub fn condition(&self) -> &IrExpr {
        match self {
            IrAssertion::AssertDeny { condition, .. } => condition,
            IrAssertion::AssertNeedApprovalBypass { condition, .. } => condition,
            IrAssertion::AssertAllow { condition, .. } => condition,
        }
    }

    /// ゴール名を取得するヘルパー
    pub fn name(&self) -> &str {
        match self {
            IrAssertion::AssertDeny { name, .. } => name,
            IrAssertion::AssertNeedApprovalBypass { name, .. } => name,
            IrAssertion::AssertAllow { name, .. } => name,
        }
    }
}

#[derive(Debug, Serialize)]
pub enum IrTerm {
    /// 文字列パターンマッチ (glob: や prefix: の解決用)
    /// 例: Match { attr: "object.path", pattern: "glob:/etc/*" }
    Match {
        attr: String,
        pattern: String,
    },

    /// 集合への包含判定
    /// 例: In { attr: "subject.role", values: ["admin", "operator"] }
    In {
        attr: String,
        values: Vec<String>,
    },
}

// --- 実装ブロック (変換ロジック) ---

impl TealIrModel {
    /// RawRuleを走査し、ポリシー内に登場するエンティティを単語帳(entities)に登録する
    fn extract_entity(raw_rule: &RawRule, entities: &mut HashSet<Entity>) {
        // ==========================================
        // 1. Subjectの抽出
        // ==========================================
        let subj = &raw_rule.subject;

        if let Some(user) = &subj.user {
            entities.insert(Entity { name: user.clone(), category: EntityCategory::User });
        }
        if let Some(uid) = subj.uid {
            entities.insert(Entity { name: uid.to_string(), category: EntityCategory::Uid });
        }
        for role in &subj.roles {
            entities.insert(Entity { name: role.clone(), category: EntityCategory::Role });
        }
        if let Some(prog) = &subj.origin_program {
            entities.insert(Entity { name: prog.clone(), category: EntityCategory::Program });
        }
        if let Some(script) = &subj.origin_script {
            entities.insert(Entity { name: script.clone(), category: EntityCategory::Script });
        }
        if let Some(applet) = &subj.origin_applet {
            entities.insert(Entity { name: applet.clone(), category: EntityCategory::Applet });
        }

        // ==========================================
        // 2. Objectの抽出
        // ==========================================
        // from_rawでの skip 処理により、ここは安全に unwrap できる
        if let Some(obj) = &raw_rule.object {
            entities.insert(Entity { name: obj.path.clone(), category: EntityCategory::ResourcePath });
            
            // ルール定義内の new_path も Entity として登録
            if let Some(np) = &obj.new_path {
                entities.insert(Entity { name: np.clone(), category: EntityCategory::ResourcePath });
            }
        }

        // ==========================================
        // 3. Actionの抽出
        // ==========================================
        let act = &raw_rule.action;
        for op in &act.ops {
            entities.insert(Entity { name: op.to_string(), category: EntityCategory::Operation });
        }
    }

    /// 文字列を見て、単純一致(Eq)かパターンマッチ(Match)かを自動判別して返す
    fn process_matchable_attr(attr: &str, val: String) -> IrExpr {
        // glob: / prefix: / * のいずれかを含めば Match (IrTerm) として扱う
        if val.starts_with("glob:") || val.starts_with("prefix:") || val.contains('*') {
            IrExpr::Term(IrTerm::Match {
                attr: attr.to_string(),
                pattern: val, // valは既にcloneされたStringを受け取る想定
            })
        } else {
            // それ以外は Alloy 側で高速に処理できる単純一致(Eq)にする
            IrExpr::Eq(attr.to_string(), val)
        }
    }

    /// ルールの条件を論理ツリー(IrExpr)に変換する
    fn extract_condition(raw_rule: &RawRule) -> anyhow::Result<IrExpr> {
        let mut and_conditions = Vec::new();
        // ==========================================
        // 1. Subject条件の組み立て (AND結合)
        // ==========================================
        let subj = &raw_rule.subject;

        // --- 1. Subject条件 (User, Program, etc) ---
        if let Some(user) = &subj.user {
            and_conditions.push(IrExpr::Eq("subject.user".into(), user.clone()));
        }
        if let Some(uid) = subj.uid {
            and_conditions.push(IrExpr::Eq("subject.uid".into(), uid.to_string()));
        }
        // 配列が空でない場合のみ、集合包含判定(In)を追加
        if !subj.roles.is_empty() {
            and_conditions.push(IrExpr::Term(IrTerm::In {
                attr: "subject.role".into(),
                values: subj.roles.clone(),
            }));
        }
        if let Some(prog) = &subj.origin_program {
            and_conditions.push(Self::process_matchable_attr("subject.origin_program", prog.clone()));
        }
        if let Some(script) = &subj.origin_script {
            and_conditions.push(Self::process_matchable_attr("subject.origin_script", script.clone()));
        }
        if let Some(applet) = &subj.origin_applet {
            and_conditions.push(Self::process_matchable_attr("subject.origin_applet", applet.clone()));
        }

        // ==========================================
        // 2. Object条件の組み立て
        // ==========================================
        // subject_only の場合は object が None になるので安全にスキップされる
        if let Some(obj) = &raw_rule.object {
            // 1. 移動元(path)の条件
            and_conditions.push(Self::process_matchable_attr("object.path", obj.path.clone()));
            
            // 2. 移動先(new_path)の条件
            if let Some(np) = &obj.new_path {
                and_conditions.push(Self::process_matchable_attr("object.new_path", np.clone()));
            }
        }

        // ==========================================
        // 3. Action条件の組み立て
        // ==========================================
        // action は RawAction なので、その中の op フィールド等を使用
        if !raw_rule.action.ops.is_empty() {
            // 複数の操作(ops)がある場合は「いずれかに合致(OR)」のツリーを作る
            let op_terms: Vec<IrExpr> = raw_rule.action.ops.iter()
                .map(|op| Self::process_matchable_attr("action.op", op.to_string()))
                .collect();
            
            // Andリストの中に「(READ or WRITE)」のようなOrブロックを追加
            and_conditions.push(IrExpr::Or(op_terms));
        }

        // すべての要素(Subjectの各条件, Object, Action)をANDで束ねる
        Ok(IrExpr::And(and_conditions))
    }

    /// RawPolicyV13 と ゴール定義から論理モデル(IR)を構築する
    pub fn from_raw(raw: &RawPolicyV13, goals: &[VerifyGoal], policy_name: &str) -> anyhow::Result<Self> {
        let mut entities_set = HashSet::new();
        let mut ir_rules = Vec::new();
        let mut managed_paths_set = HashSet::new(); // 管理対象パスの集合

        // --- 1. ルールのパース ---
        for raw_rule in &raw.rules {
            // 形式検証の対象外ルールをスキップ
            // 1. AuditOnly はアクセス可否(状態)に影響しないため除外
            // 2. subject_only (Tier2 FastPath) は特定の客体を持たず、静的検証のノイズになるため除外
            if raw_rule.effect == Effect::AuditOnly || raw_rule.rule_type == "subject_only" {
                continue; 
            }

            // 1. エンティティの抽出 (可変参照を渡して登録してもらう)
            // この時点で、対象となるルールには必ず `object` が存在することが保証される
            Self::extract_entity(raw_rule, &mut entities_set);
            
            // --- このルールが対象とするオブジェクトパスを「管理対象」として記録 ---
            if let Some(obj) = &raw_rule.object {
                managed_paths_set.insert(obj.path.clone());
                
                // RENAME時の移動先（new_path）も管理対象として登録する
                if let Some(np) = &obj.new_path {
                    managed_paths_set.insert(np.clone());
                }
            }

            // --- ステップ2: 論理ツリーの組み立て ---
            let condition = Self::extract_condition(raw_rule)?;

            // --- ステップ3: IRルールの登録 ---
            ir_rules.push(IrRule {
                id: raw_rule.id.clone(),
                effect: raw_rule.effect,
                condition,
            });
        }

        // --- 2. ゴールからAssertionとEntityの追加抽出 ---
        // 2. ゴールの処理
        let mut assertions = Vec::new();
        for goal in goals {
            // ゴール独自のエンティティ（ターゲットパスなど）を登録
            entities_set.insert(Entity { 
                name: goal.target.clone(), 
                category: EntityCategory::ResourcePath 
            });

            // new_target も検証用の Entity として登録する
            if let Some(nt) = &goal.new_target {
                entities_set.insert(Entity { 
                    name: nt.clone(),
                    category: EntityCategory::ResourcePath 
                });
            }

            let assertion = Self::build_assertion(goal)?;
            assertions.push(assertion);
        }

        Ok(Self {
            name: policy_name.to_string(),
            entities: entities_set.into_iter().collect(),
            rules: ir_rules,
            assertions,
            managed_paths: managed_paths_set.into_iter().collect(),
        })
    }

    fn build_assertion(goal: &VerifyGoal) -> anyhow::Result<IrAssertion> {
        let mut conds = Vec::new();

        // 1. ターゲット（パス）条件
        conds.push(Self::process_matchable_attr("object.path", goal.target.clone()));

        // 移動先（new_target）の条件
        // goal.yaml に new_target が指定されている場合のみ、AND条件に追加する
        if let Some(nt) = &goal.new_target {
            conds.push(Self::process_matchable_attr("object.new_path", nt.clone()));
        }

        // 2. Action条件 (ops)
        if !goal.action.is_empty() {
            conds.push(IrExpr::Term(IrTerm::In {
                attr: "action.op".into(), 
                values: goal.action.clone(),
            }));
        }
        
        // 3. Subject 属性の構築
        if let Some(roles) = &goal.role_set {
            if !roles.is_empty() {
                conds.push(IrExpr::Term(IrTerm::In {
                    attr: "subject.role".into(),
                    values: roles.clone(),
                }));
            }
        }

        if let Some(u) = &goal.user {
            conds.push(IrExpr::Eq("subject.user".into(), u.clone()));
        }

        if let Some(uid) = goal.uid {
            conds.push(IrExpr::Eq("subject.uid".into(), uid.to_string()));
        }

        if let Some(p) = &goal.program {
            conds.push(Self::process_matchable_attr("subject.origin_program", p.clone()));
        }

        if let Some(s) = &goal.script {
            conds.push(IrExpr::Eq("subject.origin_script".into(), s.clone()));
        }

        if let Some(a) = &goal.applet {
            conds.push(IrExpr::Eq("subject.origin_applet".into(), a.clone()));
        }
   
        // まとめて AND 条件にする
        let condition = IrExpr::And(conds);
        let name = goal.name.clone();

        // 4. expected_effect に基づいて適切なバリアントを作成
        match goal.expected_effect.as_str() {
            "deny" => Ok(IrAssertion::AssertDeny { name, condition }),
            "need_approval" => Ok(IrAssertion::AssertNeedApprovalBypass { name, condition }),
            "allow" => Ok(IrAssertion::AssertAllow { name, condition }),
            _ => Err(anyhow::anyhow!("Unknown expected_effect: {}", goal.expected_effect)),
        }
    }
}

