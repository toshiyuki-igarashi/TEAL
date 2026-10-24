// SPDX-License-Identifier: MIT
/*
 * TEAL logview (teal-logview)
 *
 * Copyright (c) 2026 Toshiyuki Igarashi
 */

pub mod dataset;
pub mod eval;
pub mod compare;
pub mod generate;

use std::path::Path;
use anyhow::Result;
use clap::Subcommand;

#[derive(Subcommand, Debug)]
pub enum AiCommands {
    /// AI test dataset operations
    Dataset {
        #[command(subcommand)]
        command: DatasetCommands,
    },

    /// Offline AI evaluation
    Eval {
        #[command(subcommand)]
        command: EvalCommands,
    },
}

#[derive(Subcommand, Debug)]
pub enum DatasetCommands {
    /// Create an AiEvent JSONL dataset from audit logs
    Create(dataset::CreateArgs),
    /// Create an AiEvent JSONL dataset for AI test
    Generate(generate::GenerateArgs),
}

#[derive(Subcommand, Debug)]
pub enum EvalCommands {
    /// Run AI evaluation using a dataset and configuration
    Run(eval::EvalArgs),

    /// Compare two AI evaluation reports
    Compare(compare::CompareArgs),
}

pub fn run(command: AiCommands, audit_file: &Path) -> Result<()> {
    match command {
        AiCommands::Dataset { command } => match command {
            DatasetCommands::Create(args) => dataset::create(audit_file, args),
            DatasetCommands::Generate(args) => generate::run(args),
        },

        AiCommands::Eval { command } => match command {
            EvalCommands::Run(args) => eval::run(args),
            EvalCommands::Compare(args) => compare::run(args),
        },
    }
}