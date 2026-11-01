#![feature(const_convert, const_trait_impl)]

mod check;
mod parser;
mod principals;
mod sign;
mod verify;

use clap::Parser;
use parser::{Cli, Command, SignerError};
use std::process::ExitCode;

fn run(args: &Cli) -> Result<(), SignerError<'_>> {
    let cmd = Command::from_cli(args)?;
    match cmd {
        Command::Sign(ref req) => sign::execute_sign(req),
        Command::Verify(ref req) => verify::execute_verify(req),
        Command::CheckNoValidate(ref req) => check::execute_check_novalidate(req),
        Command::FindPrincipals(ref req) => principals::execute_find_principals(req),
    }
}

fn main() -> ExitCode {
    let args = Cli::parse();

    if let Err(err) = run(&args) {
        eprintln!("{err}");
        return ExitCode::from(1);
    }

    ExitCode::SUCCESS
}
