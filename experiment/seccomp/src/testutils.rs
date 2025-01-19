use std::fs::File;
use std::io::BufReader;
use std::path::Path;
use anyhow::Error;
use nix::libc;
use nix::sys::socket;
use nix::sys::socket::{SockFlag, SockType};
use serde_json::Value;
use syscalls::syscall_args;
use crate::instruction::{Arch, SECCOMP_RET_ALLOW};
use crate::seccomp::{InstructionData, Rule, Seccomp};

fn filter_syscalls(syscalls: &[Value]) -> Vec<Value> {
    syscalls
        .iter()
        .filter(|syscall| {
            if let Some(includes) = syscall.get("includes") {
                if let Some(arches) = includes.get("arches").and_then(|a| a.as_array()) {
                    // exclude unsupported arch "s390", "s390x", "riscv64"
                    return !arches.iter().any(|arch| {
                        arch.as_str() == Some("s390")
                            || arch.as_str() == Some("s390x")
                            || arch.as_str() == Some("riscv64")
                    });
                }
            }
            true
        })
        .cloned()
        .collect()
}

pub fn read_seccomp_profile(path: &Path) -> Result<(Vec<InstructionData>), Error>{
    let mut inst_data_set: Vec<InstructionData> = Vec::new();

    let file = File::open(path)?;
    let reader = BufReader::new(file);

    // read json file
    let json_value: Value = serde_json::from_reader(reader)?;
    let syscalls = json_value
        .get("syscalls").unwrap().as_array().unwrap();

    for syscall in filter_syscalls(syscalls) {
        let mut rules: Vec<Rule> = Vec::new();
        for syscall in syscall["names"].as_array().unwrap() {
            rules.push(Rule{
                syscall: syscall.as_str().unwrap().to_string(),
                arg_cnt: 0,
                args: syscall_args!(),
                is_notify: false,
            })
        }

        inst_data_set.push(InstructionData {
            arc: Arch::X86,
            def_action: SECCOMP_RET_ALLOW,
            rule_arr: rules,
        });

    }

    Ok(inst_data_set)
}