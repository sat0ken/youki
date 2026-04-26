use nix::libc::SECCOMP_RET_KILL;
use seccomp::instruction::{Arch, SECCOMP_RET_ALLOW, SeccompCompareOp, gen_validate};
use seccomp::seccomp::{
    Rule, RuleArgs, RuleArgsBuilder, RuleBuilder, Seccomp, build_syscall_section,
};
use std::io;

fn main() -> anyhow::Result<()> {
    let arg_rule0 = RuleArgsBuilder::default()
        .index(0)
        .op(SeccompCompareOp::Equal)
        .values(0)
        .build()?;

    let arg_rule1 = RuleArgsBuilder::default()
        .index(1)
        .op(SeccompCompareOp::Equal)
        .values(1)
        .build()?;

    let arg_rule2 = RuleArgsBuilder::default()
        .index(2)
        .op(SeccompCompareOp::Equal)
        .values(2)
        .build()?;

    let arg_rule3 = RuleArgsBuilder::default()
        .index(3)
        .op(SeccompCompareOp::Equal)
        .values(3)
        .build()?;

    let arg_rule11 = RuleArgsBuilder::default()
        .index(3)
        .op(SeccompCompareOp::Equal)
        .values(11)
        .build()?;

    let arg_rule33 = RuleArgsBuilder::default()
        .index(3)
        .op(SeccompCompareOp::Equal)
        .values(33)
        .build()?;

    let arg_rule_ne1 = RuleArgsBuilder::default()
        .index(1)
        .op(SeccompCompareOp::NotEqual)
        .values(1)
        .build()?;

    let arg_rule_ne3 = RuleArgsBuilder::default()
        .index(3)
        .op(SeccompCompareOp::NotEqual)
        .values(3)
        .build()?;

    let mut rules: Vec<Rule> = vec![];
    // 1000, 2
    rules.extend(vec![
        RuleBuilder::default()
            .syscall(1000u64)
            .action(SECCOMP_RET_ALLOW)
            .rule_args(vec![arg_rule0, arg_rule1])
            .build()?,
    ]);
    // 1000, 1
    rules.extend(vec![
        RuleBuilder::default()
            .syscall(1000u64)
            .action(SECCOMP_RET_ALLOW)
            .rule_args(vec![arg_rule0.clone()])
            .build()?,
    ]);
    // 1001, 1
    rules.extend(vec![
        RuleBuilder::default()
            .syscall(1001u64)
            .action(SECCOMP_RET_ALLOW)
            .rule_args(vec![arg_rule0.clone()])
            .build()?,
    ]);
    // 1001, 2
    rules.extend(vec![
        RuleBuilder::default()
            .syscall(1001u64)
            .action(SECCOMP_RET_ALLOW)
            .rule_args(vec![arg_rule0.clone(), arg_rule1.clone()])
            .build()?,
    ]);
    // 1002, 4
    rules.extend(vec![
        RuleBuilder::default()
            .syscall(1002u64)
            .action(SECCOMP_RET_ALLOW)
            .rule_args(vec![
                arg_rule0.clone(),
                arg_rule1.clone(),
                arg_rule2.clone(),
                arg_rule3.clone(),
            ])
            .build()?,
    ]);
    // 1002, 2
    rules.extend(vec![
        RuleBuilder::default()
            .syscall(1002u64)
            .action(SECCOMP_RET_ALLOW)
            .rule_args(vec![arg_rule0.clone(), arg_rule1.clone()])
            .build()?,
    ]);
    // 1003, 2
    rules.extend(vec![
        RuleBuilder::default()
            .syscall(1003u64)
            .action(SECCOMP_RET_ALLOW)
            .rule_args(vec![arg_rule0.clone(), arg_rule1.clone()])
            .build()?,
    ]);
    // 1003, 4
    rules.extend(vec![
        RuleBuilder::default()
            .syscall(1003u64)
            .action(SECCOMP_RET_ALLOW)
            .rule_args(vec![
                arg_rule0.clone(),
                arg_rule1.clone(),
                arg_rule2.clone(),
                arg_rule3.clone(),
            ])
            .build()?,
    ]);
    // 1004, 4
    rules.extend(vec![
        RuleBuilder::default()
            .syscall(1004u64)
            .action(SECCOMP_RET_ALLOW)
            .rule_args(vec![
                arg_rule0.clone(),
                arg_rule1.clone(),
                arg_rule2.clone(),
                arg_rule3.clone(),
            ])
            .build()?,
    ]);
    // 1004, 2
    rules.extend(vec![
        RuleBuilder::default()
            .syscall(1004u64)
            .action(SECCOMP_RET_ALLOW)
            .rule_args(vec![arg_rule0.clone(), arg_rule11.clone()])
            .build()?,
    ]);
    // 1004, 4
    rules.extend(vec![
        RuleBuilder::default()
            .syscall(1004u64)
            .action(SECCOMP_RET_ALLOW)
            .rule_args(vec![
                arg_rule0.clone(),
                arg_rule1.clone(),
                arg_rule2.clone(),
                arg_rule11.clone(),
            ])
            .build()?,
    ]);
    // 1004, 2
    rules.extend(vec![
        RuleBuilder::default()
            .syscall(1004u64)
            .action(SECCOMP_RET_ALLOW)
            .rule_args(vec![arg_rule1.clone(), arg_rule2.clone()])
            .build()?,
    ]);
    // 1005, 2
    rules.extend(vec![
        RuleBuilder::default()
            .syscall(1005u64)
            .action(SECCOMP_RET_ALLOW)
            .rule_args(vec![arg_rule1.clone(), arg_rule2.clone()])
            .build()?,
    ]);
    // 1005, 4
    rules.extend(vec![
        RuleBuilder::default()
            .syscall(1005u64)
            .action(SECCOMP_RET_ALLOW)
            .rule_args(vec![
                arg_rule0.clone(),
                arg_rule1.clone(),
                arg_rule2.clone(),
                arg_rule3.clone(),
            ])
            .build()?,
    ]);
    // 1005, 2
    rules.extend(vec![
        RuleBuilder::default()
            .syscall(1005u64)
            .action(SECCOMP_RET_ALLOW)
            .rule_args(vec![arg_rule0.clone(), arg_rule1.clone()])
            .build()?,
    ]);
    // 1005, 4
    rules.extend(vec![
        RuleBuilder::default()
            .syscall(1005u64)
            .action(SECCOMP_RET_ALLOW)
            .rule_args(vec![
                arg_rule0.clone(),
                arg_rule1.clone(),
                arg_rule2.clone(),
                arg_rule33.clone(),
            ])
            .build()?,
    ]);
    // 1006, 2
    rules.extend(vec![
        RuleBuilder::default()
            .syscall(1006u64)
            .action(SECCOMP_RET_ALLOW)
            .rule_args(vec![arg_rule_ne1.clone(), arg_rule2.clone()])
            .build()?,
    ]);
    // 1006, 2
    rules.extend(vec![
        RuleBuilder::default()
            .syscall(1006u64)
            .action(SECCOMP_RET_ALLOW)
            .rule_args(vec![arg_rule1.clone(), arg_rule2.clone()])
            .build()?,
    ]);
    // 1006, 1
    rules.extend(vec![
        RuleBuilder::default()
            .syscall(1006u64)
            .action(SECCOMP_RET_ALLOW)
            .rule_args(vec![arg_rule_ne1.clone()])
            .build()?,
    ]);
    // 1007, 2
    rules.extend(vec![
        RuleBuilder::default()
            .syscall(1007u64)
            .action(SECCOMP_RET_ALLOW)
            .rule_args(vec![arg_rule2.clone(), arg_rule3.clone()])
            .build()?,
    ]);
    // 1007, 2
    rules.extend(vec![
        RuleBuilder::default()
            .syscall(1007u64)
            .action(SECCOMP_RET_ALLOW)
            .rule_args(vec![arg_rule2.clone(), arg_rule_ne3.clone()])
            .build()?,
    ]);
    // 1007, 1
    rules.extend(vec![
        RuleBuilder::default()
            .syscall(1007u64)
            .action(SECCOMP_RET_ALLOW)
            .rule_args(vec![arg_rule_ne3.clone()])
            .build()?,
    ]);

    let bpf_prog = build_syscall_section(&rules, SECCOMP_RET_KILL)?;
    let mut all_bpf_prog = gen_validate(&Arch::X86, bpf_prog.len() - 2);
    all_bpf_prog.extend(bpf_prog);

    let mut seccomp = Seccomp::new();
    seccomp.filters = all_bpf_prog;
    seccomp.export_bpf(&mut io::stdout())?;

    Ok(())
}
