use crate::instruction::*;
use crate::instruction::{Arch, Instruction, SECCOMP_IOC_MAGIC};
use anyhow::Result;
use core::fmt;
use derive_builder::Builder;
use nix::libc::{
    SECCOMP_FILTER_FLAG_LOG, SECCOMP_FILTER_FLAG_SPEC_ALLOW, SECCOMP_FILTER_FLAG_TSYNC,
    SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV,
};
use nix::{
    errno::Errno,
    ioctl_readwrite, ioctl_write_ptr, libc,
    libc::{SECCOMP_FILTER_FLAG_NEW_LISTENER, SECCOMP_SET_MODE_FILTER},
    unistd,
};
use oci_spec::runtime::{
    Arch as OciSpecArch, LinuxSeccomp, LinuxSeccompAction, LinuxSeccompFilterFlag,
    LinuxSeccompOperator,
};

use std::collections::{HashMap};
use std::io::Write;
use std::str::FromStr;
use std::{
    mem::MaybeUninit,
    os::{
        raw::{c_long, c_uint, c_ulong, c_ushort, c_void},
        unix::io::{AsRawFd, FromRawFd, IntoRawFd, RawFd},
    },
    vec,
};

#[derive(Debug, thiserror::Error)]
pub enum SeccompError {
    #[error("Failed to apply seccomp rules: {0}")]
    Apply(String),
    #[error("valid indices are 0–5")]
    InvalidArgumentSize,
    #[error("Can't ScmpActNotify to default action")]
    InvalidDefaultAction,
    #[error("Can't filter to write system call")]
    InvalidSystemCall,
    #[error("Unknown syscall name: {0}")]
    UnknownSyscall(String),
}

pub struct Seccomp {
    pub filters: Vec<Instruction>,
    pub flags: c_ulong,
}

impl Default for Seccomp {
    fn default() -> Self {
        Seccomp::new()
    }
}

impl Seccomp {
    pub fn new() -> Self {
        Seccomp {
            filters: Vec::new(),
            flags: SECCOMP_FILTER_FLAG_NEW_LISTENER,
        }
    }

    pub fn set_flags(&mut self, flags: Vec<c_ulong>) {
        for flag in flags {
            self.flags |= flag;
        }
    }

    // apply applies the seccomp rules to the current process and return a fd for seccomp notify.
    pub fn apply(&self) -> Result<NotifyFd, SeccompError> {
        let mut prog = Filters {
            len: self.filters.len() as _,
            filter: self.filters.as_ptr(),
        };

        // TODO: Address the case where don't use seccomp notify.
        let notify_fd = unsafe {
            seccomp(
                SECCOMP_SET_MODE_FILTER,
                self.flags,
                &mut prog as *mut _ as *mut c_void,
            )
        };

        Errno::result(notify_fd).map_err(|e| SeccompError::Apply(e.to_string()))?;
        Ok(unsafe { NotifyFd::from_raw_fd(notify_fd as RawFd) })
    }

    pub fn export_bpf<W: Write>(&self, writer: &mut W) -> Result<(), SeccompError> {
        for inst in &self.filters {
            writer
                .write_all(inst.to_bytes().as_slice())
                .map_err(|e| SeccompError::Apply(e.to_string()))?;
        }
        Ok(())
    }

    pub fn print_bpf(&self) {
        for (i, filter) in self.filters.iter().enumerate() {
            println!(
                "#{}  code: {:02x}, jt: {:02}, jf: {:02}, k: {:08x}",
                i + 1,
                filter.code,
                filter.offset_jump_true,
                filter.offset_jump_false,
                filter.multiuse_field
            )
        }
    }
}

#[derive(Debug)]
pub struct NotifyFd {
    fd: RawFd,
}

impl Drop for NotifyFd {
    fn drop(&mut self) {
        unistd::close(self.fd).unwrap()
    }
}

impl FromRawFd for NotifyFd {
    unsafe fn from_raw_fd(fd: RawFd) -> Self {
        NotifyFd { fd }
    }
}

impl IntoRawFd for NotifyFd {
    fn into_raw_fd(self) -> RawFd {
        let NotifyFd { fd } = self;
        fd
    }
}

impl AsRawFd for NotifyFd {
    fn as_raw_fd(&self) -> RawFd {
        self.fd
    }
}

impl NotifyFd {
    pub fn success(&self, v: i64, notify_id: u64) -> nix::Result<()> {
        let mut resp = SeccompNotifResp {
            id: notify_id,
            val: v,
            error: 0,
            flags: 0,
        };

        unsafe { seccomp_notif_ioctl_send(self.fd, &mut resp as *mut _)? };

        Ok(())
    }
}

// TODO: Rename
#[repr(C)]
#[derive(Debug)]
pub struct SeccompData {
    pub nr: libc::c_int,
    pub arch: u32,
    pub instruction_pointer: u64,
    pub args: [u64; 6],
}

#[repr(C)]
#[derive(Debug)]
pub struct SeccompNotif {
    pub id: u64,
    pub pid: u32,
    pub flags: u32,
    pub data: SeccompData,
}

#[repr(C)]
#[derive(Debug)]
pub struct SeccompNotifResp {
    pub id: u64,
    pub val: i64,
    pub error: i32,
    pub flags: u32,
}

#[repr(C)]
#[derive(Debug)]
pub struct SeccompNotifSizes {
    pub seccomp_notif: u16,
    pub seccomp_notif_resp: u16,
    pub seccomp_data: u16,
}

#[repr(C)]
#[derive(Debug)]
pub struct SeccompNotifAddfd {
    pub id: u64,
    pub flags: u32,
    pub srcfd: u32,
    pub newfd: u32,
    pub newfd_flags: u32,
}

ioctl_readwrite!(seccomp_notif_ioctl_recv, SECCOMP_IOC_MAGIC, 0, SeccompNotif);
ioctl_readwrite!(
    seccomp_notif_ioctl_send,
    SECCOMP_IOC_MAGIC,
    1,
    SeccompNotifResp
);
ioctl_write_ptr!(seccomp_notif_ioctl_id_valid, SECCOMP_IOC_MAGIC, 2, u64);
ioctl_write_ptr!(
    seccomp_notif_ioctl_addfd,
    SECCOMP_IOC_MAGIC,
    3,
    SeccompNotifAddfd
);

pub struct Notification<'f> {
    pub notif: SeccompNotif,
    pub fd: &'f NotifyFd,
}

impl<'f> fmt::Debug for Notification<'f> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&self.notif, f)
    }
}

impl NotifyFd {
    pub fn recv(&self) -> nix::Result<Notification> {
        let mut res = MaybeUninit::zeroed();
        let notif = unsafe {
            seccomp_notif_ioctl_recv(self.fd, res.as_mut_ptr())?;
            res.assume_init()
        };

        Ok(Notification { notif, fd: self })
    }
}

unsafe fn seccomp(op: c_uint, flags: c_ulong, args: *mut c_void) -> c_long {
    libc::syscall(libc::SYS_seccomp, op, flags, args)
}

#[repr(C)]
struct Filters {
    pub len: c_ushort,
    pub filter: *const Instruction,
}

fn get_syscall_number(arc: &Arch, name: &str) -> Option<u64> {
    match arc {
        Arch::X86 => match syscalls::x86_64::Sysno::from_str(name) {
            Ok(syscall) => Some(syscall as u64),
            Err(_) => None,
        },
        Arch::AArch64 => match syscalls::aarch64::Sysno::from_str(name) {
            Ok(syscall) => Some(syscall as u64),
            Err(_) => None,
        },
    }
}

// This wrapper type is used to implement the `From` trait while avoiding the orphan rule's restrictions.
pub struct SeccompActionWrapper(pub LinuxSeccompAction);

impl From<SeccompActionWrapper> for u32 {
    fn from(wrapped_action: SeccompActionWrapper) -> Self {
        // Extracts the wrapped LinuxSeccompAction
        let action = wrapped_action.0;
        match action {
            LinuxSeccompAction::ScmpActKill => SECCOMP_RET_KILL_THREAD,
            LinuxSeccompAction::ScmpActTrap => SECCOMP_RET_TRAP,
            LinuxSeccompAction::ScmpActErrno => SECCOMP_RET_ERRNO,
            LinuxSeccompAction::ScmpActTrace => SECCOMP_RET_TRACE,
            LinuxSeccompAction::ScmpActAllow => SECCOMP_RET_ALLOW,
            LinuxSeccompAction::ScmpActKillProcess => SECCOMP_RET_KILL_PROCESS,
            LinuxSeccompAction::ScmpActNotify => SECCOMP_RET_USER_NOTIF,
            LinuxSeccompAction::ScmpActLog => SECCOMP_RET_LOG,
            LinuxSeccompAction::ScmpActKillThread => SECCOMP_RET_KILL_THREAD,
        }
    }
}

impl From<LinuxSeccompOperator> for SeccompCompareOp {
    fn from(op: LinuxSeccompOperator) -> Self {
        match op {
            LinuxSeccompOperator::ScmpCmpNe => SeccompCompareOp::NotEqual,
            LinuxSeccompOperator::ScmpCmpLt => SeccompCompareOp::LessThan,
            LinuxSeccompOperator::ScmpCmpLe => SeccompCompareOp::LessOrEqual,
            LinuxSeccompOperator::ScmpCmpEq => SeccompCompareOp::Equal,
            LinuxSeccompOperator::ScmpCmpGe => SeccompCompareOp::GreaterOrEqual,
            LinuxSeccompOperator::ScmpCmpGt => SeccompCompareOp::GreaterThan,
            LinuxSeccompOperator::ScmpCmpMaskedEq => SeccompCompareOp::MaskedEqual,
        }
    }
}

fn check_seccomp(seccomp: &LinuxSeccomp) -> Result<(), SeccompError> {
    // We don't support notify as default action. After the seccomp filter is
    // created with notify, the container process will have to communicate the
    // returned fd to another process. Therefore, we need the write syscall or
    // otherwise, the write syscall will be block by the seccomp filter causing
    // the container process to hang. `runc` also disallow notify as default
    // action.
    // Note: read and close syscall are also used, because if we can
    // successfully write fd to another process, the other process can choose to
    // handle read/close syscall and allow read and close to proceed as
    // expected.
    if seccomp.default_action() == LinuxSeccompAction::ScmpActNotify {
        // Todo: consider need to porting SeccompError
        return Err(SeccompError::InvalidDefaultAction);
    }

    if let Some(syscalls) = seccomp.syscalls() {
        for syscall in syscalls {
            if syscall.action() == LinuxSeccompAction::ScmpActNotify {
                for name in syscall.names() {
                    if name == "write" {
                        return Err(SeccompError::InvalidSystemCall);
                    }
                }
            }
        }
    }

    Ok(())
}

impl SeccompCompareOp {
    pub fn set_jump_equal(rule_index: usize, args: &mut RuleArgs, jump: &mut JumpTarget) {
        for i in 0..args.values.len() {
            if i == 0 {
                if rule_index == 0 {
                    args.lower_jump.push(JumpTarget { jt: 0, jf: jump.jf });
                } else {
                    args.lower_jump.push(JumpTarget {
                        jt: jump.jt,
                        jf: jump.jf,
                    });
                }
            } else {
                args.lower_jump.push(JumpTarget { jt: jump.jt, jf: 0 });
            }
            jump.increment_one();
        }
        jump.increment_one();
        args.upper_jump.push(JumpTarget { jt: 0, jf: jump.jf });
        jump.increment_two();
    }

    pub fn set_jump_not_equal(args: &mut RuleArgs, jump: &mut JumpTarget) {
        for i in 0..args.values.len() {
            if i == 0 {
                args.lower_jump.push(JumpTarget {
                    jt: jump.jt + 1,
                    jf: jump.jf - 1,
                });
            } else {
                args.lower_jump.push(JumpTarget { jt: jump.jt, jf: 0 });
            }
            jump.increment_one();
        }
        jump.increment_one();
        args.upper_jump.push(JumpTarget { jt: 0, jf: 2 });
        jump.increment_two();
    }
}

fn set_jump_to_rule(rules: &mut Vec<Rule>) {
    // The portion of the BPF instructions generated by each operator that is included in the jump offset to the next rule:
    //
    // Equal/NotEqual:
    // Generated instructions: syscall_check(1) + load_hi(1) + cmp_hi(1) + load_lo(1) + cmp_lo(1) + ret*2(2) = 7 instructions
    // jump_cnt is the remaining instruction after "excluding the two ret instructions and the syscall_check instruction" = 7 - 3 = 4
    //
    // MaskedEqual:
    // Since one upper and one lower AND instruction is added, +2 → However, it is still +4
    // (The reason the syscall_check skip target for MaskedEqual is +6 is due to this addition)
    //
    // LessThan/LessOrEqual/GreaterThan/GreaterOrEqual:
    // Since BPF_JGT/BPF_JGE has one more instruction in the upper comparison, +5

    let mut jump = JumpTarget { jt: 0, jf: 1 };
    for (rule_index, rule) in rules.iter_mut().rev().enumerate() {
        if rule.rule_args.is_empty() {
            if rule_index == 0 {
                rule.jump.jf = jump.jf;
            } else {
                rule.jump.jt = jump.jt;
            }
            jump.increment_one();
        } else {
            let mut cnt = 0;
            for args in rule.rule_args.iter_mut().rev() {
                match args.op {
                    SeccompCompareOp::Equal => {
                        SeccompCompareOp::set_jump_equal(rule_index, args, &mut jump);
                        cnt += 3 + args.values.len();
                        rule.jump.jt = jump.jf;
                    }
                    SeccompCompareOp::NotEqual => {
                        SeccompCompareOp::set_jump_not_equal(args, &mut jump);
                        cnt += 3 + args.values.len();
                        rule.jump.jt = jump.jf;
                    }
                    SeccompCompareOp::GreaterOrEqual
                    | SeccompCompareOp::GreaterThan
                    | SeccompCompareOp::LessOrEqual
                    | SeccompCompareOp::LessThan => {
                        args.lower_jump.push(JumpTarget {
                            jt: jump.jt + 1,
                            jf: 0,
                        });
                        jump.increment_two();

                        args.upper_jump.push(JumpTarget {
                            jt: 0,
                            jf: jump.jf - 1,
                        });
                        jump.increment_two();

                        args.upper_jump.push(JumpTarget { jt: jump.jt, jf: 0 });
                        jump.increment_one();
                        cnt += 5;
                    }
                    SeccompCompareOp::MaskedEqual => {}
                }
                // println!("jump_num {:?}, {}", jump, rule.jump_num);
                // println!("bpf_num :{:?}", bpf_num);
                // println!("upper jumps :{:?}, lower jumps :{:?}", args.upper_vec, args.lower_vec);
            }
            if rule_index != 0 {
                rule.jump.jt = cnt as u8;
            }
            jump.increment_one();
        }
        // println!("rule :{:#?}", rule);
    }
}

pub fn build_syscall_section(
    rules: &mut Vec<Rule>,
    def_action: u32,
) -> Result<Vec<Instruction>, SeccompError> {
    let mut bpf = vec![];
    let mut action = 0;
    let mut is_same_action = false;
    // check filter action is same to all system call or not
    if let Some(rules_action) = check_same_action(rules) {
        action = rules_action;
        is_same_action = true;
    }

    set_jump_to_rule(rules);
    for rule in rules.iter() {
        bpf.extend(Rule::build_instruction(rule, is_same_action)?);
    }

    // insert return bpf code at the end of the filter
    bpf.extend(vec![
        Instruction::stmt(BPF_RET | BPF_K, action),
        Instruction::stmt(BPF_RET | BPF_K, def_action),
    ]);
    // This is not normally reached, but KILL_THREAD is returned just in case.
    bpf.extend(vec![Instruction::stmt(BPF_RET | BPF_K, 0)]);

    Ok(bpf)
}

// check all action for system call is same or not
fn check_same_action(rules: &[Rule]) -> Option<u32> {
    let first = rules.first()?.action;
    if rules.iter().all(|r| r.action == first) {
        Some(first)
    } else {
        None
    }
}

fn merge_same_syscall_args(rule_a: &mut Rule, rule_b: &Rule) {
    if rule_a.rule_args.is_empty() || rule_b.rule_args.is_empty() {
        return;
    }

    for arg_b in &rule_b.rule_args {
        // If rule needs to check multiple arguments with the same index in the same syscall, combine them to one
        if let Some(arg_a) = rule_a
            .rule_args
            .iter_mut()
            .find(|a| a.index == arg_b.index && a.op == arg_b.op)
        {
            for &val in &arg_b.values {
                arg_a.values.push(val);
            }
        } else {
            rule_a.rule_args.push(arg_b.clone());
        }
    }
    for arg in &mut rule_a.rule_args {
        // sort args value by descending
        arg.values.sort_by(|a, b| b.cmp(a));
        arg.values.dedup();
    }
}

fn merge_rule_args(rule: &mut Rule) {
    let mut merged_map: HashMap<(u8, SeccompCompareOp), Vec<u64>> = HashMap::new();

    // Break down the args value and collect the values ​​for each (index, op) section.
    for arg in rule.rule_args.drain(..) {
        merged_map
            .entry((arg.index, arg.op))
            .or_insert_with(Vec::new)
            .extend(arg.values);
    }

    // The merged result is returned to Vec<RuleArgs>
    rule.rule_args = merged_map
        .into_iter()
        .map(|((index, op), values)| RuleArgs {
            index,
            values,
            op,
            lower_jump: vec![],
            upper_jump: vec![],
        })
        .collect();

    rule.rule_args.sort_by_key(|a| a.index);
}

fn sort_and_merge_syscall_rules(rules: &mut Vec<Rule>) {
    // sort by whether check syscall args, and syscall number
    rules.sort_by_key(|r| (!r.rule_args.is_empty(), r.syscall));
    if rules.iter().any(|r| r.rule_args.len() >= 2) {
        return;
    }

    let mut merged: Vec<Rule> = Vec::new();
    for mut rule in rules.drain(..) {
        if let Some(existing) = merged.iter_mut().find(|r| r.syscall == rule.syscall) {
            merge_same_syscall_args(existing, &rule);
            existing.is_notify |= rule.is_notify;
        } else {
            merge_rule_args(&mut rule);
            merged.push(rule);
        }
    }

    *rules = merged;
}

#[derive(Debug, Default)]
pub struct SeccompProgramPlan {
    pub arc: Arch,
    pub def_action: u32,
    pub def_errno_ret: u32,
    pub flags: Vec<c_ulong>,
    pub rules: Vec<Rule>,
}

impl TryFrom<SeccompProgramPlan> for Vec<Instruction> {
    type Error = SeccompError;
    fn try_from(mut inst_data: SeccompProgramPlan) -> Result<Self, SeccompError> {
        sort_and_merge_syscall_rules(&mut inst_data.rules);
        let bpf_prog = build_syscall_section(&mut inst_data.rules, inst_data.def_action)?;
        let jump_num = if inst_data.rules.is_empty() {
            0
        } else {
            bpf_prog.len() - 3
        };
        let mut all_bpf_prog = gen_validate(&inst_data.arc, jump_num);
        all_bpf_prog.extend(bpf_prog);
        Ok(all_bpf_prog)
    }
}

impl TryFrom<LinuxSeccomp> for SeccompProgramPlan {
    type Error = SeccompError;

    fn try_from(seccomp: LinuxSeccomp) -> Result<Self, SeccompError> {
        let mut data: SeccompProgramPlan = Default::default();
        check_seccomp(&seccomp)?;

        if seccomp.default_action() == LinuxSeccompAction::ScmpActErrno {
            if let Some(ret) = seccomp.default_errno_ret() {
                data.def_action = seccomp.default_action().as_u32(Option::from(ret));
            }
        } else {
            data.def_action = u32::from(seccomp.default_action());
        }

        if let Some(flags) = seccomp.flags() {
            for flag in flags {
                match flag {
                    LinuxSeccompFilterFlag::SeccompFilterFlagLog => {
                        data.flags.push(SECCOMP_FILTER_FLAG_LOG)
                    }
                    LinuxSeccompFilterFlag::SeccompFilterFlagTsync => {
                        data.flags.push(SECCOMP_FILTER_FLAG_TSYNC)
                    }
                    LinuxSeccompFilterFlag::SeccompFilterFlagSpecAllow => {
                        data.flags.push(SECCOMP_FILTER_FLAG_SPEC_ALLOW)
                    }
                    LinuxSeccompFilterFlag::SeccompFilterFlagWaitKillableRecv => {
                        data.flags.push(SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV)
                    }
                }
            }
        }

        if let Some(archs) = seccomp.architectures() {
            for &arch in archs {
                // Todo: consider support other Arch
                match arch {
                    OciSpecArch::ScmpArchX86_64 => data.arc = Arch::X86,
                    OciSpecArch::ScmpArchAarch64 => data.arc = Arch::AArch64,
                    _ => {}
                }
            }
        }

        /*
        Todo: how to impl this?
        ctx.set_ctl_nnp(false)
        .map_err(|err| SeccompError::SetCtlNnp { source: err })?;
         */
        if let Some(syscalls) = seccomp.syscalls() {
            for syscall in syscalls {
                for name in syscall.names() {
                    let mut rule = Rule::default();
                    if syscall.action().eq(&LinuxSeccompAction::ScmpActErrno)
                        || syscall.action().eq(&LinuxSeccompAction::ScmpActTrace)
                    {
                        if let Some(errno_ret) = syscall.errno_ret() {
                            rule.action = syscall.action().as_u32(Option::from(errno_ret));
                        }
                    } else {
                        rule.action = u32::from(syscall.action());
                    }
                    rule.is_notify = rule.action == SECCOMP_RET_USER_NOTIF;
                    rule.syscall = get_syscall_number(&data.arc, name)
                        .ok_or_else(|| SeccompError::UnknownSyscall(name.to_string()))?;

                    if let Some(args) = syscall.args() {
                        if syscall.args().iter().len() > 6 {
                            return Err(SeccompError::InvalidArgumentSize);
                        }
                        for arg in args {
                            let mut rule_args = RuleArgs::default();
                            rule_args.index = arg.index() as u8;
                            rule_args.values.push(arg.value());
                            rule_args.op = SeccompCompareOp::from(arg.op());
                            rule.rule_args.push(rule_args);
                        }
                    }
                    data.rules.push(rule);
                }
            }
        }
        Ok(data)
    }
}

#[derive(Builder, Clone, Debug, Default, Eq, Ord, PartialEq, PartialOrd)]
pub struct JumpTarget {
    pub jt: u8,
    pub jf: u8,
}

impl JumpTarget {
    pub fn increment_one(&mut self) {
        self.jt += 1;
        self.jf += 1;
    }

    pub fn increment_two(&mut self) {
        self.jt += 2;
        self.jf += 2;
    }
}
// RuleArgs for check argument of system call
#[derive(Builder, Clone, Debug, Default, Eq, Ord, PartialEq, PartialOrd)]
pub struct RuleArgs {
    pub index: u8,
    pub values: Vec<u64>,
    pub op: SeccompCompareOp,
    pub upper_jump: Vec<JumpTarget>,
    pub lower_jump: Vec<JumpTarget>,
}

#[derive(Builder, Clone, Debug, Default)]
#[builder(setter(into))]
pub struct Rule {
    pub syscall: u64,
    pub action: u32,
    #[builder(default)]
    pub errno_ret: u32,
    #[builder(default)]
    pub rule_args: Vec<RuleArgs>,
    #[builder(default)]
    pub is_notify: bool,
    pub jump: JumpTarget,
}

#[allow(clippy::too_many_arguments)]
impl Rule {
    pub fn new(
        syscall: u64,
        action: u32,
        errno_ret: u32,
        rule_args: Vec<RuleArgs>,
        is_notify: bool,
        jump: JumpTarget,
    ) -> Self {
        Self {
            syscall,
            action,
            errno_ret,
            rule_args,
            is_notify,
            jump,
        }
    }

    fn push_equal(
        bpf_prog: &mut Vec<Instruction>,
        offset: u8,
        rule_arg: &RuleArgs,
    ) {
        // To upper 32bit check of args, load from offset
        // code: 20
        bpf_prog.push(Instruction::stmt(
            BPF_LD | BPF_W | BPF_ABS,
            (offset + 4).into(),
        ));

        // check argument of upper 32bit, if false jump to action
        // code: 15
        for jmp in rule_arg.upper_jump.iter() {
            bpf_prog.push(Instruction::jump(
                BPF_JEQ | BPF_K,
                jmp.jt,
                jmp.jf,
                (rule_arg.values[0] >> 32) as c_uint,
            ));
        }

        // To lower 32bit check of args, load from offset
        // code: 20
        bpf_prog.push(Instruction::stmt(
            BPF_LD | BPF_W | BPF_ABS,
            offset as c_uint,
        ));

        // check argument of lower 32bit, if false jump to action
        // code: 15
        for (i, jmp) in rule_arg.lower_jump.iter().rev().enumerate() {
            bpf_prog.push(Instruction::jump(
                BPF_JEQ | BPF_K,
                jmp.jt,
                jmp.jf,
                rule_arg.values[i] as c_uint,
            ));
        }
    }

    fn push_masked_equal(bpf_prog: &mut Vec<Instruction>, offset: u8, rule_arg: &RuleArgs) {
        // To upper 32bit check of args, load from offset
        bpf_prog.push(Instruction::stmt(
            BPF_LD | BPF_W | BPF_ABS,
            (offset + 4).into(),
        ));
        bpf_prog.push(Instruction::stmt(
            BPF_ALU | BPF_AND | BPF_K,
            (rule_arg.values[0] >> 32) as c_uint,
        ));
        bpf_prog.push(Instruction::jump(
            BPF_JEQ | BPF_K,
            0,
            3,
            (rule_arg.values[0] >> 32) as c_uint,
        ));
        // To lower 32bit check of args, load from offset
        bpf_prog.push(Instruction::stmt(BPF_LD | BPF_W | BPF_ABS, offset.into()));
        bpf_prog.push(Instruction::stmt(
            BPF_ALU | BPF_AND | BPF_K,
            rule_arg.values[0] as c_uint,
        ));
        bpf_prog.push(Instruction::jump(
            BPF_JEQ | BPF_K,
            1,
            0,
            rule_arg.values[0] as c_uint,
        ));
    }

    fn push_cmp_compare(
        bpf_prog: &mut Vec<Instruction>,
        offset: u8,
        rule_arg: &RuleArgs,
        op: SeccompCompareOp,
    ) {
        let (upper_op, lower_op) = match op {
            SeccompCompareOp::GreaterThan | SeccompCompareOp::LessOrEqual => (BPF_JGT, BPF_JGT),
            SeccompCompareOp::LessThan | SeccompCompareOp::GreaterOrEqual => (BPF_JGT, BPF_JGE),
            _ => (0, 0),
        };

        // To upper 32bit check of args, load from offset
        // code: 20
        bpf_prog.push(Instruction::stmt(
            BPF_LD | BPF_W | BPF_ABS,
            (offset + 4).into(),
        ));
        // check argument of upper 32bit, if false jump to action
        for jmp in rule_arg.upper_jump.iter().rev() {
            // println!("values : {:08x}", arg_ctx.rule_arg.values[0]);
            bpf_prog.push(Instruction::jump(
                upper_op | BPF_K,
                jmp.jt,
                jmp.jf,
                (rule_arg.values[0] >> 32) as c_uint,
            ));
        }

        // To check lower 32-bit of the argument
        bpf_prog.push(Instruction::stmt(BPF_LD | BPF_W | BPF_ABS, offset.into()));
        // check argument of lower 32bit, if false jump to action
        for (i, jmp) in rule_arg.lower_jump.iter().rev().enumerate() {
            bpf_prog.push(Instruction::jump(
                lower_op | BPF_K,
                jmp.jt,
                jmp.jf,
                rule_arg.values[i] as c_uint,
            ));
        }
    }

    fn build_instruction_with_args(
        rule: &Rule,
        syscall: &u64,
    ) -> Result<Vec<Instruction>, SeccompError> {
        let mut bpf_prog = vec![];
        for (i, rule_arg) in rule.rule_args.iter().enumerate() {
            let offset = seccomp_data_args_offset(rule_arg.index)?;
            if i == 0 {
                bpf_prog.push(Instruction::jump(
                    BPF_JEQ | BPF_K,
                    0,
                    rule.jump.jt,
                    *syscall as c_uint,
                ));
            }
            match rule_arg.op {
                SeccompCompareOp::NotEqual => {
                    Rule::push_equal(&mut bpf_prog, offset, rule_arg);
                }
                SeccompCompareOp::LessThan => {
                    Rule::push_cmp_compare(
                        &mut bpf_prog,
                        offset,
                        rule_arg,
                        SeccompCompareOp::LessThan,
                    );
                }
                SeccompCompareOp::LessOrEqual => {
                    Rule::push_cmp_compare(
                        &mut bpf_prog,
                        offset,
                        rule_arg,
                        SeccompCompareOp::LessOrEqual,
                    );
                }
                SeccompCompareOp::Equal => {
                    Rule::push_equal(&mut bpf_prog, offset, rule_arg);
                }
                SeccompCompareOp::GreaterOrEqual | SeccompCompareOp::GreaterThan => {
                    Rule::push_cmp_compare(
                        &mut bpf_prog,
                        offset,
                        rule_arg,
                        SeccompCompareOp::GreaterOrEqual,
                    );
                }
                SeccompCompareOp::MaskedEqual => {
                    Rule::push_masked_equal(&mut bpf_prog, offset, rule_arg);
                }
            }
        }

        Ok(bpf_prog)
    }

    pub fn build_instruction(
        rule: &Rule,
        is_same_action: bool,
    ) -> Result<(Vec<Instruction>), SeccompError> {
        let mut bpf_prog = vec![];
        if !rule.rule_args.is_empty() {
            bpf_prog.extend(Rule::build_instruction_with_args(rule, &rule.syscall)?);
        } else if is_same_action {
            bpf_prog.extend(vec![Instruction::jump(
                BPF_JEQ | BPF_K,
                rule.jump.jt,
                rule.jump.jf,
                rule.syscall as c_uint,
            )]);
        } else {
            bpf_prog.extend(vec![Instruction::jump(
                BPF_JEQ | BPF_K,
                0,
                1,
                rule.syscall as c_uint,
            )]);
            bpf_prog.extend(vec![Instruction::stmt(BPF_RET | BPF_K, rule.action)]);
        }
        Ok(bpf_prog)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_syscall_number_x86() {
        let sys_num = get_syscall_number(&Arch::X86, "read");
        assert_eq!(sys_num.unwrap(), 0);
    }

    #[test]
    fn test_get_syscall_number_aarch64() {
        let sys_num = get_syscall_number(&Arch::AArch64, "read");
        assert_eq!(sys_num.unwrap(), 63);
    }

    #[test]
    fn test_build_instruction_x86() {
        let getcwd = get_syscall_number(&Arch::X86, "getcwd").unwrap();
        let rule = RuleBuilder::default()
            .action(SECCOMP_RET_ALLOW)
            .syscall(getcwd)
            .build()
            .expect("failed to build rule");
        let inst =
            Rule::build_instruction(&rule, SECCOMP_RET_ALLOW, true, false, false, 1, &getcwd)
                .unwrap();
        assert_eq!(
            inst[0],
            Instruction::jump(BPF_JEQ | BPF_K, 1, 0, getcwd as c_uint)
        );
    }

    #[test]
    fn test_build_instruction_aarch64() {
        let getcwd = get_syscall_number(&Arch::AArch64, "getcwd").unwrap();
        let rule = RuleBuilder::default()
            .action(SECCOMP_RET_ALLOW)
            .syscall(getcwd)
            .build()
            .expect("failed to build rule");
        let inst =
            Rule::build_instruction(&rule, SECCOMP_RET_ALLOW, true, false, false, 1, &getcwd)
                .unwrap();
        assert_eq!(
            inst[0],
            Instruction::jump(BPF_JEQ | BPF_K, 1, 0, getcwd as c_uint)
        );
    }

    #[test]
    fn test_build_instruction_with_args_x86_equal() {
        let personality = get_syscall_number(&Arch::X86, "personality").unwrap();
        let personality_args = 8;
        let rule_args = RuleArgsBuilder::default()
            .op(SeccompCompareOp::Equal)
            .index(0)
            .values(personality_args)
            .build()
            .expect("failed to build rule");
        let rule = RuleBuilder::default()
            .syscall(personality)
            .action(SECCOMP_RET_ALLOW)
            .rule_args(vec![rule_args.clone()])
            .build()
            .expect("failed to build rule");
        let offset = seccomp_data_args_offset(rule_args.index).unwrap();
        let inst = Rule::build_instruction_with_args(&rule, &personality, SECCOMP_RET_ALLOW, true)
            .unwrap();

        assert_eq!(
            inst[0],
            Instruction::jump(BPF_JEQ | BPF_K, 0, 4, personality as c_uint)
        );
        assert_eq!(
            inst[1],
            Instruction::stmt(BPF_LD | BPF_W | BPF_ABS, (offset + 4).into())
        );
        assert_eq!(
            inst[2],
            Instruction::jump(BPF_JEQ | BPF_K, 0, 2, (personality_args >> 32) as c_uint)
        );
        assert_eq!(
            inst[3],
            Instruction::stmt(BPF_LD | BPF_W | BPF_ABS, offset.into())
        );
        assert_eq!(
            inst[4],
            Instruction::jump(BPF_JEQ | BPF_K, 1, 0, personality_args as c_uint)
        );
    }

    #[test]
    fn test_build_instruction_with_args_aarch64_equal() {
        let personality = get_syscall_number(&Arch::AArch64, "personality").unwrap();
        let personality_args = 8;
        let rule_args = RuleArgsBuilder::default()
            .op(SeccompCompareOp::Equal)
            .index(0)
            .values(personality_args)
            .build()
            .expect("failed to build rule");
        let rule = RuleBuilder::default()
            .syscall(personality)
            .action(SECCOMP_RET_ALLOW)
            .rule_args(vec![rule_args.clone()])
            .build()
            .expect("failed to build rule");
        let offset = seccomp_data_args_offset(rule_args.index).unwrap();
        let inst = Rule::build_instruction_with_args(&rule, &personality, SECCOMP_RET_ALLOW, true)
            .unwrap();

        assert_eq!(
            inst[0],
            Instruction::jump(BPF_JEQ | BPF_K, 0, 4, personality as c_uint)
        );
        assert_eq!(
            inst[1],
            Instruction::stmt(BPF_LD | BPF_W | BPF_ABS, (offset + 4) as c_uint)
        );
        assert_eq!(
            inst[2],
            Instruction::jump(BPF_JEQ | BPF_K, 0, 2, (personality_args >> 32) as c_uint)
        );
        assert_eq!(
            inst[3],
            Instruction::stmt(BPF_LD | BPF_W | BPF_ABS, offset.into())
        );
        assert_eq!(
            inst[4],
            Instruction::jump(BPF_JEQ | BPF_K, 1, 0, personality_args as c_uint)
        );
    }

    #[test]
    fn test_build_instruction_with_args_x86_not_equal() {
        let personality = get_syscall_number(&Arch::X86, "personality").unwrap();
        let personality_args = 8;
        let rule_args = RuleArgsBuilder::default()
            .op(SeccompCompareOp::NotEqual)
            .index(0)
            .values(personality_args)
            .build()
            .expect("failed to build rule");
        let rule = RuleBuilder::default()
            .syscall(personality)
            .action(SECCOMP_RET_ALLOW)
            .rule_args(vec![rule_args.clone()])
            .build()
            .expect("failed to build rule");
        let offset = seccomp_data_args_offset(rule_args.index).unwrap();
        let inst = Rule::build_instruction_with_args(&rule, &personality, SECCOMP_RET_ALLOW, true)
            .unwrap();

        assert_eq!(
            inst[0],
            Instruction::jump(BPF_JEQ | BPF_K, 0, 5, personality as c_uint)
        );
        assert_eq!(
            inst[1],
            Instruction::stmt(BPF_LD | BPF_W | BPF_ABS, (offset + 4).into())
        );
        assert_eq!(
            inst[2],
            Instruction::jump(BPF_JEQ | BPF_K, 0, 2, (personality_args >> 32) as c_uint)
        );
        assert_eq!(
            inst[3],
            Instruction::stmt(BPF_LD | BPF_W | BPF_ABS, offset.into())
        );
        assert_eq!(
            inst[4],
            Instruction::jump(BPF_JEQ | BPF_K, 1, 0, personality_args as c_uint)
        );
    }

    #[test]
    fn test_build_instruction_with_args_aarch64_not_equal() {
        let personality = get_syscall_number(&Arch::AArch64, "personality").unwrap();
        let personality_args = 8;
        let rule_args = RuleArgsBuilder::default()
            .op(SeccompCompareOp::NotEqual)
            .index(0)
            .values(personality_args)
            .build()
            .expect("failed to build rule");
        let rule = RuleBuilder::default()
            .syscall(personality)
            .action(SECCOMP_RET_ALLOW)
            .rule_args(vec![rule_args.clone()])
            .build()
            .expect("failed to build rule");
        let offset = seccomp_data_args_offset(rule_args.index).unwrap();
        let inst = Rule::build_instruction_with_args(&rule, &personality, SECCOMP_RET_ALLOW, true)
            .unwrap();

        assert_eq!(
            inst[0],
            Instruction::jump(BPF_JEQ | BPF_K, 0, 5, personality as c_uint)
        );
        assert_eq!(
            inst[1],
            Instruction::stmt(BPF_LD | BPF_W | BPF_ABS, (offset + 4).into())
        );
        assert_eq!(
            inst[2],
            Instruction::jump(BPF_JEQ | BPF_K, 0, 2, (personality_args >> 32) as c_uint)
        );
        assert_eq!(
            inst[3],
            Instruction::stmt(BPF_LD | BPF_W | BPF_ABS, offset.into())
        );
        assert_eq!(
            inst[4],
            Instruction::jump(BPF_JEQ | BPF_K, 1, 0, personality_args as c_uint)
        );
    }

    #[test]
    fn test_build_instruction_with_args_x86_less_than() {
        let personality = get_syscall_number(&Arch::X86, "personality").unwrap();
        let personality_args = 8;
        let rule_args = RuleArgsBuilder::default()
            .op(SeccompCompareOp::LessThan)
            .index(0)
            .values(personality_args)
            .build()
            .expect("failed to build rule");
        let rule = RuleBuilder::default()
            .syscall(personality)
            .action(SECCOMP_RET_ALLOW)
            .rule_args(vec![rule_args.clone()])
            .build()
            .expect("failed to build rule");
        let offset = seccomp_data_args_offset(rule_args.index).unwrap();
        let inst = Rule::build_instruction_with_args(&rule, &personality, SECCOMP_RET_ALLOW, true)
            .unwrap();

        assert_eq!(
            inst[0],
            Instruction::jump(BPF_JEQ | BPF_K, 0, 5, personality as c_uint)
        );
        assert_eq!(
            inst[1],
            Instruction::stmt(BPF_LD | BPF_W | BPF_ABS, (offset + 4).into())
        );
        assert_eq!(
            inst[2],
            Instruction::jump(BPF_JGE | BPF_K, 0, 4, (personality_args >> 32) as c_uint)
        );
        assert_eq!(
            inst[3],
            Instruction::jump(BPF_JEQ | BPF_K, 0, 2, (personality_args >> 32) as c_uint)
        );
        assert_eq!(
            inst[4],
            Instruction::stmt(BPF_LD | BPF_W | BPF_ABS, offset.into())
        );
        assert_eq!(
            inst[5],
            Instruction::jump(BPF_JGE | BPF_K, 0, 1, personality_args as c_uint)
        );
    }

    #[test]
    fn test_build_instruction_with_args_aarch64_less_than() {
        let personality = get_syscall_number(&Arch::AArch64, "personality").unwrap();
        let personality_args = 8;
        let rule_args = RuleArgsBuilder::default()
            .op(SeccompCompareOp::LessThan)
            .index(0)
            .values(personality_args)
            .build()
            .expect("failed to build rule");
        let rule = RuleBuilder::default()
            .syscall(personality)
            .action(SECCOMP_RET_ALLOW)
            .rule_args(vec![rule_args.clone()])
            .build()
            .expect("failed to build rule");
        let offset = seccomp_data_args_offset(rule_args.index).unwrap();
        let inst = Rule::build_instruction_with_args(&rule, &personality, SECCOMP_RET_ALLOW, true)
            .unwrap();

        assert_eq!(
            inst[0],
            Instruction::jump(BPF_JEQ | BPF_K, 0, 5, personality as c_uint)
        );
        assert_eq!(
            inst[1],
            Instruction::stmt(BPF_LD | BPF_W | BPF_ABS, (offset + 4).into())
        );
        assert_eq!(
            inst[2],
            Instruction::jump(BPF_JGE | BPF_K, 0, 4, (personality_args >> 32) as c_uint)
        );
        assert_eq!(
            inst[3],
            Instruction::jump(BPF_JEQ | BPF_K, 0, 2, (personality_args >> 32) as c_uint)
        );
        assert_eq!(
            inst[4],
            Instruction::stmt(BPF_LD | BPF_W | BPF_ABS, offset.into())
        );
        assert_eq!(
            inst[5],
            Instruction::jump(BPF_JGE | BPF_K, 0, 1, personality_args as c_uint)
        );
    }

    #[test]
    fn test_build_instruction_with_args_x86_less_or_equal() {
        let personality = get_syscall_number(&Arch::X86, "personality").unwrap();
        let personality_args = 8;
        let rule_args = RuleArgsBuilder::default()
            .op(SeccompCompareOp::LessOrEqual)
            .index(0)
            .values(personality_args)
            .build()
            .expect("failed to build rule");
        let rule = RuleBuilder::default()
            .syscall(personality)
            .action(SECCOMP_RET_ALLOW)
            .rule_args(vec![rule_args.clone()])
            .build()
            .expect("failed to build rule");
        let offset = seccomp_data_args_offset(rule_args.index).unwrap();
        let inst = Rule::build_instruction_with_args(&rule, &personality, SECCOMP_RET_ALLOW, true)
            .unwrap();

        assert_eq!(
            inst[0],
            Instruction::jump(BPF_JEQ | BPF_K, 0, 5, personality as c_uint)
        );
        assert_eq!(
            inst[1],
            Instruction::stmt(BPF_LD | BPF_W | BPF_ABS, (offset + 4).into())
        );
        assert_eq!(
            inst[2],
            Instruction::jump(BPF_JGE | BPF_K, 0, 4, (personality_args >> 32) as c_uint)
        );
        assert_eq!(
            inst[3],
            Instruction::jump(BPF_JEQ | BPF_K, 0, 2, (personality_args >> 32) as c_uint)
        );
        assert_eq!(
            inst[4],
            Instruction::stmt(BPF_LD | BPF_W | BPF_ABS, offset.into())
        );
        assert_eq!(
            inst[5],
            Instruction::jump(BPF_JGT | BPF_K, 0, 1, personality_args as c_uint)
        );
    }

    #[test]
    fn test_build_instruction_with_args_aarch64_less_or_equal() {
        let personality = get_syscall_number(&Arch::AArch64, "personality").unwrap();
        let personality_args = 8;
        let rule_args = RuleArgsBuilder::default()
            .op(SeccompCompareOp::LessOrEqual)
            .index(0)
            .values(personality_args)
            .build()
            .expect("failed to build rule");
        let rule = RuleBuilder::default()
            .syscall(personality)
            .action(SECCOMP_RET_ALLOW)
            .rule_args(vec![rule_args.clone()])
            .build()
            .expect("failed to build rule");
        let offset = seccomp_data_args_offset(rule_args.index).unwrap();
        let inst = Rule::build_instruction_with_args(&rule, &personality, SECCOMP_RET_ALLOW, true)
            .unwrap();

        assert_eq!(
            inst[0],
            Instruction::jump(BPF_JEQ | BPF_K, 0, 5, personality as c_uint)
        );
        assert_eq!(
            inst[1],
            Instruction::stmt(BPF_LD | BPF_W | BPF_ABS, (offset + 4).into())
        );
        assert_eq!(
            inst[2],
            Instruction::jump(BPF_JGE | BPF_K, 0, 4, (personality_args >> 32) as c_uint)
        );
        assert_eq!(
            inst[3],
            Instruction::jump(BPF_JEQ | BPF_K, 0, 2, (personality_args >> 32) as c_uint)
        );
        assert_eq!(
            inst[4],
            Instruction::stmt(BPF_LD | BPF_W | BPF_ABS, offset.into())
        );
        assert_eq!(
            inst[5],
            Instruction::jump(BPF_JGT | BPF_K, 0, 1, personality_args as c_uint)
        );
    }

    #[test]
    fn test_build_instruction_with_args_x86_greater_or_equal() {
        let personality = get_syscall_number(&Arch::X86, "personality").unwrap();
        let personality_args = 8;
        let rule_args = RuleArgsBuilder::default()
            .op(SeccompCompareOp::GreaterOrEqual)
            .index(0)
            .values(personality_args)
            .build()
            .expect("failed to build rule");
        let rule = RuleBuilder::default()
            .syscall(personality)
            .action(SECCOMP_RET_ALLOW)
            .rule_args(vec![rule_args.clone()])
            .build()
            .expect("failed to build rule");
        let offset = seccomp_data_args_offset(rule_args.index).unwrap();
        let inst = Rule::build_instruction_with_args(&rule, &personality, SECCOMP_RET_ALLOW, true)
            .unwrap();

        assert_eq!(
            inst[0],
            Instruction::jump(BPF_JEQ | BPF_K, 0, 5, personality as c_uint)
        );
        assert_eq!(
            inst[1],
            Instruction::stmt(BPF_LD | BPF_W | BPF_ABS, (offset + 4).into())
        );
        assert_eq!(
            inst[2],
            Instruction::jump(BPF_JGT | BPF_K, 4, 0, (personality_args >> 32) as c_uint)
        );
        assert_eq!(
            inst[3],
            Instruction::jump(BPF_JEQ | BPF_K, 0, 2, (personality_args >> 32) as c_uint)
        );
        assert_eq!(
            inst[4],
            Instruction::stmt(BPF_LD | BPF_W | BPF_ABS, offset.into())
        );
        assert_eq!(
            inst[5],
            Instruction::jump(BPF_JGE | BPF_K, 1, 0, personality_args as c_uint)
        );
    }

    #[test]
    fn test_build_instruction_with_args_aarch64_greater_or_equal() {
        let personality = get_syscall_number(&Arch::AArch64, "personality").unwrap();
        let personality_args = 8;
        let rule_args = RuleArgsBuilder::default()
            .op(SeccompCompareOp::GreaterOrEqual)
            .index(0)
            .values(personality_args)
            .build()
            .expect("failed to build rule");
        let rule = RuleBuilder::default()
            .syscall(personality)
            .action(SECCOMP_RET_ALLOW)
            .rule_args(vec![rule_args.clone()])
            .build()
            .expect("failed to build rule");
        let offset = seccomp_data_args_offset(rule_args.index).unwrap();
        let inst = Rule::build_instruction_with_args(&rule, &personality, SECCOMP_RET_ALLOW, true)
            .unwrap();

        assert_eq!(
            inst[0],
            Instruction::jump(BPF_JEQ | BPF_K, 0, 5, personality as c_uint)
        );
        assert_eq!(
            inst[1],
            Instruction::stmt(BPF_LD | BPF_W | BPF_ABS, (offset + 4).into())
        );
        assert_eq!(
            inst[2],
            Instruction::jump(BPF_JGT | BPF_K, 4, 0, (personality_args >> 32) as c_uint)
        );
        assert_eq!(
            inst[3],
            Instruction::jump(BPF_JEQ | BPF_K, 0, 2, (personality_args >> 32) as c_uint)
        );
        assert_eq!(
            inst[4],
            Instruction::stmt(BPF_LD | BPF_W | BPF_ABS, offset.into())
        );
        assert_eq!(
            inst[5],
            Instruction::jump(BPF_JGE | BPF_K, 1, 0, personality_args as c_uint)
        );
    }

    #[test]
    fn test_build_instruction_with_args_x86_greater_than() {
        let personality = get_syscall_number(&Arch::X86, "personality").unwrap();
        let personality_args = 8;
        let rule_args = RuleArgsBuilder::default()
            .op(SeccompCompareOp::GreaterThan)
            .index(0)
            .values(personality_args)
            .build()
            .expect("failed to build rule");
        let rule = RuleBuilder::default()
            .syscall(personality)
            .action(SECCOMP_RET_ALLOW)
            .rule_args(vec![rule_args.clone()])
            .build()
            .expect("failed to build rule");
        let offset = seccomp_data_args_offset(rule_args.index).unwrap();
        let inst = Rule::build_instruction_with_args(&rule, &personality, SECCOMP_RET_ALLOW, true)
            .unwrap();

        assert_eq!(
            inst[0],
            Instruction::jump(BPF_JEQ | BPF_K, 0, 5, personality as c_uint)
        );
        assert_eq!(
            inst[1],
            Instruction::stmt(BPF_LD | BPF_W | BPF_ABS, (offset + 4).into())
        );
        assert_eq!(
            inst[2],
            Instruction::jump(BPF_JGT | BPF_K, 4, 0, (personality_args >> 32) as c_uint)
        );
        assert_eq!(
            inst[3],
            Instruction::jump(BPF_JEQ | BPF_K, 0, 2, (personality_args >> 32) as c_uint)
        );
        assert_eq!(
            inst[4],
            Instruction::stmt(BPF_LD | BPF_W | BPF_ABS, offset.into())
        );
        assert_eq!(
            inst[5],
            Instruction::jump(BPF_JGE | BPF_K, 1, 0, personality_args as c_uint)
        );
    }

    #[test]
    fn test_build_instruction_with_args_aarch64_greater_than() {
        let personality = get_syscall_number(&Arch::AArch64, "personality").unwrap();
        let personality_args = 8;
        let rule_args = RuleArgsBuilder::default()
            .op(SeccompCompareOp::GreaterThan)
            .index(0)
            .values(personality_args)
            .build()
            .expect("failed to build rule");
        let rule = RuleBuilder::default()
            .syscall(personality)
            .action(SECCOMP_RET_ALLOW)
            .rule_args(vec![rule_args.clone()])
            .build()
            .expect("failed to build rule");
        let offset = seccomp_data_args_offset(rule_args.index).unwrap();
        let inst = Rule::build_instruction_with_args(&rule, &personality, SECCOMP_RET_ALLOW, true)
            .unwrap();

        assert_eq!(
            inst[0],
            Instruction::jump(BPF_JEQ | BPF_K, 0, 5, personality as c_uint)
        );
        assert_eq!(
            inst[1],
            Instruction::stmt(BPF_LD | BPF_W | BPF_ABS, (offset + 4).into())
        );
        assert_eq!(
            inst[2],
            Instruction::jump(BPF_JGT | BPF_K, 4, 0, (personality_args >> 32) as c_uint)
        );
        assert_eq!(
            inst[3],
            Instruction::jump(BPF_JEQ | BPF_K, 0, 2, (personality_args >> 32) as c_uint)
        );
        assert_eq!(
            inst[4],
            Instruction::stmt(BPF_LD | BPF_W | BPF_ABS, offset.into())
        );
        assert_eq!(
            inst[5],
            Instruction::jump(BPF_JGE | BPF_K, 1, 0, personality_args as c_uint)
        );
    }

    #[test]
    fn test_build_instruction_with_args_x86_masked_equal() {
        let personality = get_syscall_number(&Arch::X86, "personality").unwrap();
        let personality_args = 8;
        let rule_args = RuleArgsBuilder::default()
            .op(SeccompCompareOp::MaskedEqual)
            .index(0)
            .values(personality_args)
            .build()
            .expect("failed to build rule");
        let rule = RuleBuilder::default()
            .syscall(personality)
            .action(SECCOMP_RET_ALLOW)
            .rule_args(vec![rule_args.clone()])
            .build()
            .expect("failed to build rule");
        let offset = seccomp_data_args_offset(rule_args.index).unwrap();
        let inst = Rule::build_instruction_with_args(&rule, &personality, SECCOMP_RET_ALLOW, true)
            .unwrap();

        assert_eq!(
            inst[0],
            Instruction::jump(BPF_JEQ | BPF_K, 0, 6, personality as c_uint)
        );
        assert_eq!(
            inst[1],
            Instruction::stmt(BPF_LD | BPF_W | BPF_ABS, (offset + 4).into())
        );
        assert_eq!(
            inst[2],
            Instruction::stmt(
                BPF_ALU | BPF_AND | BPF_K,
                (personality_args >> 32) as c_uint
            )
        );
        assert_eq!(
            inst[3],
            Instruction::jump(BPF_JEQ | BPF_K, 0, 3, (personality_args >> 32) as c_uint)
        );
        assert_eq!(
            inst[4],
            Instruction::stmt(BPF_LD | BPF_W | BPF_ABS, offset.into())
        );
        assert_eq!(
            inst[5],
            Instruction::stmt(BPF_ALU | BPF_AND | BPF_K, (personality_args) as c_uint)
        );
        assert_eq!(
            inst[6],
            Instruction::jump(BPF_JEQ | BPF_K, 1, 0, personality_args as c_uint)
        );
    }

    #[test]
    fn test_build_instruction_with_args_aarch64_masked_equal() {
        let personality = get_syscall_number(&Arch::AArch64, "personality").unwrap();
        let personality_args = 8;
        let rule_args = RuleArgsBuilder::default()
            .op(SeccompCompareOp::MaskedEqual)
            .index(0)
            .values(personality_args)
            .build()
            .expect("failed to build rule");
        let rule = RuleBuilder::default()
            .syscall(personality)
            .action(SECCOMP_RET_ALLOW)
            .rule_args(vec![rule_args.clone()])
            .build()
            .expect("failed to build rule");
        let offset = seccomp_data_args_offset(rule_args.index).unwrap();
        let inst = Rule::build_instruction_with_args(&rule, &personality, SECCOMP_RET_ALLOW, true)
            .unwrap();

        assert_eq!(
            inst[0],
            Instruction::jump(BPF_JEQ | BPF_K, 0, 6, personality as c_uint)
        );
        assert_eq!(
            inst[1],
            Instruction::stmt(BPF_LD | BPF_W | BPF_ABS, (offset + 4).into())
        );
        assert_eq!(
            inst[2],
            Instruction::stmt(
                BPF_ALU | BPF_AND | BPF_K,
                (personality_args >> 32) as c_uint
            )
        );
        assert_eq!(
            inst[3],
            Instruction::jump(BPF_JEQ | BPF_K, 0, 3, (personality_args >> 32) as c_uint)
        );
        assert_eq!(
            inst[4],
            Instruction::stmt(BPF_LD | BPF_W | BPF_ABS, offset.into())
        );
        assert_eq!(
            inst[5],
            Instruction::stmt(BPF_ALU | BPF_AND | BPF_K, (personality_args) as c_uint)
        );
        assert_eq!(
            inst[6],
            Instruction::jump(BPF_JEQ | BPF_K, 1, 0, personality_args as c_uint)
        );
    }
}
