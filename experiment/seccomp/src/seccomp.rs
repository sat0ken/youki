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
use std::io::Write;
use std::os::raw::c_uchar;
use std::str::FromStr;
use std::{
    mem::MaybeUninit,
    os::{
        raw::{c_long, c_uint, c_ulong, c_ushort, c_void},
        unix::io::{AsRawFd, FromRawFd, IntoRawFd, RawFd},
    },
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

/// Converts one chunk (up to 254) of syscalls into a sequence of BPF instructions.
/// The jump offset is complete within this chunk, and it is assumed that the matching instruction (an intermediate BPF_RET or a final BPF_RET)
/// comes immediately after the chunk.
fn syscall_to_bpf_chunk(
    def_action: u32,
    rule_chunk: &&[Rule],
    is_same_action: bool,
    is_ealry_return: bool,
) -> Result<Vec<Instruction>, SeccompError> {
    let mut bpf = vec![];

    let n = rule_chunk.len();
    for (i, rule) in rule_chunk.iter().enumerate() {
        let is_last = i == n - 1;
        let remain = n - i;
        bpf.extend(Rule::build_instruction(
            rule,
            def_action,
            is_same_action,
            is_last,
            is_ealry_return,
            remain,
            &rule.syscall,
        )?);
    }

    Ok(bpf)
}

/// Divide the entire rule.syscall into chunks of 254,
/// Construct the BPF instruction sequence so that jt/jf does not exceed 255.
/// Insert BPF_JA + intermediate BPF_RET at the end of non-final chunks.
fn build_syscall_section(
    rules: &Vec<Rule>,
    def_action: u32,
) -> Result<Vec<Instruction>, SeccompError> {
    let mut bpf = vec![];
    let mut chunks: Vec<&[Rule]> = Vec::new();
    let chunk_size = BPF_JMP_MAX;
    let remainder = rules.len() % chunk_size;
    let mut start = 0;

    if remainder != 0 {
        chunks.push(&rules[0..remainder]);
        start = remainder;
    }

    while start < rules.len() {
        let end = std::cmp::min(start + chunk_size, rules.len());
        chunks.push(&rules[start..end]);
        start = end;
    }

    let last_idx = chunks.len().saturating_sub(1);

    let mut action = 0;
    let mut is_same_action = false;
    // check filter action is same to all system call or not
    if let Some(rules_action) = check_same_action(rules) {
        action = rules_action;
        is_same_action = true;
    }

    let has_args = rules.iter().any(|r| !r.rule_args.is_empty());
    for (i, chunk) in chunks.iter().enumerate() {
        if i != last_idx {
            bpf.extend(syscall_to_bpf_chunk(
                def_action,
                chunk,
                is_same_action,
                true,
            )?);
            bpf.push(Instruction::stmt(BPF_RET | BPF_K, action));
        } else {
            bpf.extend(syscall_to_bpf_chunk(
                def_action,
                chunk,
                is_same_action,
                false,
            )?);
        }
    }
    // insert return bpf code at the end of the filter
    // - All rules have the same action and no argument check → Mismatch: default action, Match: action
    // - Each rule has a different action and the rule is empty → default action only
    // - Other cases do not need to be added as they are returned within each rule.
    match (is_same_action, has_args, chunks.is_empty()) {
        (true, false, _) => {
            bpf.push(Instruction::stmt(BPF_RET | BPF_K, def_action));
            bpf.push(Instruction::stmt(BPF_RET | BPF_K, action));
        }
        (false, _, true) => {
            bpf.push(Instruction::stmt(BPF_RET | BPF_K, def_action));
        }
        _ => {}
    }
    // This is not normally reached, but KILL_THREAD is returned just in case.
    bpf.push(Instruction::stmt(BPF_RET | BPF_K, 0));

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
    fn try_from(inst_data: SeccompProgramPlan) -> Result<Self, SeccompError> {
        let bpf_prog = build_syscall_section(inst_data.rules.as_ref(), inst_data.def_action)?;
        let jump_num = if inst_data.rules.is_empty() {
            0
        } else {
            bpf_prog.len() - 2
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
                            rule_args.values = arg.value();
                            rule_args.op = SeccompCompareOp::from(arg.op());
                            rule.rule_args.push(rule_args);
                        }
                    }
                    data.rules.push(rule);
                }
            }
            data.rules.sort_by_key(|rule| rule.syscall);
        }
        Ok(data)
    }
}

struct RuleArgumentContext<'a> {
    syscall: &'a u64,
    offset: u8,
    rule_arg: &'a RuleArgs,
    def_action: u32,
    action: u32,
}

// RuleArgs for check argument of system call
#[derive(Builder, Clone, Debug, Default)]
pub struct RuleArgs {
    pub index: u8,
    pub values: u64,
    pub op: SeccompCompareOp,
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
}

#[allow(clippy::too_many_arguments)]
impl Rule {
    pub fn new(
        syscall: u64,
        action: u32,
        errno_ret: u32,
        rule_args: Vec<RuleArgs>,
        is_notify: bool,
    ) -> Self {
        Self {
            syscall,
            action,
            errno_ret,
            rule_args,
            is_notify,
        }
    }

    fn jump_cnt(rule: &Rule, mut jump_num: usize) -> c_uchar {
        if rule.rule_args.is_empty() {
            jump_num as c_uchar
        } else {
            for rule_args in rule.rule_args.iter() {
                match rule_args.op {
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
                    SeccompCompareOp::Equal
                    | SeccompCompareOp::NotEqual
                    | SeccompCompareOp::MaskedEqual => jump_num += 4,
                    SeccompCompareOp::GreaterThan
                    | SeccompCompareOp::GreaterOrEqual
                    | SeccompCompareOp::LessThan
                    | SeccompCompareOp::LessOrEqual => jump_num += 5,
                }
            }
            jump_num as c_uchar
        }
    }

    fn push_equal(
        bpf_prog: &mut Vec<Instruction>,
        arg_ctx: RuleArgumentContext,
        op: SeccompCompareOp,
    ) {
        let equal = op == SeccompCompareOp::Equal;
        // skip_jump_num is if syscall not matched, jump num to action
        // if equal is 4, not equal is 5
        let skip_jump_num = if equal { 4 } else { 5 };
        let (first_ret, second_ret) = if equal {
            (arg_ctx.def_action, arg_ctx.action)
        } else {
            (arg_ctx.action, arg_ctx.def_action)
        };

        // if system call number is not match, skip args check jump to default action
        bpf_prog.push(Instruction::jump(
            BPF_JEQ | BPF_K,
            0,
            skip_jump_num,
            *arg_ctx.syscall as c_uint,
        ));
        // To upper 32bit check of args, load from offset
        bpf_prog.push(Instruction::stmt(
            BPF_LD | BPF_W | BPF_ABS,
            (arg_ctx.offset + 4).into(),
        ));
        // check argument of upper 32bit, if false jump to action
        bpf_prog.push(Instruction::jump(
            BPF_JEQ | BPF_K,
            0,
            2,
            (arg_ctx.rule_arg.values >> 32) as c_uint,
        ));
        // To lower 32bit check of args, load from offset
        bpf_prog.push(Instruction::stmt(
            BPF_LD | BPF_W | BPF_ABS,
            arg_ctx.offset as c_uint,
        ));
        // check argument of lower 32bit, if false jump to action
        bpf_prog.push(Instruction::jump(
            BPF_JEQ | BPF_K,
            1,
            0,
            arg_ctx.rule_arg.values as c_uint,
        ));
        bpf_prog.push(Instruction::stmt(BPF_RET | BPF_K, first_ret));
        bpf_prog.push(Instruction::stmt(BPF_RET | BPF_K, second_ret));
    }

    fn push_masked_equal(bpf_prog: &mut Vec<Instruction>, arg_ctx: RuleArgumentContext) {
        // if system call number is not match, skip args check jf 4 to default action
        bpf_prog.push(Instruction::jump(
            BPF_JEQ | BPF_K,
            0,
            6,
            *arg_ctx.syscall as c_uint,
        ));

        // To upper 32bit check of args, load from offset
        bpf_prog.push(Instruction::stmt(
            BPF_LD | BPF_W | BPF_ABS,
            (arg_ctx.offset + 4).into(),
        ));
        bpf_prog.push(Instruction::stmt(
            BPF_ALU | BPF_AND | BPF_K,
            (arg_ctx.rule_arg.values >> 32) as c_uint,
        ));
        bpf_prog.push(Instruction::jump(
            BPF_JEQ | BPF_K,
            0,
            3,
            (arg_ctx.rule_arg.values >> 32) as c_uint,
        ));
        // To lower 32bit check of args, load from offset
        bpf_prog.push(Instruction::stmt(
            BPF_LD | BPF_W | BPF_ABS,
            arg_ctx.offset.into(),
        ));
        bpf_prog.push(Instruction::stmt(
            BPF_ALU | BPF_AND | BPF_K,
            arg_ctx.rule_arg.values as c_uint,
        ));
        bpf_prog.push(Instruction::jump(
            BPF_JEQ | BPF_K,
            1,
            0,
            arg_ctx.rule_arg.values as c_uint,
        ));
        bpf_prog.push(Instruction::stmt(BPF_RET | BPF_K, arg_ctx.def_action));
        bpf_prog.push(Instruction::stmt(BPF_RET | BPF_K, arg_ctx.action));
    }

    fn push_cmp_compare(
        bpf_prog: &mut Vec<Instruction>,
        arg_ctx: RuleArgumentContext,
        op: SeccompCompareOp,
    ) {
        // 1. Determine instructions and jump offsets
        // Configuration to "short-circuit" based on upper 32-bit comparison
        let (upper_op, upper_jt, upper_jf) = match op {
            SeccompCompareOp::GreaterThan | SeccompCompareOp::GreaterOrEqual => {
                // Greater-than cases: If upper is larger, match is confirmed (skip 4 lines)
                (BPF_JGT, 4, 0)
            }
            // Less-than cases: If upper is greater or equal, it's an immediate mismatch (skip 4 lines)
            _ => (BPF_JGE, 0, 4),
        };

        // Instruction for lower 32-bit comparison
        let lower_op = match op {
            SeccompCompareOp::LessThan => BPF_JGE,
            SeccompCompareOp::LessOrEqual => BPF_JGT,
            _ => BPF_JGE, // Greater-than cases
        };

        // Jump configuration for lower 32-bit match (Greater: 1,0 / Less: 0,1)
        let (lower_jt, lower_jf) = match op {
            SeccompCompareOp::GreaterThan | SeccompCompareOp::GreaterOrEqual => (1, 0),
            _ => (0, 1),
        };

        // 2. Expand common logic
        // Check system call number
        bpf_prog.push(Instruction::jump(
            BPF_JEQ | BPF_K,
            0,
            5,
            *arg_ctx.syscall as c_uint,
        ));

        // Check upper 32-bit of the argument
        bpf_prog.push(Instruction::stmt(
            BPF_LD | BPF_W | BPF_ABS,
            (arg_ctx.offset + 4).into(),
        ));
        bpf_prog.push(Instruction::jump(
            upper_op | BPF_K,
            upper_jt,
            upper_jf,
            (arg_ctx.rule_arg.values >> 32) as c_uint,
        ));

        // Continue to lower 32-bit check only if upper 32-bit is equal
        bpf_prog.push(Instruction::jump(
            BPF_JEQ | BPF_K,
            0,
            2,
            (arg_ctx.rule_arg.values >> 32) as c_uint,
        ));

        // Check lower 32-bit of the argument
        bpf_prog.push(Instruction::stmt(
            BPF_LD | BPF_W | BPF_ABS,
            arg_ctx.offset.into(),
        ));
        bpf_prog.push(Instruction::jump(
            lower_op | BPF_K,
            lower_jt,
            lower_jf,
            arg_ctx.rule_arg.values as c_uint,
        ));

        // Return actions
        bpf_prog.push(Instruction::stmt(BPF_RET | BPF_K, arg_ctx.def_action));
        bpf_prog.push(Instruction::stmt(BPF_RET | BPF_K, arg_ctx.action));
    }

    fn build_instruction_with_args(
        rule: &Rule,
        syscall: &u64,
        def_action: u32,
    ) -> Result<Vec<Instruction>, SeccompError> {
        let mut bpf_prog = vec![];
        for rule_arg in rule.rule_args.iter() {
            let offset = seccomp_data_args_offset(rule_arg.index)?;
            let arg_ctx = RuleArgumentContext {
                syscall,
                offset,
                rule_arg,
                def_action,
                action: rule.action,
            };
            match rule_arg.op {
                SeccompCompareOp::NotEqual => {
                    Rule::push_equal(&mut bpf_prog, arg_ctx, SeccompCompareOp::NotEqual)
                }
                SeccompCompareOp::LessThan => {
                    Rule::push_cmp_compare(&mut bpf_prog, arg_ctx, SeccompCompareOp::LessThan);
                }
                SeccompCompareOp::LessOrEqual => {
                    Rule::push_cmp_compare(&mut bpf_prog, arg_ctx, SeccompCompareOp::LessOrEqual);
                }
                SeccompCompareOp::Equal => {
                    Rule::push_equal(&mut bpf_prog, arg_ctx, SeccompCompareOp::Equal)
                }
                SeccompCompareOp::GreaterOrEqual | SeccompCompareOp::GreaterThan => {
                    Rule::push_cmp_compare(
                        &mut bpf_prog,
                        arg_ctx,
                        SeccompCompareOp::GreaterOrEqual,
                    );
                }
                SeccompCompareOp::MaskedEqual => {
                    Rule::push_masked_equal(&mut bpf_prog, arg_ctx);
                }
            }
        }

        Ok(bpf_prog)
    }

    pub fn build_instruction(
        rule: &Rule,
        def_action: u32,
        is_same_action: bool,
        is_last: bool,
        is_early_return: bool,
        mut jump_num: usize,
        syscall: &u64,
    ) -> Result<Vec<Instruction>, SeccompError> {
        let mut bpf_prog = vec![];
        if is_early_return {
            jump_num -= 1;
        }
        if !rule.rule_args.is_empty() {
            bpf_prog.extend(Rule::build_instruction_with_args(
                rule, syscall, def_action,
            )?);
        } else if is_same_action {
            if is_last && is_early_return {
                bpf_prog.push(Instruction::jump(BPF_JEQ | BPF_K, 0, 1, *syscall as c_uint));
            } else {
                bpf_prog.push(Instruction::jump(
                    BPF_JEQ | BPF_K,
                    jump_num as c_uchar,
                    0,
                    *syscall as c_uint,
                ));
            }
        } else {
            bpf_prog.push(Instruction::jump(
                BPF_JEQ | BPF_K,
                Self::jump_cnt(rule, 0),
                1,
                *syscall as c_uint,
            ));
            bpf_prog.push(Instruction::stmt(BPF_RET | BPF_K, rule.action));
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
        let inst =
            Rule::build_instruction_with_args(&rule, &personality, SECCOMP_RET_ALLOW).unwrap();

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
        let inst =
            Rule::build_instruction_with_args(&rule, &personality, SECCOMP_RET_ALLOW).unwrap();

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
        let inst =
            Rule::build_instruction_with_args(&rule, &personality, SECCOMP_RET_ALLOW).unwrap();

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
        let inst =
            Rule::build_instruction_with_args(&rule, &personality, SECCOMP_RET_ALLOW).unwrap();

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
        let inst =
            Rule::build_instruction_with_args(&rule, &personality, SECCOMP_RET_ALLOW).unwrap();

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
        let inst =
            Rule::build_instruction_with_args(&rule, &personality, SECCOMP_RET_ALLOW).unwrap();

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
        let inst =
            Rule::build_instruction_with_args(&rule, &personality, SECCOMP_RET_ALLOW).unwrap();

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
        let inst =
            Rule::build_instruction_with_args(&rule, &personality, SECCOMP_RET_ALLOW).unwrap();

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
        let inst =
            Rule::build_instruction_with_args(&rule, &personality, SECCOMP_RET_ALLOW).unwrap();

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
        let inst =
            Rule::build_instruction_with_args(&rule, &personality, SECCOMP_RET_ALLOW).unwrap();

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
        let inst =
            Rule::build_instruction_with_args(&rule, &personality, SECCOMP_RET_ALLOW).unwrap();

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
        let inst =
            Rule::build_instruction_with_args(&rule, &personality, SECCOMP_RET_ALLOW).unwrap();

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
        let inst =
            Rule::build_instruction_with_args(&rule, &personality, SECCOMP_RET_ALLOW).unwrap();

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
        let inst =
            Rule::build_instruction_with_args(&rule, &personality, SECCOMP_RET_ALLOW).unwrap();

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
