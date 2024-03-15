const std = @import("std");

const GenTablesOptions = struct {
    source: []const u8,
    prefix: []const u8,
    output: []const u8,
    lowercase: bool = true,
    uppercase: bool = false,
    i2s: bool = true,
    i2s_transtab: bool = false,
    s2i: bool = true,
    duplicate_ints: bool = false,
};

fn genTables(b: *std.Build, configHeader: *std.Build.Step.ConfigHeader, options: GenTablesOptions) std.Build.LazyPath {
    const source = b.dependency("libaudit", .{});

    const genTablesExec = b.addExecutable(.{
        .name = b.fmt("gen_{s}_h", .{std.fs.path.stem(options.source)}),
        .target = b.host,
        .link_libc = true,
    });

    genTablesExec.addConfigHeader(configHeader);
    genTablesExec.addIncludePath(source.path("auparse"));
    genTablesExec.addIncludePath(source.path("common"));
    genTablesExec.addIncludePath(source.path("lib"));

    genTablesExec.addCSourceFiles(.{
        .root = source.path("lib"),
        .files = &.{
            "gen_tables.c",
        },
        .flags = &.{
            "-D_GNU_SOURCE",
            b.fmt("-DTABLE_H=\"{s}\"", .{options.source}),
        },
    });

    const genTablesStep = b.addRunArtifact(genTablesExec);
    if (options.lowercase) genTablesStep.addArg("--lowercase");
    if (options.uppercase) genTablesStep.addArg("--uppercase");
    if (options.i2s) genTablesStep.addArg("--i2s");
    if (options.i2s_transtab) genTablesStep.addArg("--i2s-transtab");
    if (options.s2i) genTablesStep.addArg("--s2i");
    if (options.duplicate_ints) genTablesStep.addArg("--duplicate-ints");
    genTablesStep.addArg(options.prefix);

    const output = b.allocator.create(std.Build.Step.Run.Output) catch @panic("OOM");
    output.* = .{
        .prefix = "",
        .basename = b.fmt("{s}.h", .{options.output}),
        .generated_file = .{ .step = &genTablesStep.step },
    };
    genTablesStep.captured_stdout = output;
    return .{ .generated_dirname = .{
        .generated = &output.generated_file,
        .up = 0,
    } };
}

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const linkage = b.option(std.builtin.LinkMode, "linkage", "whether to statically or dynamically link the library") orelse @as(std.builtin.LinkMode, if (target.result.isGnuLibC()) .dynamic else .static);

    const source = b.dependency("libaudit", .{});

    const libcap = b.dependency("libcap-ng", .{
        .target = target,
        .optimize = optimize,
        .linkage = linkage,
    });

    const configHeader = b.addConfigHeader(.{
        .style = .{
            .autoconf = source.path("config.h.in"),
        },
        .include_path = "config.h",
    }, .{
        .HAVE_CLOCK_GETTIME = 1,
        .HAVE_CLOCK_SYSCALL = 1,
        .HAVE_DECL_ADDR_NO_RANDOMIZE = 1,
        .HAVE_DECL_AUDIT_FEATURE_VERSION = 1,
        .HAVE_DECL_AUDIT_STATUS_BACKLOG_WAIT_TIME = 1,
        .HAVE_DECL_AUDIT_STATUS_BACKLOG_WAIT_TIME_ACTUAL = 1,
        .HAVE_DECL_AUDIT_VERSION_BACKLOG_WAIT_TIME = 1,
        .HAVE_DLFCN_H = 1,
        .HAVE_EPOLL_CTL = 1,
        .HAVE_EVENTFD = 1,
        .HAVE_FACCESSAT = 1,
        .HAVE_FLOOR = 1,
        .HAVE_INOTIFY_INIT = 1,
        .HAVE_INTTYPES_H = 1,
        .HAVE_IPX_HEADERS = null,
        .HAVE_KERNEL_RWF_T = 1,
        .HAVE_KQUEUE = 1,
        .HAVE_LIBCAP_NG = 1,
        .HAVE_LIBRT = null,
        .HAVE_LIBWRAP = null,
        .HAVE_LINUX_AIO_ABI_H = 1,
        .HAVE_LINUX_FS_H = 1,
        .HAVE_NANOSLEEP = 1,
        .HAVE_POLL = 1,
        .HAVE_POLL_H = 1,
        .HAVE_PORT_CREATE = 1,
        .HAVE_PORT_H = 1,
        .HAVE_POSIX_FALLOCATE = 1,
        .HAVE_PTHREAD_YIELD = 1,
        .HAVE_RAWMEMCHR = @as(?u8, if (target.result.abi.isGnu()) 1 else null),
        .HAVE_SELECT = 1,
        .HAVE_SIGNALFD = 1,
        .HAVE_STDINT_H = 1,
        .HAVE_STDIO_H = 1,
        .HAVE_STDLIB_H = 1,
        .HAVE_STRINGS_H = 1,
        .HAVE_STRING_H = 1,
        .HAVE_STRNDUPA = if (target.result.abi.isGnu()) true else null,
        .HAVE_STRUCT_AUDIT_STATUS_FEATURE_BITMAP = 1,
        .HAVE_SYS_EPOLL_H = 1,
        .HAVE_SYS_EVENTFD_H = 1,
        .HAVE_SYS_EVENT_H = 1,
        .HAVE_SYS_INOTIFY_H = 1,
        .HAVE_SYS_SELECT_H = 1,
        .HAVE_SYS_SIGNALFD_H = 1,
        .HAVE_SYS_STAT_H = 1,
        .HAVE_SYS_TIMERFD_H = 1,
        .HAVE_SYS_TYPES_H = 1,
        .HAVE_UNISTD_H = 1,
        .LT_OBJDIR = "/lib",
        .PACKAGE = "libaudit 4.0",
        .PACKAGE_BUGREPORT = "https://github.com/MidstallSoftware/libaudit.zig/issues",
        .PACKAGE_NAME = "libaudit",
        .PACKAGE_STRING = "\"libaudit 4.0\"",
        .PACKAGE_TARNAME = "libaudit-4.0.tar.gz",
        .PACKAGE_URL = "https://people.redhat.com/sgrubb/audit",
        .PACKAGE_VERSION = "4.0",
        .SIZEOF_LONG = target.result.c_type_bit_size(.long),
        .SIZEOF_TIME_T = "sizeof (time_t)",
        .SIZEOF_UNSIGNED_INT = target.result.c_type_bit_size(.uint),
        .SIZEOF_UNSIGNED_LONG = target.result.c_type_bit_size(.ulong),
        .STDC_HEADERS = true,
        .USE_FANOTIFY = true,
        .USE_GSSAPI = null,
        .USE_LISTENER = true,
        .VERSION = "4.0",
        .WITH_AARCH64 = if (target.result.cpu.arch.isAARCH64()) true else null,
        .WITH_APPARMOR = true,
        .WITH_ARM = if (target.result.cpu.arch.isARM()) true else null,
        .WITH_IO_URING = true,
    });

    const common = b.addStaticLibrary(.{
        .name = "common",
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });

    common.addConfigHeader(configHeader);
    common.addIncludePath(source.path("common"));
    common.addIncludePath(source.path("lib"));

    common.addCSourceFiles(.{
        .root = source.path("common"),
        .files = &.{
            "audit-fgets.c",
            "common.c",
            "strsplit.c",
        },
        .flags = &.{"-D_GNU_SOURCE"},
    });

    const libaudit = std.Build.Step.Compile.create(b, .{
        .name = "audit",
        .root_module = .{
            .target = target,
            .optimize = optimize,
            .link_libc = true,
        },
        .kind = .lib,
        .linkage = linkage,
        .version = .{
            .major = 1,
            .minor = 0,
            .patch = 0,
        },
    });

    libaudit.addConfigHeader(configHeader);
    libaudit.addIncludePath(source.path("common"));
    libaudit.addIncludePath(source.path("lib"));

    libaudit.addIncludePath(genTables(b, configHeader, .{
        .source = source.path("lib/actiontab.h").getPath(source.builder),
        .prefix = "action",
        .output = "actiontabs",
    }));

    if (target.result.cpu.arch.isAARCH64()) {
        libaudit.addIncludePath(genTables(b, configHeader, .{
            .source = source.path("lib/aarch64_table.h").getPath(source.builder),
            .prefix = "aarch64_syscall",
            .output = "aarch64_tables",
        }));
    }

    if (target.result.cpu.arch.isARM()) {
        libaudit.addIncludePath(genTables(b, configHeader, .{
            .source = source.path("lib/arm_table.h").getPath(source.builder),
            .prefix = "arm_syscall",
            .output = "arm_tables",
        }));
    }

    libaudit.addIncludePath(genTables(b, configHeader, .{
        .source = source.path("lib/errtab.h").getPath(source.builder),
        .prefix = "err",
        .output = "errtabs",
        .uppercase = true,
        .lowercase = false,
        .duplicate_ints = true,
    }));

    libaudit.addIncludePath(genTables(b, configHeader, .{
        .source = source.path("lib/fieldtab.h").getPath(source.builder),
        .prefix = "field",
        .output = "fieldtabs",
        .duplicate_ints = true,
    }));

    libaudit.addIncludePath(genTables(b, configHeader, .{
        .source = source.path("lib/flagtab.h").getPath(source.builder),
        .prefix = "flag",
        .output = "flagtabs",
    }));

    libaudit.addIncludePath(genTables(b, configHeader, .{
        .source = source.path("lib/fstypetab.h").getPath(source.builder),
        .prefix = "fstype",
        .output = "fstypetabs",
    }));

    libaudit.addIncludePath(genTables(b, configHeader, .{
        .source = source.path("lib/ftypetab.h").getPath(source.builder),
        .prefix = "ftype",
        .output = "ftypetabs",
    }));

    libaudit.addIncludePath(genTables(b, configHeader, .{
        .source = source.path("lib/i386_table.h").getPath(source.builder),
        .prefix = "i386_syscall",
        .output = "i386_tables",
        .duplicate_ints = true,
    }));

    libaudit.addIncludePath(genTables(b, configHeader, .{
        .source = source.path("lib/machinetab.h").getPath(source.builder),
        .prefix = "machine",
        .output = "machinetabs",
        .duplicate_ints = true,
    }));

    libaudit.addIncludePath(genTables(b, configHeader, .{
        .source = source.path("lib/msg_typetab.h").getPath(source.builder),
        .prefix = "msg_type",
        .output = "msg_typetabs",
        .uppercase = true,
        .lowercase = false,
    }));

    libaudit.addIncludePath(genTables(b, configHeader, .{
        .source = source.path("lib/optab.h").getPath(source.builder),
        .prefix = "op",
        .output = "optabs",
        .s2i = false,
        .lowercase = false,
    }));

    libaudit.addIncludePath(genTables(b, configHeader, .{
        .source = source.path("lib/permtab.h").getPath(source.builder),
        .prefix = "perm",
        .output = "permtabs",
    }));

    libaudit.addIncludePath(genTables(b, configHeader, .{
        .source = source.path("lib/ppc_table.h").getPath(source.builder),
        .prefix = "ppc_syscall",
        .output = "ppc_tables",
    }));

    libaudit.addIncludePath(genTables(b, configHeader, .{
        .source = source.path("lib/s390_table.h").getPath(source.builder),
        .prefix = "s390_syscall",
        .output = "s390_tables",
    }));

    libaudit.addIncludePath(genTables(b, configHeader, .{
        .source = source.path("lib/s390x_table.h").getPath(source.builder),
        .prefix = "s390x_syscall",
        .output = "s390x_tables",
    }));

    libaudit.addIncludePath(genTables(b, configHeader, .{
        .source = source.path("lib/uringop_table.h").getPath(source.builder),
        .prefix = "uringop",
        .output = "uringop_tables",
    }));

    libaudit.addIncludePath(genTables(b, configHeader, .{
        .source = source.path("lib/x86_64_table.h").getPath(source.builder),
        .prefix = "x86_64_syscall",
        .output = "x86_64_tables",
    }));

    libaudit.addCSourceFiles(.{
        .root = source.path("lib"),
        .files = &.{
            "libaudit.c",
            "message.c",
            "netlink.c",
            "lookup_table.c",
            "audit_logging.c",
            "deprecated.c",
        },
        .flags = &.{"-D_GNU_SOURCE"},
    });

    libaudit.linkLibrary(common);
    libaudit.linkLibrary(libcap.artifact("cap-ng"));

    {
        const headers: []const []const u8 = &.{
            "audit-records.h",
            "audit_logging.h",
            "libaudit.h",
        };

        for (headers) |header| {
            const install_file = b.addInstallFileWithDir(source.path(b.pathJoin(&.{ "lib", header })), .header, header);
            b.getInstallStep().dependOn(&install_file.step);
            libaudit.installed_headers.append(&install_file.step) catch @panic("OOM");
        }
    }

    b.installArtifact(libaudit);

    const libauparse = std.Build.Step.Compile.create(b, .{
        .name = "auparse",
        .root_module = .{
            .target = target,
            .optimize = optimize,
            .link_libc = true,
        },
        .kind = .lib,
        .linkage = linkage,
        .version = .{
            .major = 0,
            .minor = 0,
            .patch = 0,
        },
    });

    libauparse.addConfigHeader(configHeader);
    libauparse.addIncludePath(source.path("common"));
    libauparse.addIncludePath(source.path("lib"));
    libauparse.addIncludePath(source.path("src"));

    {
        const headers: []const struct { []const u8, []const u8, ?bool } = &.{
            .{ "normalize_record_maps", "normalize_record_map", false },
            .{ "normalize_syscall_maps", "normalize_syscall_map", null },
            .{ "normalize_obj_kind_maps", "normalize_obj_kind_map", false },
            .{ "normalize_evtypetabs", "evtype", false },
        };

        for (headers) |header| {
            libauparse.addIncludePath(genTables(b, configHeader, .{
                .source = source.path(b.fmt("auparse/{s}.h", .{header[0][0..(header[0].len - 1)]})).getPath(source.builder),
                .prefix = header[1],
                .output = header[0],
                .lowercase = true,
                .i2s = header[2] == false,
                .i2s_transtab = header[2] == true,
                .s2i = header[2] == null,
            }));
        }
    }

    {
        const headers: []const struct { []const u8, []const u8, ?bool } = &.{
            .{ "accesstabs", "access", true },
            .{ "captabs", "cap", false },
            .{ "clocktabs", "clock", false },
            .{ "clone-flagtabs", "clone_flag", true },
            .{ "epoll_ctls", "epoll_ctl", false },
            .{ "famtabs", "fam", false },
            .{ "flagtabs", "flag", true },
            .{ "fcntl-cmdtabs", "fcntl", false },
            .{ "fsconfigs", "fsconfig", false },
            .{ "icmptypetabs", "icmptype", false },
            .{ "ioctlreqtabs", "ioctlreq", false },
            .{ "ipctabs", "ipc", false },
            .{ "ipccmdtabs", "ipccmd", true },
            .{ "ipoptnametabs", "ipoptname", false },
            .{ "ip6optnametabs", "ip6optname", false },
            .{ "mmaptabs", "mmap", true },
            .{ "mounttabs", "mount", true },
            .{ "nfprototabs", "nfproto", false },
            .{ "open-flagtabs", "open_flag", true },
            .{ "persontabs", "person", false },
            .{ "ptracetabs", "ptrace", false },
            .{ "pktoptnametabs", "pktoptname", false },
            .{ "prottabs", "prot", true },
            .{ "recvtabs", "recv", true },
            .{ "rlimittabs", "rlimit", false },
            .{ "schedtabs", "sched", false },
            .{ "seccomptabs", "seccomp", false },
            .{ "seektabs", "seek", false },
            .{ "shm_modetabs", "shm_mode", true },
            .{ "signaltabs", "signal", false },
            .{ "sockleveltabs", "socklevel", false },
            .{ "sockoptnametabs", "sockoptname", false },
            .{ "socktabs", "sock", false },
            .{ "socktypetabs", "sock_type", false },
            .{ "tcpoptnametabs", "tcpoptname", false },
            .{ "typetabs", "type", null },
            .{ "umounttabs", "umount", true },
            .{ "inethooktabs", "inethook", false },
            .{ "netactiontabs", "netaction", false },
            .{ "bpftabs", "bpf", false },
            .{ "openat2-resolvetabs", "openat2_resolve", true },
        };

        for (headers) |header| {
            libauparse.addIncludePath(genTables(b, configHeader, .{
                .source = source.path(b.fmt("auparse/{s}.h", .{header[0][0..(header[0].len - 1)]})).getPath(source.builder),
                .prefix = header[1],
                .output = header[0],
                .lowercase = false,
                .i2s = header[2] == false,
                .i2s_transtab = header[2] == true,
                .s2i = header[2] == null,
            }));
        }
    }

    libauparse.addIncludePath(genTables(b, configHeader, .{
        .source = source.path("auparse/prctl-opt-tab.h").getPath(source.builder),
        .prefix = "prctl_opt",
        .output = "prctl_opttabs",
        .lowercase = false,
        .i2s = true,
        .i2s_transtab = false,
        .s2i = false,
    }));

    libauparse.addIncludePath(source.path("auparse"));

    // NOTE: https://github.com/linux-audit/audit-userspace/issues/358
    libauparse.addCSourceFile(.{
        .file = .{
            .path = "auparse/interpret.c",
        },
        .flags = &.{"-D_GNU_SOURCE"},
    });

    libauparse.addCSourceFiles(.{
        .root = source.path("auparse"),
        .files = &.{
            "auditd-config.c",
            "auparse.c",
            "data_buf.c",
            "ellist.c",
            "expression.c",
            "lru.c",
            "message.c",
            "normalize-llist.c",
            "normalize.c",
            "nvlist.c",
        },
        .flags = &.{"-D_GNU_SOURCE"},
    });

    libauparse.linkLibrary(common);
    libauparse.linkLibrary(libcap.artifact("cap-ng"));

    {
        const headers: []const []const u8 = &.{
            "auparse-defs.h",
            "auparse.h",
        };

        for (headers) |header| {
            const install_file = b.addInstallFileWithDir(source.path(b.pathJoin(&.{ "auparse", header })), .header, header);
            b.getInstallStep().dependOn(&install_file.step);
            libaudit.installed_headers.append(&install_file.step) catch @panic("OOM");
        }
    }

    b.installArtifact(libauparse);
}
