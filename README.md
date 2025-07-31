# Syslog NIF

[![Build Status](https://github.com/OpenRiak/syslog_nif/actions/workflows/erlang.yml/badge.svg)](https://github.com/OpenRiak/syslog_nif/actions/workflows/erlang.yml)

An Erlang [`logger`](https://www.erlang.org/doc/man/logger.html) backend for Unix `syslog`.

This is a small, fast, stable handler for OTP 21+ applications that need to record log events to the Unix `syslog` subsystem.

## Usage
`syslog` appears to OTP as an application, so it can (and in most cases should) be started automatically by adding `syslog` to the `applications` list in your `<project>.app` file, normally compiled from the `<dir>/src/<project>.app.src` file.

```erlang
{application, sample, [
    {description,   "A sample Erlang application"},
    . . .
    {applications, [
        kernel,
        stdlib,
        syslog,     %% <== include early in the list
        . . .
    ]},
    . . .
```
Here, starting the `sample` application will in turn cause the `syslog` application to be started with the configuration described below.

The application is configured like any other in your `sys.config` file.
An example might look like the following:

```erlang
[
    {kernel, [
        %% consider disabling the default log handler if you ONLY want
        %% syslog output, in which case you should make sure the syslog
        %% application is loaded early in your application's dependencies.
        {logger, [{handler, default, undefined}]}
    ]},
    {syslog, [

        %% openlog initialization values.
        {identity,  "SampleApp"},
        {facility,  local0},    %% may be overridden by handlers
        {options,   [pid, cons, perror]},

        %% logger handlers, see below
        {logger, [
            {handler, fast_handler, syslog, #{
                config => user, formatter => {syslog, #{
                    depth => 5, max_size => 512
            }}}},
            {handler, alt_handler, syslog, #{config => local3,
                formatter => {logger_formatter, #{single_line => true,
                template => [level," ",pid,":",mfa,":",line,": ",msg]
            }}}}
        ]}
    ]},
    . . .
].
```
> Refer to [syslog.app](./src/syslog.app.src) and below for further details on the above settings.

With this configuration, `syslog` will cause the configured handlers to be loaded once its own initialization is complete.

***Why are the 'logger' handlers specified in the 'syslog' section instead of under 'kernel' where the OTP docs tell me to put them?***

Configuring the `syslog` `logger` handlers inside the `syslog` section ensures that the `syslog` application is up and running before the handlers are added.
Adding the handlers in the `kernel -> logger` section _may_ result in the handlers being added before the `syslog` application is started, resulting in obscure `noproc` exceptions.

### Configuration

`identity` is a string or atom representing your program's name to be included in syslog records.
If not specified, it defaults to the name your program was started with.

`facility` is one of

```erlang
    kernel          %% you probably shouldn't be using this
    user            %% the default if not specified
    mail            %% mail subsystem
    daemon          %% long-running background servers
    auth            %% security/authorization messages
    lpr             %% line printer subsystem
    news            %% network news subsystem
    uucp            %% UUCP subsystem
    cron            %% cron subsystem
    authpriv        %% private security/authorization messages
    ftp             %% FTP daemon
    local0 - local7 %% locally defined classifications
```
`options` is a list containing any combination of the following:

```erlang
    pid             %% log the process ID with each message
    cons            %% log to the system console if logging facility unavailable
    ndelay          %% open the connection to the logging facility immediately
    odelay          %% delay logging facility connection until a log is written
    nowait          %% low-level option, generally deprecated, look it up
    perror          %% log to standard error stream as well
```
If not specified, `options` defaults to `[pid, cons]`.

Handlers are configured as documented for the
 [`logger`](https://www.erlang.org/doc/apps/kernel/logger_chapter.html#configuration)
application.
`syslog` handlers' `config` is a single `facility` atom, or the atom `default` to use the global `syslog` setting:

```erlang
{logger, [
    {handler, <handler-name>, syslog,
        #{config => <facility> | 'default', ...} }
    . . .
]}
```

The built-in formatter in the `syslog` module is optimized for speed, with minimal configuration options:
* `chars_limit`, `depth`, and `max_size` behave as documented for the corresponding
  [`logger_formatter:config()`](https://www.erlang.org/doc/apps/kernel/logger_formatter.html#t:config/0) options.
* `single_line` _may_ be specified with the value `true` and `legacy_header` _may_ be specified with the value `false`.
  * Any other values result in errors from `syslog:check_config/1`.
  * As this is the default behavior, there's no benefit in specifying them, they're allowed only for compatibility.
* Any other keys in the configuration map result in errors from `syslog:check_config/1`.

The built-in formatter's default configuration is roughly analogous to,
but considerably faster than, a `logger_formatter` configuration of:
```
#{
    legacy_header => false,
    single_line => true,
    template => [ level, " ", {pid, [pid, ":"], []},
                  {mfa, [mfa, {line, [":", line, ":"], ":"}, []}, " ", msg ]
}
```
Note that the timestamp and its representation is provided by the OS syslog facility,
not by this handler, so if you do choose to use the `logger_formatter` module's
formatter you should generally _NOT_ include the `time` field in the template.

Handlers may also be added and configured through
 [`logger:add_handler/3`](https://www.erlang.org/doc/man/logger.html#add_handler-3)
and related functions.

## Building
`syslog_nif` is a small
 [Rebar3](http://rebar3.org/docs/)
project that should build and function properly on any current
 [Erlang/OTP](https://www.erlang.org/)
Unix platform with a standard C compiler.

Add the following dependency to your `rebar.config` file's `deps` section and build your project:

```erlang
{deps, [
    . . .
    {syslog,
        {git, "https://github.com/OpenRiak/syslog_nif.git"
            %% The repo's default branch will always be the latest production
            %% version, or you can specify a specific branch if needed.
            , {branch, "openriak-3.2"}
    }}
]}.
```
If you're packaging your application with `relx` be sure to include `syslog` in the list of packaged libraries. Again, adding it near the head of the list is recommended.

## Platform Support
The `syslog` handler supports Linux, BSD, and macOS operating systems.

Other Unix systems _should_ work but are untested.

### Implementation
The implementation relies on OS conformance to the
 [IEEE syslog API](https://pubs.opengroup.org/onlinepubs/9799919799/functions/syslog.html)
and
 [IETF syslog protocol](https://datatracker.ietf.org/doc/html/rfc5424#section-6.2.1) 
standards, supported by all common Unix variants.

Based on this widespread support, we're able to translate directly between atoms representing facilities, levels, and severities and their integral mappings in simple optimized Erlang code to keep the NIF itself small, uncluttered, and _fast_.

The logging path is optimized for throughput, so don't expect to learn much by inspecting the runtime handler configuration without the code in front of you.

> Facility 5 (syslog) is reserved for internal syslog use.<br/>
> Facilities 12-15 vary across platforms and are reserved for system use.<br/>
> Facility _may_ be specified as an integer in the range 0..23 to circumvent the above limitations, but this usage is **_strongly_** discouraged!

## Bugs
What??? No way ...

Yeah, you should probably file an [issue](https://github.com/OpenRiak/syslog_nif/issues).
