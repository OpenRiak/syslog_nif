%% -*- mode: erlang; erlang-indent-level: 4; indent-tabs-mode: nil -*-
%% -------------------------------------------------------------------
%%
%% Copyright (c) 2023-2025 Workday, Inc.
%%
%% This file is provided to you under the Apache License,
%% Version 2.0 (the "License"); you may not use this file
%% except in compliance with the License.  You may obtain
%% a copy of the License at
%%
%%   http://www.apache.org/licenses/LICENSE-2.0
%%
%% Unless required by applicable law or agreed to in writing,
%% software distributed under the License is distributed on an
%% "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
%% KIND, either express or implied.  See the License for the
%% specific language governing permissions and limitations
%% under the License.
%%
%% -------------------------------------------------------------------
%%
%% @doc A NIF-based `logger' backend for Unix `syslog'.
%%
%% Combined Application/Service/Logger Handler for the `syslog' application.
%%
%% Everything's in one module to optimize direct calls.
%%
%% There is no public API, this module simply sets up the configured
%% handler(s) and services logging requests through the NIF.
%%
%% To the extent reasonable, error results mimic those of the OTP kernel's
%% included handlers and formatter.
%%
%% === Behaviors ===
%% <ul>
%% <li><a
%%  href="https://www.erlang.org/doc/apps/kernel/logger_handler.html"
%%  target="_blank">logger_handler</a></li>
%% <li><a
%%  href="https://www.erlang.org/doc/apps/kernel/logger_formatter.html"
%%  target="_blank">logger_formatter</a></li>
%% </ul>
%% @end
-module(syslog).
-ifndef(EDOC).
-behavior(application).
-behavior(gen_server).
-if(?OTP_RELEASE >= 27).
-behavior(logger_handler).
-behavior(logger_formatter).
-else.  % OTP_RELEASE < 27
%% Because there are no logger_xxx behaviors prior to OTP 27, xref sees the
%% logger callbacks as unused exports, but we can mock behaviors from its
%% perspective ...
%% -behavior(logger_handler):
-ignore_xref([adding_handler/1, changing_config/3, filter_config/1, log/2]).
%% -behavior(logger_formatter):
-ignore_xref([check_config/1, format/2]).
-endif. % OTP_RELEASE
-endif. % EDOC

%% -------------------------------------------------------------------
%%
%% We use a gen_server as the application's only process, there is no
%% supervisor.
%% The gen_server gives us a place to store/access active configuration and
%% serialize calls to non-logging functions, so we don't have to worry about
%% any serialization in the NIF.
%%
%% The `log/2' function doesn't interact with the gen_server in any way and
%% passes as directly as possible through to the NIF - it can be called
%% concurrently by any number of processes and will only be serialized at the
%% OS syslog implementation.
%%
%% Unlike the default OTP logger handlers, everything here runs synchronously
%% in the process of the caller. When used with this module's formatter, the
%% log handler should impose negligible overhead on the calling process. By
%% running in the caller's process a bunch of configuration relating to queue
%% depth and duplicate messages is irrelevant - the log handler is stateless
%% and concurrent, so any notion of "the last message" is meaningless.
%%
%% This module is full of constants, and mapping between atoms and integers is
%% done here rather than in the NIF for simplicity and efficiency.
%% We can use these constants because all known Unixes' syslog implementations
%% derive from the same BSD source, and the priority constants (facility and
%% severity) themselves are defined in the RFC 5424 protocol, so no platform
%% can really change them without making a very large headache for themselves.
%%
%% DO NOT ENABLE INLINING!
%% The compiler 'inline' option WILL break this module, as the NIF stub
%% functions are small enough to be inlined away.
%% Newer compilers will generate a warning that we force to an error with the
%% compiler directive below, but older ones (before OTP 23) will happily
%% generate broken code that unconditionally raises a `syslog_nif_not_loaded'
%% error when the application is started.
%% There are no functions in this module that would benefit from inlining
%% anyway, so there's nothing to be gained (and performance to lose) by
%% breaking the NIF functions out into a separate module.
%%
%% -------------------------------------------------------------------

%% Ensure that the NIF inlining warning from newer compilers results in
%% a compilation error, but older compilers will still slip through so
%% DO NOT ENABLE INLINING!
-compile([warnings_as_errors]).

%% Callbacks
-export([
    %% application callbacks
    start/2,
    stop/1,

    %% gen_server callbacks
    init/1,
    handle_call/3,
    handle_cast/2,
    handle_continue/2,

    %% logger handler callbacks
    adding_handler/1,
    changing_config/3,
    filter_config/1,
    log/2,

    %% logger formatter callbacks
    check_config/1,
    format/2
]).
-ifdef(TIMING_TESTS).
-export([
    timing_test_/0,
    timer_proc/4
]).
-endif. % TIMING_TESTS

-export_type([
    cfg_error/0,
    facility/0,
    fmt_config/0,
    fmt_error/0,
    hnd_config/0,
    hnd_error/0,
    ident/0,
    option/0
]).

-define(CFG_ERROR(Type), {error, {Type, module(), err_map()}}).

-type cfg_error() :: fmt_error() | hnd_error().
-type err_key() :: term().
-type err_map() :: #{err_key() => err_val()}.
-type err_val() :: term().
-type fmt_error() :: ?CFG_ERROR(invalid_formatter_config).
-type hnd_error() :: ?CFG_ERROR(invalid_config).
-type sz_limit() :: pos_integer() | unlimited.

-type fmt_config() :: #{
    chars_limit     => sz_limit(),
    depth           => sz_limit(),
    legacy_header   => false,
    max_size        => sz_limit(),
    report_cb       => logger:report_cb(),
    single_line     => true
}.
-type hnd_config() :: facility() | default.

-type facility() ::
    kernel | user | mail | daemon | auth | lpr | news | uucp | cron |
    authpriv | ftp |
    local0 | local1 | local2 | local3 | local4 | local5 | local6 | local7 |
    0..23.

%% MUST be kept in sync with the named facilities.
-define(FACILITIES, [
    kernel, user, mail, daemon, auth, lpr, news, uucp, cron, authpriv, ftp,
    local0, local1, local2, local3, local4, local5, local6, local7
]).

-type ident() :: atom() | binary() | nonempty_string().
-type option() :: pid | cons | odelay | ndelay | nowait | perror.

%% -------------------------------------------------------------------
%% Internal
%% -------------------------------------------------------------------

-type err_rec() :: {err_key(), err_val()}.
-type err_recs() :: list(err_rec()).

-type fac_int() :: 0..(23 bsl 3).
-type opt_int() :: 0..63.
-type pri_int() :: 0..((23 bsl 3) bor 7).
-type sev_int() :: 0..7.

-type report_cb_1() :: fun((logger:report()) -> {io:format(), list()}).
-type report_cb_2() :: fun((logger:report(), logger:report_cb_config())
    -> unicode:chardata()).

-type config() :: #{
    identity  := ident(),
    facility  := facility(),
    options   := list(option())
}.
-type state() :: #{
    config := config(),
    facmap := #{fac_int() => facility()}
}.

-nifs([
    nif_log/2,
    nif_open/3
]).
-on_load(load_nif_lib/0).

-include_lib("kernel/include/logger.hrl").
-ifdef(EUNIT).
-include_lib("stdlib/include/assert.hrl").
-endif. % EUNIT

-define(APP_NAME,   syslog).
-define(NIF_NAME,   syslog_nif).
-define(SVC_NAME,   ?MODULE).
-define(DFLT_FAC,   user).
-define(DFLT_OPTS,  [pid, cons]).

%% -------------------------------------------------------------------
%% logger_handler callbacks
%% -------------------------------------------------------------------

-spec adding_handler(HConfig :: logger:handler_config() )
        -> {ok, logger:handler_config()} | cfg_error() | {error, term()}.
%% @doc <a
%% href="https://www.erlang.org/doc/apps/kernel/logger_handler.html#c:adding_handler/1"
%% target="_blank">logger_handler:adding_handler/1</a> callback.
adding_handler(HConfig) ->
    gen_server:call(?SVC_NAME, {?FUNCTION_NAME, HConfig}).

-spec changing_config(Mode :: set | update,
    OldHConfig :: logger:handler_config(),
    NewHConfig :: logger:handler_config() )
        -> {ok, logger:handler_config()} | cfg_error() | {error, term()}.
%% @doc <a
%% href="https://www.erlang.org/doc/apps/kernel/logger_handler.html#c:changing_config/3"
%% target="_blank">logger_handler:changing_config/3</a> callback.
changing_config(Mode, OldHConfig, NewHConfig) ->
    gen_server:call(?SVC_NAME, {?FUNCTION_NAME, Mode, OldHConfig, NewHConfig}).

-spec filter_config(HConfig :: logger:handler_config() )
        -> logger:handler_config().
%% @doc <a
%% href="https://www.erlang.org/doc/apps/kernel/logger_handler.html#c:filter_config/1"
%% target="_blank">logger_handler:filter_config/1</a> callback.
filter_config(HConfig) ->
    gen_server:call(?SVC_NAME, {?FUNCTION_NAME, HConfig}).

-spec log(Event :: logger:log_event(), Config :: logger:handler_config() )
        -> ok.
%% @doc <a
%% href="https://www.erlang.org/doc/apps/kernel/logger_handler.html#c:log/2"
%% target="_blank">logger_handler:log/2</a> callback.
%%
%% Does as much prep as possible in Erlang code to spend the briefest
%% possible time in the NIF.
%%
%% Optimized for this module's formatter, which can be called locally.
%% @end
%% Passes the formatted message to the NIF as a null-terminated binary.
%% IMPORTANT! If the binary isn't null terminated, the NIF will raise a badarg.
log(#{level := Level} = Event,
        #{formatter := {?MODULE, FmtConf}, config := Facility} = _HConfig ) ->
    MsgBin = erlang:iolist_to_binary([format(Event, FmtConf), 0]),
    nif_log(Facility bor level(Level), MsgBin);
log(#{level := Level} = Event,
        #{formatter := {FmtMod, FmtConf}, config := Facility} = _HConfig ) ->
    MsgBin = erlang:iolist_to_binary([FmtMod:format(Event, FmtConf), 0]),
    nif_log(Facility bor level(Level), MsgBin).

%% -------------------------------------------------------------------
%% logger_formatter callbacks
%% -------------------------------------------------------------------

-spec check_config(FConfig :: fmt_config() )
        -> ok | fmt_error().
%% @doc <a
%% href="https://www.erlang.org/doc/apps/kernel/logger_formatter.html#c:check_config/1"
%% target="_blank">logger_formatter:check_config/1</a> callback.
%%
%% FConfig is a subset of <a
%% href="https://www.erlang.org/doc/apps/kernel/logger_formatter#t:config/0"
%% target="_blank">logger_formatter:config()</a> restricted to the keys and
%% values specified for {@link fmt_config()}.
%%
%% Note that:<ul>
%% <li>For 'report' events where a 2-parameter `report_cb' function is
%%  specified in either FConfig or the event's metadata, only the
%%  `chars_limit', `depth', and `max_size' values have any effect.</li>
%% <li>For all other log events only the `depth' and `max_size' values
%%  have any effect.</li>
%% <li>The `legacy_header' and `single_line' values are allowed as constrained
%%  by the {@link fmt_config()} specification for compatibility, but are
%%  otherwise ignored.</li>
%% <li>All other `logger_formatter:config()' keys are disallowed and return
%%  an error result.</li>
%% </ul>
check_config(FConfig) ->
    case maps:fold(fun check_config/3, [], FConfig) of
        [] ->
            ok;
        Errors ->
            {error, {invalid_formatter_config,
                ?MODULE, maps:from_list(Errors)}}
    end.

-spec format(
    Event :: logger:log_event(), FConfig :: fmt_config() )
        -> unicode:chardata().
%% @doc <a
%% href="https://www.erlang.org/doc/apps/kernel/logger_formatter.html#c:format/2"
%% target="_blank">logger_formatter:format/2</a> callback.
format(#{msg := {string, Str}, level := Level} = Event,
        #{max_size := Size} = _FConfig) ->
    S1 = lists:flatten(
        [format_level(Level), format_meta(Event), $\s, string:trim(Str)]),
    lists:sublist(S1, Size);
format(#{msg := {string, Str}, level := Level} = Event, _FConfig) ->
    [format_level(Level), format_meta(Event), $\s, string:trim(Str)];
format(#{msg := {report, _Rpt}} = Event, FConfig) ->
    format_report(Event, FConfig);
format(#{msg := {Fmt, Args}} = Event,
        #{chars_limit := CLimit, depth := Depth} = FConfig) ->
    Scan = io_lib:scan_format(Fmt, Args),
    Filt = format_filter(Scan, Depth),
    Text = io_lib:build_text(Filt, [{chars_limit, CLimit}]),
    format(Event#{msg => {string, Text}}, FConfig);
format(#{msg := {Fmt, Args}} = Event, #{chars_limit := CLimit} = FConfig) ->
    Scan = io_lib:scan_format(Fmt, Args),
    Filt = format_filter(Scan),
    Text = io_lib:build_text(Filt, [{chars_limit, CLimit}]),
    format(Event#{msg => {string, Text}}, FConfig);
format(#{msg := {Fmt, Args}} = Event, #{depth := Depth} = FConfig) ->
    Scan = io_lib:scan_format(Fmt, Args),
    Filt = format_filter(Scan, Depth),
    Text = io_lib:build_text(Filt),
    format(Event#{msg => {string, Text}}, FConfig);
format(#{msg := {Fmt, Args}} = Event, FConfig) ->
    Scan = io_lib:scan_format(Fmt, Args),
    Filt = format_filter(Scan),
    Text = io_lib:build_text(Filt),
    format(Event#{msg => {string, Text}}, FConfig).

%% -------------------------------------------------------------------
%% application callbacks
%% -------------------------------------------------------------------

-spec start(
    StartType :: application:start_type(),
    StartArgs :: term() )
        -> {ok, pid()} | cfg_error() | {error, term()}.
%% @hidden
start(_StartType, _StartArgs) ->
    case init_state() of
        {ok, State} ->
            gen_server:start_link({local, ?SVC_NAME}, ?MODULE, State, []);
        Error ->
            Error
    end.

-spec stop(State :: term()) -> Ignored :: ok.
%% @hidden
stop(_State) ->
    ok.

%% -------------------------------------------------------------------
%% gen_server callbacks
%% -------------------------------------------------------------------

-spec init(State :: state())
        -> {ok, state()} | {ok, state(), {continue, term()}} | {stop, term()}.
%% @hidden
init(#{config := Config} = State) ->
    case init_log(Config) of
        ok ->
            %% Return so we're fully initialized before having logger call back
            {ok, State, {continue, add_handlers}};
        {error, Reason} ->
            {stop, Reason}
    end.

-spec handle_call(Request :: term(), From :: {pid(), _}, State :: state())
        -> {reply, term(), state()}.
%% @hidden
handle_call({adding_handler, HConfig}, _From, State) ->
    Result = case maps:get(config, HConfig, default) of
        default ->
            {ok, HConfig#{config =>
                facility(maps:get(facility, maps:get(config, State)))}};
        FacName ->
            case map_config(FacName) of
                {ok, FacInt} ->
                    {ok, HConfig#{config => FacInt}};
                Error ->
                    Error
            end
    end,
    {reply, Result, State};

handle_call({changing_config, _Mode, #{config := FacInt} = _OldHConfig,
        #{config := FacInt} = NewHConfig}, _From, State) ->
    {reply, {ok, NewHConfig}, State};
handle_call({changing_config, _Mode, _OldHConfig,
        #{config := FacName} = NewHConfig}, _From, State) ->
    Result = case map_config(FacName) of
        {ok, FacInt} ->
            {ok, NewHConfig#{config => FacInt}};
        Error ->
            Error
    end,
    {reply, Result, State};

handle_call({filter_config, #{config := FacInt} = HConfig},
        _From, #{config := Config, facmap := FacMap} = State) ->
    FacName = case maps:get(FacInt, FacMap, undefined) of
        undefined ->
            ?LOG_WARNING(
                "invalid facility value ~p for syslog handler ~p",
                [FacInt, maps:get(id, HConfig)]),
            undefined;
        FacVal ->
            FacVal
    end,
    {reply, HConfig#{config => Config#{facility => FacName}}, State};

handle_call(_Req, _From, State) ->
    {reply, ignored ,State}.

-spec handle_cast(Request :: term(), State :: state())
        -> {noreply, state()}.
%% @hidden
handle_cast(_Req, State) ->
    {noreply, State}.

-spec handle_continue(Continue :: term(), State :: state())
        -> {noreply, state()}.
%% @hidden
handle_continue(add_handlers, State) ->
    %% Spawn adding handlers, it'll cause callbacks into the gen_server that
    %% would deadlock if called from this process.
    _ = erlang:spawn(logger, add_handlers, [?APP_NAME]),
    {noreply, State}.

%% -------------------------------------------------------------------
%% Formatter Internal
%% -------------------------------------------------------------------
%%
%% Always single_line ... mostly!
%% It's expensive to filter newlines that may be present in a string or
%% io:format arg, but we can and do clear them out of the format itself.
%%

-spec check_config(
    Key :: term(), Val :: term(), Errors :: list(tuple()) )
        -> list(tuple()).
%% @hidden
%% @doc Map folder for {@link check_config/1}.
check_config(Key, Val, Errors) when
        (Key =:= chars_limit orelse Key =:= depth orelse Key =:= max_size)
        andalso (Val =:= unlimited
            orelse (erlang:is_integer(Val) andalso Val > 0)) ->
    Errors;
check_config(single_line, true, Errors) ->
    Errors;
check_config(legacy_header, false, Errors) ->
    Errors;
check_config(report_cb, CB, Errors) when
        erlang:is_function(CB, 1) orelse erlang:is_function(CB, 2) ->
    Errors;
check_config(Key, Val, Errors) ->
    [{Key, Val} | Errors].

-spec format_filter(Specs :: list(io_lib:format_spec()) )
        -> list(io_lib:format_spec()).
%% @hidden
%% @doc No depth limit specified
format_filter([$\n | Specs]) ->
    [$,, $\s | format_filter(Specs)];
format_filter([#{control_char := $n} | Specs]) ->
    [$,, $\s | format_filter(Specs)];
format_filter([#{control_char := $p} = Spec | Specs]) ->
    [Spec#{width => 0} | format_filter(Specs)];
format_filter([Spec | Specs]) ->
    [Spec | format_filter(Specs)];
format_filter([]) ->
    [].

-spec format_filter(
    Specs :: list(io_lib:format_spec()),
    Depth :: pos_integer() )
        -> list(io_lib:format_spec()).
%% @hidden
%% @doc Depth limit specified
format_filter([$\n | Specs], Depth) ->
    [$,, $\s | format_filter(Specs, Depth)];
format_filter([#{control_char := $n} | Specs], Depth) ->
    [$,, $\s | format_filter(Specs, Depth)];
format_filter([#{control_char := $p, args := [Arg]} = Spec | Specs], Depth) ->
    [Spec#{control_char => $P, width => 0, args => [Arg, Depth]}
        | format_filter(Specs, Depth)];
format_filter([#{control_char := $p, args := Args} = Spec | Specs], Depth) ->
    [Spec#{control_char => $P, width => 0, args => Args ++ [Depth]}
        | format_filter(Specs, Depth)];
format_filter([#{control_char := $w, args := [Arg]} = Spec | Specs], Depth) ->
    [Spec#{control_char => $W, args => [Arg, Depth]}
        | format_filter(Specs, Depth)];
format_filter([#{control_char := $w, args := Args} = Spec | Specs], Depth) ->
    [Spec#{control_char => $W, args => Args ++ [Depth]}
        | format_filter(Specs, Depth)];
format_filter([Spec | Specs], Depth) ->
    [Spec | format_filter(Specs, Depth)];
format_filter([], _Depth) ->
    [].

-spec format_level(Level :: logger:level()) -> nonempty_string().
format_level(emergency) -> "EMERG";
format_level(alert)     -> "ALERT";
format_level(critical)  -> "CRIT";
format_level(error)     -> "ERROR";
format_level(warning)   -> "WARN";
format_level(notice)    -> "NOTICE";
format_level(info)      -> "INFO";
format_level(debug)     -> "DEBUG";
format_level(Level) ->
    erlang:error(badarg, [{?MODULE, ?FUNCTION_NAME}, Level]).

-spec format_meta(Event :: logger:log_event() ) -> unicode:chardata().
format_meta(#{meta := #{mfa := {M, F, A}, line := L, pid := P}}) ->
    io_lib:format(" ~p:~s:~s/~b:~b:", [P, M, F, A, L]);
format_meta(#{meta := #{pid := P}}) ->
    io_lib:format(" ~p:", [P]);
format_meta(_) ->
    [].

-spec format_report(
    Event :: logger:log_event(),
    FConfig :: fmt_config() )
        -> unicode:chardata().
%% @hidden
%% @doc report_cb in FConfig takes precedence over metadata.
format_report(#{msg := {report, Rpt}} = Event, #{report_cb := CB} = FConfig)
        when erlang:is_function(CB, 1) ->
    format(Event#{msg => format_report_cb_1(CB, Rpt)}, FConfig);
format_report(#{msg := {report, Rpt}} = Event, #{report_cb := CB} = FConfig)
        when erlang:is_function(CB, 2) ->
    format(Event#{msg => format_report_cb_2(CB, Rpt, FConfig)}, FConfig);
format_report(
    #{msg := {report, Rpt}, meta := #{report_cb := CB}} = Event, FConfig)
        when erlang:is_function(CB, 1) ->
    format(Event#{msg => format_report_cb_1(CB, Rpt)}, FConfig);
format_report(
    #{msg := {report, Rpt}, meta := #{report_cb := CB}} = Event, FConfig)
        when erlang:is_function(CB, 2) ->
    format(Event#{msg => format_report_cb_2(CB, Rpt, FConfig)}, FConfig);
format_report(#{msg := {report, Rpt}} = Event, FConfig) ->
    format(Event#{msg => logger:format_report(Rpt)}, FConfig).

-spec format_report_cb_1(
    CbFun :: report_cb_1(),
    Report :: logger:report() )
        -> {string, Str :: unicode:chardata()}
        |  {Fmt :: io:format(), Args :: list()}.
format_report_cb_1(CbFun, Report) ->
    try CbFun(Report) of
        {Fmt, Args} = Msg when erlang:is_list(Args), erlang:is_list(Fmt) ->
            Msg;
        {Fmt, Args} = Msg when erlang:is_list(Args), erlang:is_binary(Fmt) ->
            Msg;
        {string, Str} = Msg when erlang:is_list(Str); erlang:is_binary(Str) ->
            Msg;
        {Fmt, Args} = Msg when erlang:is_list(Args),
                erlang:is_atom(Fmt), Fmt =/= report ->
            Msg;
        Result ->
            {"REPORT_CB/1 ERROR: ~0tp; Returned: ~0tp", [Report, Result]}
    catch
        C:R:S ->
            {"REPORT_CB/1 CRASH: ~0tp; Reason: ~0tp",
                [Report, {C, R, format_report_cb_stack(S)}]}
    end.

-spec format_report_cb_2(
    CbFun :: report_cb_2(),
    Report :: logger:report(),
    FConfig :: fmt_config() )
        -> {string, Str :: unicode:chardata()}
        |  {Fmt :: nonempty_string(), Args :: list()}.
%% @hidden
format_report_cb_2(CbFun, Report, FConfig) ->
    CbOpts = format_report_cb_opts(FConfig),
    try CbFun(Report, CbOpts) of
        Str when erlang:is_list(Str); erlang:is_binary(Str) ->
            {string, Str};
        Result ->
            {"REPORT_CB/2 ERROR: ~0tp; Returned: ~0tp", [Report, Result]}
    catch
        C:R:S ->
            {"REPORT_CB/2 CRASH: ~0tp; Reason: ~0tp",
                [Report, {C, R, format_report_cb_stack(S)}]}
    end.

-spec format_report_cb_opts(
    FConfig :: logger:formatter_config() )
        -> logger:report_cb_config().
%% @hidden
format_report_cb_opts(#{chars_limit := CLimit, depth := Depth})
        when erlang:is_integer(CLimit) andalso erlang:is_integer(Depth) ->
    #{chars_limit => CLimit, depth => Depth, single_line => true};
format_report_cb_opts(#{chars_limit := CLimit})
        when erlang:is_integer(CLimit) ->
    #{chars_limit => CLimit, single_line => true};
format_report_cb_opts(#{depth := Depth}) when erlang:is_integer(Depth) ->
    #{depth => Depth, single_line => true};
format_report_cb_opts(_) ->
    #{single_line => true}.

-spec format_report_cb_stack(Frames :: list(tuple()) ) -> list(tuple()).
%% @hidden Return only the stack frames up to and including the first frame
%% in this module (the point from which the callback function was invoked).
format_report_cb_stack([Frame | _Frames]) when erlang:is_tuple(Frame),
        erlang:tuple_size(Frame) > 1, erlang:element(1, Frame) =:= ?MODULE ->
    [Frame];
format_report_cb_stack([Frame | Frames]) ->
    [Frame | format_report_cb_stack(Frames)];
format_report_cb_stack([]) ->
    [].

%% -------------------------------------------------------------------
%% Handler Internal
%% -------------------------------------------------------------------

-spec init_log(Config :: config()) -> ok | {error, term()}.
init_log(#{identity := Ident, facility := Facility, options := Opts}) ->
    nif_open(ident_binary(Ident), facility(Facility), options(Opts, 0)).

-spec init_state() -> {ok, state()} | hnd_error().
init_state() ->
    AppEnv  = maps:from_list(application:get_all_env(?APP_NAME)),
    CfgKeys = [facility, identity, options],
    case init_config(CfgKeys, AppEnv, [], #{}) of
        Config when erlang:is_map(Config) ->
            {ok, #{config => Config, facmap => map_facilities()}};
        Errors ->
            {error, {invalid_config, ?MODULE, maps:from_list(Errors)}}
    end.

-spec init_config(
    CfgKeys :: list(atom()),
    AppEnv :: #{atom() => term()},
    ErrAcc :: err_recs(),
    CfgAcc :: #{atom() => term()} )
        -> Config :: config() | Errors :: nonempty_list(err_rec()).

init_config([facility = Key | Keys], #{facility := Val} = AppEnv, ErrAcc, CfgAcc) ->
    try
        _ = facility(Val),
        init_config(Keys, AppEnv, ErrAcc, CfgAcc#{Key => Val})
    catch
        error:badarg ->
            init_config(Keys, AppEnv, [{Key, Val} | ErrAcc], CfgAcc)
    end;
init_config([facility = Key | Keys], AppEnv, ErrAcc, CfgAcc) ->
    init_config(Keys, AppEnv, ErrAcc, CfgAcc#{Key => ?DFLT_FAC});
init_config([identity = Key | Keys], #{identity := Val} = AppEnv, ErrAcc, CfgAcc) ->
    try
        _ = ident_binary(Val),
        init_config(Keys, AppEnv, ErrAcc, CfgAcc#{Key => Val})
    catch
        error:badarg ->
            init_config(Keys, AppEnv, [{Key, Val} | ErrAcc], CfgAcc)
    end;
init_config([identity = Key | Keys], AppEnv, ErrAcc, CfgAcc) ->
    ProgName = case init:get_argument(progname) of
        {ok, [[Prog]]} ->
            Prog;
        {ok, [_|_] = Progs} ->
            [[Last] | _] = lists:reverse(Progs),
            Last;
        _ ->
            "beam"
    end,
    %% In case it was set with a path ...
    Val = filename:basename(ProgName),
    init_config(Keys, AppEnv, ErrAcc, CfgAcc#{Key => Val});
init_config([options = Key | Keys], #{options := Val} = AppEnv, ErrAcc, CfgAcc) ->
    try
        _ = options(Val, 0),
        init_config(Keys, AppEnv, ErrAcc, CfgAcc#{Key => Val})
    catch
        error:badarg ->
            init_config(Keys, AppEnv, [{Key, Val} | ErrAcc], CfgAcc)
    end;
init_config([options = Key | Keys], AppEnv, ErrAcc, CfgAcc) ->
    init_config(Keys, AppEnv, ErrAcc, CfgAcc#{Key => ?DFLT_OPTS});
init_config([], _AppEnv, [], Config) ->
    Config;
init_config([], _AppEnv, Errors, _Config) ->
    Errors;
init_config(CfgKeys, AppEnv, ErrAcc, CfgAcc) ->
    erlang:error(badarg,
        [{?MODULE, ?FUNCTION_NAME}, CfgKeys, AppEnv, ErrAcc, CfgAcc]).

-spec ident_binary(Ident :: ident() ) -> binary() | no_return().
ident_binary(Ident) when
        erlang:is_binary(Ident) andalso erlang:byte_size(Ident) > 0 ->
    Ident;
ident_binary([_|_] = Ident) ->
    erlang:list_to_binary(Ident);
ident_binary(Ident) when erlang:is_atom(Ident) ->
    erlang:atom_to_binary(Ident);
ident_binary(Ident) ->
    erlang:error(badarg, [{?MODULE, ?FUNCTION_NAME}, Ident]).

map_config(FacName) ->
    try
        {ok, facility(FacName)}
    catch
        error:badarg ->
            {error, {invalid_config, ?MODULE, #{facility => FacName}}}
    end.

%% Generate the reverse lookup map for reporting/changing config.
map_facilities() ->
    Map = maps:from_list([{facility(N), N} || N <- ?FACILITIES]),
    %% Fill in the reserved facility gaps
    lists:foldl(
        fun(V, M) ->
            K = (V bsl 3),
            case M of
                #{K := _} ->
                    M;
                _ ->
                    M#{K => V}
            end
        end, Map, lists:seq(0, 23)).

%% -------------------------------------------------------------------
%% Constant atom <=> integer mapping.
%% Facility and Level are defined in IETF RFC 5424.
%% Options are constant across all common Unix variants.
%% -------------------------------------------------------------------

-spec facility(Facility :: facility()) -> fac_int().
facility(kernel)    -> 0;
facility(user)      -> ( 1 bsl 3);
facility(mail)      -> ( 2 bsl 3);
facility(daemon)    -> ( 3 bsl 3);
facility(auth)      -> ( 4 bsl 3);
%% Facility 5 (syslog) is for syslog internal use only
facility(lpr)       -> ( 6 bsl 3);
facility(news)      -> ( 7 bsl 3);
facility(uucp)      -> ( 8 bsl 3);
facility(cron)      -> ( 9 bsl 3);
facility(authpriv)  -> (10 bsl 3);
facility(ftp)       -> (11 bsl 3);
%% Facilities 12 - 15 are reserved for system use and vary across platforms
facility(local0)    -> (16 bsl 3);
facility(local1)    -> (17 bsl 3);
facility(local2)    -> (18 bsl 3);
facility(local3)    -> (19 bsl 3);
facility(local4)    -> (20 bsl 3);
facility(local5)    -> (21 bsl 3);
facility(local6)    -> (22 bsl 3);
facility(local7)    -> (23 bsl 3);
facility(Facility) when erlang:is_integer(Facility)
        andalso Facility >= 0 andalso Facility < 24 ->
    (Facility bsl 3);
facility(Facility) ->
    erlang:error(badarg, [{?MODULE, ?FUNCTION_NAME}, Facility]).

-spec level(Level :: logger:level()) -> sev_int().
level(emergency)    -> 0;
level(alert)        -> 1;
level(critical)     -> 2;
level(error)        -> 3;
level(warning)      -> 4;
level(notice)       -> 5;
level(info)         -> 6;
level(debug)        -> 7;
level(Level) ->
    erlang:error(badarg, [{?MODULE, ?FUNCTION_NAME}, Level]).

-spec options(Options :: list(option()), Result :: opt_int()) -> opt_int().
options([], Result) -> Result;
options([pid    | Opts], Result)  -> options(Opts, (Result bor  1));
options([cons   | Opts], Result)  -> options(Opts, (Result bor  2));
options([odelay | Opts], Result)  -> options(Opts, (Result bor  4));
options([ndelay | Opts], Result)  -> options(Opts, (Result bor  8));
options([nowait | Opts], Result)  -> options(Opts, (Result bor 16));
options([perror | Opts], Result)  -> options(Opts, (Result bor 32));
options(Options, _Result) ->
    erlang:error(badarg, [{?MODULE, ?FUNCTION_NAME}, Options]).

%% -------------------------------------------------------------------
%% NIF operations
%% -------------------------------------------------------------------

-spec nif_open(
    Ident :: binary(), Facility :: fac_int(), Opts :: opt_int() )
        -> ok | {error, term()}.
nif_open(_Ident, _Facility, _Opts) ->
    erlang:nif_error(syslog_nif_not_loaded).

-spec nif_log(Priority :: pri_int(), Message :: binary()) -> ok.
nif_log(_Priority, _Message) ->
    erlang:nif_error(syslog_nif_not_loaded).

-spec load_nif_lib() -> ok | {error, term()}.
load_nif_lib() ->
    NifPath = case code:priv_dir(?MODULE) of
        {error, _} ->
            Maybe = filename:join(priv, syslog_nif),
            case filelib:is_dir(priv) of
                true ->
                    Maybe;
                _ ->
                    filename:join("..", Maybe)
            end;
        LibDir ->
            filename:join(LibDir, syslog_nif)
    end,
    erlang:load_nif(NifPath, ?MODULE).

%% -------------------------------------------------------------------
%% Timing tests
%% ALL functional tests are to be performed in the common_test suite(s).
%% Timing tests alone are contained here for the shortest path to the NIF.
%% -------------------------------------------------------------------
-ifdef(TIMING_TESTS).

-ifndef(TIMING_FACIL).
-define(TIMING_FACIL,   user).
-endif.
-ifndef(TIMING_LEVEL).
-define(TIMING_LEVEL,   notice).
-endif.
-ifndef(TIMING_PROCS).
-define(TIMING_PROCS,   ((erlang:system_info(schedulers) * 3) div 4)).
-endif.
-ifndef(TIMING_MSGS).
-define(TIMING_MSGS,    10000).
-endif.

timing_test_() ->
    {timeout, 120, fun run_timing/0}.

run_timing() ->
    Ident   = ?FUNCTION_NAME,
    Facil   = ?TIMING_FACIL,
    Level   = ?TIMING_LEVEL,
    NProc   = ?TIMING_PROCS,
    Count   = ?TIMING_MSGS,

    %% lists:concat/1 will turn whatever Ident is defined to be into a list
    IdentBin = erlang:iolist_to_binary([lists:concat([Ident]), 0]),
    ?assertMatch(ok, nif_open(IdentBin, facility(Facil), options([pid], 0))),

    Owner   = erlang:self(),
    Prio    = (facility(Facil) bor level(Level)),
    IDs     = lists:seq(1, NProc),
    Workers = [{Id, erlang:spawn(
        ?MODULE, timer_proc, [Owner, Id, Count, Prio])} || Id <- IDs],
    _ = [receive {ready, Id} -> Id end || Id <- IDs],
    _ = [Pid ! {go, Owner} || {_Id, Pid} <- Workers],
    Results = [receive {done, Id, S, F} -> {Id, S, F} end
        || {Id, _Pid} <- Workers],
    report_timing(Results, NProc, Count).

report_timing(Results, NProc, Count) ->
    MsgCnt  = (NProc * Count),
    Start   = lists:min(lists:map(fun({_I, S, _F}) -> S end, Results)),
    Finish  = lists:max(lists:map(fun({_I, _S, F}) -> F end, Results)),
    TotalET = lists:foldl(fun({_I, S, F}, R) -> (R + (F - S)) end, 0, Results),
    AvgCall = (TotalET div MsgCnt),
    Elapsed = (Finish - Start),
    PerMsg  = (Elapsed div MsgCnt),
    Through = (erlang:convert_time_unit(1, second, native) div PerMsg),
    Micros  = erlang:convert_time_unit(AvgCall, native, microsecond),
    io:format(standard_error,
        "~n\tConfiguration: ~b parallel processes writing ~b messages each"
        "~n\toverall ~b messages written at ~b per second"
        "~n\taverage log write latency ~b microseconds~n",
        [NProc, Count, MsgCnt, Through, Micros] ).

timer_proc(Owner, Id, Count, Prio) ->
    First = (Id * Count),
    Last = (First + Count - 1),
    Fmt = lists:concat(["Tester ", Id, ": ~b\0"]),
    Bins = [erlang:iolist_to_binary(io_lib:format(Fmt, [I]))
        || I <- lists:seq(First, Last)],
    %% Send one primer message to ensure syslog is connected (possibly
    %% per-thread) before we start timing.
    send_logs(Prio, [erlang:iolist_to_binary(
        lists:concat(["Tester ", Id, ": init\0"]))]),
    Owner ! {ready, Id},
    Start = receive {go, Owner} -> erlang:monotonic_time() end,
    send_logs(Prio, Bins),
    Finish = erlang:monotonic_time(),
    Owner ! {done, Id, Start, Finish},
    erlang:exit(normal).

send_logs(Prio, [Bin | Bins]) ->
    nif_log(Prio, Bin),
    send_logs(Prio, Bins);
send_logs(_, []) ->
    ok.

-endif. % TIMING_TESTS
