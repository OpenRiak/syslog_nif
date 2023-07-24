%% -*- mode: erlang; erlang-indent-level: 4; indent-tabs-mode: nil -*-
%% -------------------------------------------------------------------
%%
%% Copyright (c) 2023 Workday, Inc.
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
-module(syslog_SUITE).

%% Setup/teardown
-export([
    init_per_suite/1, end_per_suite/1,
    init_per_testcase/2, end_per_testcase/2
]).

%% Tests to run
-export([all/0]).

%% Test cases
-export([
    application/0, application/1,
    simple_handler/0, simple_handler/1,
    syslog_formatter/0, syslog_formatter/1
]).

-include_lib("common_test/include/ct.hrl").
-include_lib("kernel/include/logger.hrl").

%% Test cases

all() ->
    [application, simple_handler, syslog_formatter].

%% System default formatter configuration
-define(STD_FORMATTER, {logger_formatter, #{
    single_line => true, legacy_header => false,
    template => [level," ",pid,":",mfa,":",line,": ",msg]}} ).

%% Our default formatter configuration
-define(SYSLOG_FORMATTER, {syslog, #{}} ).

%% Our standard per-testcase handler
-define(STD_HANDLER(Formatter), {handler, ?FUNCTION_NAME, syslog, #{
    config => default, formatter => Formatter }} ).

%% Suite setup/teardown

init_per_suite(Config) ->
    ok = logger:set_primary_config(level, debug),
    {_, System} = os:type(),
    [{system_type, System} | Config].

end_per_suite(_Config) ->
    ok.

%% Testcase setup/teardown

init_per_testcase(Case, Config) ->
    ok = application:load(syslog),
    ok = application:set_env(syslog, identity, Case),
    Config.

end_per_testcase(Case, _Config) ->
    lists:foreach(
        fun(Handler) ->
            %% It may not be loaded, so don't sweat it if it's not there
            _ = logger:remove_handler(Handler)
        end, proplists:get_value(syslog_handlers, ?MODULE:Case(), [])),
    lists:foreach(
        fun({Key, _Val}) ->
            ok = application:unset_env(syslog, Key)
        end, application:get_all_env(syslog)),
    %% Not all tests leave the application running, so be tolerant
    _ = application:stop(syslog),
    ok = application:unload(syslog).

%% Ensure we can start and stop the application

application() ->
    [].
application(_Config) ->
    ok = application:start(syslog),
    true = erlang:is_pid(erlang:whereis(syslog)),
    ok = application:stop(syslog),
    undefined = erlang:whereis(syslog),
    ok.

%% ToDo: Deliberately misconfigure

%% Install and write to a handler

simple_handler() ->
    [{syslog_handlers, [?FUNCTION_NAME]}].
simple_handler(Config) ->
    LConfig = [?STD_HANDLER(?STD_FORMATTER)],
    ok = application:set_env(syslog, logger, LConfig),
    ok = application:start(syslog),

    %% Give logger time to install the configured handler(s)
    timer:sleep(200),

    SysType = ?config(system_type, Config),
    check_logged(log_simple(SysType, ?FUNCTION_NAME),
        #{type => SysType, pid => os:getpid(), handler => ?FUNCTION_NAME}).

syslog_formatter() ->
    [{syslog_handlers, [?FUNCTION_NAME]}].
syslog_formatter(Config) ->
    LConfig = [?STD_HANDLER(?SYSLOG_FORMATTER)],
    ok = application:set_env(syslog, logger, LConfig),
    ok = application:start(syslog),

    %% Give logger time to install the configured handler(s)
    timer:sleep(200),

    SysType = ?config(system_type, Config),
    check_logged(log_simple(SysType, ?FUNCTION_NAME),
        #{type => SysType, pid => os:getpid(), handler => ?FUNCTION_NAME}).

%% Helpers

-spec log_simple(SysType :: atom(), TestCase :: atom())
        -> nonempty_list(nonempty_string()).
log_simple(SysType, Test) ->
    Msg1 = lists:concat([Test, " ", SysType, " test message ", (?LINE + 1)]),
    ?LOG_EMERGENCY("~s ~s test message ~b", [Test, SysType, ?LINE]),

    Msg2 = lists:concat([Test, " ", SysType, " test message ", (?LINE + 1)]),
    ?LOG_ALERT("~s ~s test message ~b", [Test, SysType, ?LINE]),

    Msg3 = lists:concat([Test, " ", SysType, " test message ", (?LINE + 1)]),
    ?LOG_CRITICAL("~s ~s test message ~b", [Test, SysType, ?LINE]),

    Msg4 = lists:concat([Test, " ", SysType, " test message ", (?LINE + 1)]),
    ?LOG_ERROR("~s ~s test message ~b", [Test, SysType, ?LINE]),

    Msg5 = lists:concat([Test, " ", SysType, " test message ", (?LINE + 1)]),
    ?LOG_WARNING("~s ~s test message ~b", [Test, SysType, ?LINE]),

    Msg6 = lists:concat([Test, " ", SysType, " test message ", (?LINE + 1)]),
    ?LOG_NOTICE("~s ~s test message ~b", [Test, SysType, ?LINE]),

    Msg7 = lists:concat([Test, " ", SysType, " test message ", (?LINE + 1)]),
    ?LOG_INFO("~s ~s test message ~b", [Test, SysType, ?LINE]),

    Msg8 = lists:concat([Test, " ", SysType, " test message ", (?LINE + 1)]),
    ?LOG_DEBUG("~s ~s test message ~b", [Test, SysType, ?LINE]),

    timer:sleep(500),   %% let them get written

    Messages = [Msg1, Msg2, Msg3, Msg4, Msg5, Msg6, Msg7],
    case SysType of
        darwin ->
            %% Debug doesn't seem to make it through on Mac
            Messages;
        _ ->
            [Msg8 | Messages]
    end.


-spec check_logged(
    Msgs :: list(nonempty_string()),
    Context :: #{atom() => term()} )
        -> ok | {comment, nonempty_string()}.

check_logged([], #{fail := [_|_] = Fail, out := _, cmd := Cmd}) ->
    ct:fail(#{notfound => Fail, cmd => Cmd});
check_logged([], #{fail := [_|_] = Fail, out := _}) ->
    ct:fail({notfound, Fail});

check_logged([], #{fail := [_|_] = Fail, file := File, pid := Pid}) ->
    {comment, lists:flatten(io_lib:format(
        "Lacking permission to search ~s for PID ~s with message(s): ~s",
        [File, Pid, [$\", string:join(Fail, "\", \""), $\"] ])) };

check_logged([], _) ->
    ok;

check_logged(Msgs, #{out := []} = Context) ->
    check_logged([], Context#{fail => Msgs});
check_logged(Msgs, #{out := _} = Context) ->
    check_logged([], lists:foldl(fun message_check/2, Context, Msgs));

check_logged(Msgs, #{cmd := Cmd} = Context) ->
    CmdOut = os:cmd(Cmd),
    Lines = string:tokens(CmdOut, "\n"),
    check_logged(Msgs, Context#{out => Lines});

check_logged(Msgs, #{file := File, grep := Grep, pid := Pid} = Context) ->
    case file:open(File, [read]) of
        {ok, IoDev} ->
            %% We have read permission
            ok = file:close(IoDev),
            Cmd = lists:flatten([Grep, " -Ew ", Pid, $\s, File]),
            check_logged(Msgs, Context#{cmd => Cmd});
        {error, eacces} ->
            check_logged([], Context#{fail => Msgs});
        {error, _} ->
            %% We looked in the wrong place
            check_logged([], Context#{fail => Msgs, file => "system logs"})
    end;

%% macOS has a command for reading logs, and there are _some_ suggestions on
%% the 'net that some other BSD variants may, too. Haven't found anything
%% official, though, so just Macs using this for now.
check_logged(Msgs, #{type := darwin, pid := Pid} = Context) ->
    Cmd = lists:flatten([ "/usr/bin/log show --process ",
        Pid, " --last 30 --style compact --info --debug" ]),
    check_logged(Msgs, Context#{cmd => Cmd});

%% The compiler will optimize matching bodies to a single block,
%% keep them distinct for clarity (and in case any need to be changed).
check_logged(Msgs, #{type := linux} = Context) ->
    check_logged(Msgs, Context#{
        file => "/var/log/messages", grep => "/usr/bin/grep"});
check_logged(Msgs, #{type := freebsd} = Context) ->
    check_logged(Msgs, Context#{
        file => "/var/log/messages", grep => "/usr/bin/grep"});
check_logged(Msgs, #{type := netbsd} = Context) ->
    check_logged(Msgs, Context#{
        file => "/var/log/messages", grep => "/usr/bin/grep"});
check_logged(Msgs, #{type := openbsd} = Context) ->
    check_logged(Msgs, Context#{
        file => "/var/log/messages", grep => "/usr/bin/grep"});

%% Unrecognized platform.
check_logged(Msgs, Context) ->
    %% It appears that /var/log/syslog is pretty universally deprecated,
    %% so just stick with looking for /var/log/messages.
    File = "/var/log/messages",
    case filelib:is_regular(File) of
        true ->
            case os:find_executable("grep") of
                false ->
                    %% Well then, that's that ...
                    check_logged([], Context#{fail => Msgs, file => File});
                Grep ->
                    check_logged(Msgs, Context#{file => File, grep => Grep})
            end;
        _ ->
            %% We don't know where to look.
            %% Maybe add a platform-specific head above here.
            check_logged([], Context#{fail => Msgs, file => "system logs"})
    end.


-spec message_check(
    Lines :: nonempty_list(nonempty_string()),
    Message :: nonempty_string() )
        -> boolean().
message_check(Msg, #{out := Lines, pid := Pid} = Context) ->
    RegEx = io_lib:format("\\b~s\\b.+\\b~s$", [Pid, Msg]),
    {ok, RE} = re:compile(RegEx),
    ReFun = fun(Line) -> re:run(Line, RE, [{capture, none}]) =:= match end,
    case lists:any(ReFun, Lines) of
        true ->
            Context#{found => [Msg | maps:get(found, Context, [])]};
        _ ->
            Context#{fail => [Msg | maps:get(fail, Context, [])]}
    end.
