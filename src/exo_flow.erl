%%% coding: latin-1
%%%---- BEGIN COPYRIGHT -------------------------------------------------------
%%%
%%% Copyright (C) 2015, Rogvall Invest AB, <tony@rogvall.se>
%%%
%%% This software is licensed as described in the file COPYRIGHT, which
%%% you should have received as part of this distribution. The terms
%%% are also available at http://www.rogvall.se/docs/copyright.txt.
%%%
%%% You may opt to use, copy, modify, merge, publish, distribute and/or sell
%%% copies of the Software, and permit persons to whom the Software is
%%% furnished to do so, under the terms of the COPYRIGHT file.
%%%
%%% This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
%%% KIND, either express or implied.
%%%
%%%---- END COPYRIGHT ---------------------------------------------------------
%%% @author Malotte W Lönne <malotte@malotte.net>
%%% @copyright (C) 2015, Tony Rogvall
%%% @doc
%%%    Server handling flow control.
%%%
%%% Implementing token bucket, see wikipedia for further information.
%%% Created : September 2015 by Malotte W Lönne
%%% @end
-module(exo_flow).
-behaviour(gen_server).

-include_lib("lager/include/log.hrl").

%% general api
-export([start_link/1, 
	 stop/0]).

%% functional api
-export([new/2,
	 delete/1,
	 use/2,
	 fill/1,
	 fill_time/2,
	 wait/2,
	 fill_wait/2]).

%% gen_server callbacks
-export([init/1, 
	 handle_call/3, 
	 handle_cast/2, 
	 handle_info/2,
	 terminate/2, 
	 code_change/3]).

%% test api
-export([dump/0]).

-define(SERVER, ?MODULE). 
-define(BUCKETS, exo_token_buckets).
-define(POLICIES, exo_token_policies).

%% For dialyzer
-type start_options()::{linked, TrueOrFalse::boolean()}.

%% token bucket
-record(bucket,
	{
	  key::term(),
	  capacity::float(),    %% max number of tokens in the bucket
	  rate::float(),        %% bytes per second 
	  current::float(),     %% current number of tokens
	  action::atom(),       %% to do when overload
	  parent::atom(),       %% for group flow
	  timestamp::integer()  %% last time
	}).

%% Loop data
-record(ctx,
	{
	  buckets::term(),
	  policies::term()
	}).

%%%===================================================================
%%% API
%%%===================================================================
%%--------------------------------------------------------------------
%% @doc
%% Starts the server.
%% Loads configuration from File.
%% @end
%%--------------------------------------------------------------------
-spec start_link(Opts::list(start_options())) -> 
			{ok, Pid::pid()} | 
			ignore | 
			{error, Error::term()}.

start_link(Opts) ->
    lager:info("args = ~p\n", [Opts]),
    F =	case proplists:get_value(linked,Opts,true) of
	    true -> start_link;
	    false -> start
	end,
    
    gen_server:F({local, ?SERVER}, ?MODULE, Opts, []).


%%--------------------------------------------------------------------
%% @doc
%% Stops the server.
%% @end
%%--------------------------------------------------------------------
-spec stop() -> ok | {error, Error::term()}.

stop() ->
    gen_server:call(?SERVER, stop).


%%--------------------------------------------------------------------
%% @doc
%% Create a pair of new buckets, one for incoming and one for outgoing.
%%
%% @end
%%--------------------------------------------------------------------
-spec new(Key::term(), Policy::atom()) -> ok | {error, Error::atom()}.

new(Key, Policy) ->
    case new_bucket({in, Key}, Policy) of
	ok ->
	    case new_bucket({out, Key}, Policy) of
		ok -> ok;
		E -> delete({in, Key}), E
	    end;
	E ->
	    E
    end.

%%--------------------------------------------------------------------
%% @doc
%% Delete a bucket.
%%
%% @end
%%--------------------------------------------------------------------
-spec delete(Key::term()) -> ok | {error, Error::atom()}.

delete({_Direction, _K} = Key) ->
    lager:debug("key = ~p", [Key]),
    ets:delete(?BUCKETS, Key);
delete(Key) ->
    delete({in, Key}),
    delete({out, Key}).

%%--------------------------------------------------------------------
%% @doc
%% Use a bucket.
%% If enough tokens -> ok, otherwise -> {error, Action}.
%%
%% @end
%%--------------------------------------------------------------------
-spec use(Key::term(), Tokens::number()) -> ok | 
					    {action, Action::throw | wait} |
					    {error, Error::atom()}.

use({Direction, _K} = Key, Tokens) 
  when is_number(Tokens), is_atom(Direction) ->
    lager:debug("key = ~p, tokens = ~p", [Key, Tokens]),
    use_tokens(Key, Tokens).

%%--------------------------------------------------------------------
%% @doc
%% Fills the bucket fill rate with tokens accumulated since last use.
%% Returns number of tokens in the bucket.
%%
%% @end
%%--------------------------------------------------------------------
-spec fill(Key::term()) -> {ok, Tokens::number()} |
			   {error, Error::atom()}.

fill({Direction, _K} = Key) when is_atom(Direction) ->
    lager:debug("key = ~p", [Key]),
    case ets:lookup(?BUCKETS, Key) of
	[B] when is_record(B, bucket) ->
	   fill_bucket(B);
	[] ->
	   {error, unkown_key}
    end.

%%--------------------------------------------------------------------
%% @doc
%% How long to wait for the bucket to contain Tokens in seconds.
%%
%% @end
%%--------------------------------------------------------------------
-spec fill_time(Key::term(), Tokens::number()) -> 
		       {ok, Secs::number()} |
		       {error, Error::atom()}.

fill_time({Direction, _K} = Key, Tokens) 
  when is_number(Tokens), is_atom(Direction) ->
   lager:debug("key = ~p, tokens = ~p", [Key, Tokens]),
   case ets:lookup(?BUCKETS, Key) of
	[B] when is_record(B, bucket) ->
	   bucket_fill_time(B, Tokens);
	[] ->
	    {error, unkown_key}
    end.


%%--------------------------------------------------------------------
%% @doc
%% Wait the time needed for the bucket to have enough tokens.
%% However, does not fill the bucket !!!
%%
%% @end
%%--------------------------------------------------------------------
-spec wait(Key::term(), Tokens::number()) -> 
		       ok |
		       {error, Error::atom()}.

wait({Direction, _K} = Key, Tokens) 
  when is_number(Tokens), is_atom(Direction) ->
   lager:debug("key = ~p, tokens = ~p", [Key, Tokens]),
   case ets:lookup(?BUCKETS, Key) of
	[{Key, B}] when is_record(B, bucket) ->
	   bucket_wait(B, Tokens);
	[] ->
	    {error, unkown_key}
    end.
	    	    
%%--------------------------------------------------------------------
%% @doc
%% Wait the time needed for the bucket to have enough tokens and
%% fill the bucket.
%% Returns number of tokens in the bucket.
%%
%% @end
%%--------------------------------------------------------------------
-spec fill_wait(Key::term(), Tokens::number()) -> 
		       {ok, Tokens::number()} |
		       {error, Error::atom()}.

fill_wait({Direction, _K} = Key, Tokens) 
  when is_number(Tokens), is_atom(Direction) ->
   lager:debug("key = ~p, tokens = ~p", [Key, Tokens]),
   case ets:lookup(?BUCKETS, Key) of
	[B] when is_record(B, bucket) ->
	   wait(B, Tokens),
	   fill(B);
	[] ->
	    {error, unkown_key}
    end.

%%--------------------------------------------------------------------
%% @doc
%% Dumps data to standard output.
%%
%% @end
%%--------------------------------------------------------------------
-spec dump() -> ok | {error, Error::atom()}.

dump() ->
    gen_server:call(?SERVER,dump).

%%%===================================================================
%%% gen_server callbacks
%%%===================================================================

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Initializes the server
%%
%% @end
%%--------------------------------------------------------------------
-spec init(Args::list(start_options())) -> 
		  {ok, Ctx::#ctx{}} |
		  {stop, Reason::term()}.

init(Args) ->
    lager:info("args = ~p,\n pid = ~p\n", [Args, self()]),
    BTab = ets:new(?BUCKETS, [named_table, public, {keypos, #bucket.key}]),
    PTab = ets:new(?POLICIES, [named_table, public, {keypos, #bucket.key}]),
    lists:foreach(fun({PolicyName, Opts}) ->
			  add_template(PolicyName, in, Opts),
			  add_template(PolicyName, out, Opts)
		  end, application:get_env(exo, policies, [])),
    {ok, #ctx {buckets = BTab, policies = PTab}}.


%%--------------------------------------------------------------------
%% @private
%% @doc
%% Handling call messages.
%% Request can be the following:
%% <ul>
%% <li> dump - Writes loop data to standard out (for debugging).</li>
%% <li> stop - Stops the application.</li>
%% </ul>
%%
%% @end
%%--------------------------------------------------------------------
-type call_request()::
	dump |
	stop.

-spec handle_call(Request::call_request(), From::{pid(), Tag::term()}, Ctx::#ctx{}) ->
			 {reply, Reply::term(), Ctx::#ctx{}} |
			 {noreply, Ctx::#ctx{}} |
			 {stop, Reason::atom(), Reply::term(), Ctx::#ctx{}}.

handle_call(dump, _From, Ctx=#ctx {buckets = B}) ->
    io:format("Ctx: Buckets = ~p.", [ets:tab2list(B)]),
    {reply, ok, Ctx};

handle_call(stop, _From, Ctx) ->
    lager:debug("stop.",[]),
    {stop, normal, ok, Ctx};

handle_call(_Request, _From, Ctx) ->
    lager:debug("unknown request ~p.", [_Request]),
    {reply, {error,bad_call}, Ctx}.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Handling cast messages.
%%
%% @end
%%--------------------------------------------------------------------
-type cast_msg()::
	term().

-spec handle_cast(Msg::cast_msg(), Ctx::#ctx{}) -> 
			 {noreply, Ctx::#ctx{}} |
			 {stop, Reason::term(), Ctx::#ctx{}}.

handle_cast(_Msg, Ctx) ->
    lager:debug("unknown msg ~p.", [_Msg]),
    {noreply, Ctx}.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Handling all non call/cast messages.
%% 
%% @end
%%--------------------------------------------------------------------
-type info()::
	term().

-spec handle_info(Info::info(), Ctx::#ctx{}) -> 
			 {noreply, Ctx::#ctx{}} |
			 {noreply, Ctx::#ctx{}, Timeout::timeout()} |
			 {stop, Reason::term(), Ctx::#ctx{}}.

handle_info(_Info, Ctx) ->
    lager:debug("unknown info ~p.", [_Info]),
    {noreply, Ctx}.

%%--------------------------------------------------------------------
%% @private
%%--------------------------------------------------------------------
-spec terminate(Reason::term(), Ctx::#ctx{}) -> 
		       no_return().

terminate(_Reason, _Ctx) ->
    lager:debug("terminating, reason = ~p.",[_Reason]),
    ok.
%%--------------------------------------------------------------------
%% @private
%% @doc
%% Convert process ctx when code is changed
%%
%% @end
%%--------------------------------------------------------------------
-spec code_change(OldVsn::term(), Ctx::#ctx{}, Extra::term()) -> 
			 {ok, NewCtx::#ctx{}}.

code_change(_OldVsn, Ctx, _Extra) ->
    lager:debug("old version ~p.", [_OldVsn]),
    {ok, Ctx}.


%%%===================================================================
%%% Internal functions
%%%===================================================================
add_template(PolicyName, Direction, Opts) ->
    case proplists:get_value(Direction, Opts) of
	[] -> do_nothing;
	DirOpts -> add_bucket(?POLICIES, {Direction, PolicyName}, DirOpts)
    end.

add_bucket(Table, Key, Opts) ->
    Capacity = proplists:get_value(capacity, Opts),
    Rate = proplists:get_value(rate, Opts),
    Parent = proplists:get_value(parent, Opts),
    Action = proplists:get_value(action, Opts, throw),
    Bucket = #bucket {key = Key,
		      capacity  = float(Capacity),
		      current    = float(Capacity),
		      rate = float(Rate),
		      action = Action,
		      parent = Parent,
		      timestamp = erlang:system_time(micro_seconds)},
    lager:debug("bucket ~p created,", [Bucket]),
    ets:insert(Table, Bucket).

new_bucket({Direction, _K} = Key, PolicyName) -> 
   case ets:lookup(?POLICIES, {Direction,PolicyName}) of
       [Policy=#bucket {capacity = C}] ->
	   ets:insert(?BUCKETS, 
		      Policy#bucket{key=Key, 
				    current = C, 
				    timestamp = erlang:system_time(micro_seconds)}),
	   lager:debug("bucket ~p created.", [Key]),
	   ok;
       [] -> 
	   lager:debug("no policy found for ~p", [{Direction, PolicyName}]),
	   {error,no_policy}
    end.

use_tokens(Key, Tokens) ->
    case ets:lookup(?BUCKETS, Key) of
	[_B=#bucket {current = Current}] when Tokens =< Current ->
	    ets:update_element(?BUCKETS, Key, 
			       [{#bucket.current, Current - Tokens}]),
	    ok;
	[_B=#bucket {action = Action}] ->
	    lager:debug("bucket ~p full, ~p.", [Key, Action]),
	    {action, Action};
	[] ->
	    {error, unkown_key}
    end.

fill_bucket(B) when is_record(B, bucket) ->
    Now = erlang:system_time(micro_seconds),
    Current = B#bucket.current,
    Capacity = B#bucket.capacity,
    T = if Current < Capacity ->
		Dt = time_delta(Now, B#bucket.timestamp),
		New = B#bucket.rate * Dt,
		erlang:min(Capacity, Current + New);
	   true ->
		Current
		end,
    ets:insert(?BUCKETS, B#bucket {current = T, timestamp = Now}),
    {ok, T}.
    
bucket_fill_time(B, Tokens) when is_record(B, bucket) ->
    Current = B#bucket.current,
    if Tokens < Current ->
	    {ok, 0};
       true ->
	    Ts = Tokens - Current,  %% tokens to wait for
	    {ok, Ts / B#bucket.rate}
    end.

bucket_wait(B, Tokens)  when is_record(B, bucket) ->
    {ok, Ts} = fill_time(B, Tokens),
    Tms = Ts*1000,
    Delay = trunc(Tms),
    if Delay < Tms ->
	    timer:sleep(Delay+1);
       Delay > 0 ->
	    timer:sleep(Delay);
       true ->
	    ok
    end.

time_delta(T1, T0) ->
    (T1 - T0) / 1000000.
