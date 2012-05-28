%%%-------------------------------------------------------------------
%%% @author Tony Rogvall <tony@rogvall.se>
%%% @copyright (C) 2011, Tony Rogvall
%%% @doc
%%%    General socket server
%%% @end
%%% Created : 22 Aug 2011 by Tony Rogvall <tony@rogvall.se>
%%%-------------------------------------------------------------------
-module(exo_socket_server).

-behaviour(gen_server).

%%
%% methods
%%   init(Socket, Args) ->  
%%      {ok, State'}
%%      {stop, Reason, State'}
%%
%%   data(Socket, Data, State) ->
%%      {ok, State'}
%%      {stop, Reason, State'};
%%
%%   close(Socket, State) ->
%%      {ok, State'}
%%      
%%   error(Socket, Error, State) ->
%%      {ok, State'}
%%      {stop, Reason, State'}
%%

%% API
-export([start_link/5, start_link/6]).
-export([start/5, start/6]).
-export([reusable_sessions/1]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
	 terminate/2, code_change/3]).

-export([behaviour_info/1]).

-include("exo_socket.hrl").
-define(debug(Fmt,Args), ok).
-define(error(Fmt,Args), error_logger:format(Fmt, Args)).

-define(SERVER, ?MODULE). 

-record(state, {
	  listen,    %% #exo_socket{}
	  active,    %% default active mode for socket
	  socket_reuse = none,  %% 'none' | #reuse{}
	  ref,       %% prim_inet internal accept ref number
	  module,    %% session module
	  args       %% session init args
	 }).

-record(reuse, {
	  mode,
	  port,
	  sessions = dict:new(),
	  session_pids = dict:new(),
	  state
	 }).

%%%===================================================================
%%% API
%%%===================================================================

%% The plugin behaviour
behaviour_info(callbacks) ->
    [
     {init,  2},  %% init(Socket::socket(), Args::[term()] 
                  %%   -> {ok,state()} | {stop,reason(),state()}
     {data,  3},  %% data(Socket::socket(), Data::io_list(), State::state()) 
                  %%   -> {ok,state()}|{close,state()}|{stop,reason(),state()}
     {close, 2},  %% close(Socket::socket(), State::state())
                  %%   -> {ok,state()}
     {error, 3}   %% error(Socket::socket(),Error::error(), State:state())
                  %%   -> {ok,state8)} | {stop,reason(),state()}
    ];
behaviour_info(_Other) ->
    undefined.

%%--------------------------------------------------------------------
%% @doc
%% Starts the server
%% @end
%%--------------------------------------------------------------------

start_link(Port, Protos, Options, Module, Args) ->
    gen_server:start_link(?MODULE, [Port,Protos,Options,Module,Args], []).

start_link(ServerName, Protos, Port, Options, Module, Args) ->
    gen_server:start_link(ServerName, ?MODULE, [Port,Protos,Options,Module,Args], []).

start(Port, Protos, Options, Module, Args) ->
    gen_server:start(?MODULE, [Port,Protos,Options,Module,Args], []).

start(ServerName, Protos, Port, Options, Module, Args) ->
    gen_server:start(ServerName, ?MODULE, [Port,Protos,Options,Module,Args], []).

reusable_sessions(P) ->
    gen_server:call(P, reusable_sessions).

%%%===================================================================
%%% gen_server callbacks
%%%===================================================================

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Initializes the server
%%
%% @spec init(Args) -> {ok, State} |
%%                     {ok, State, Timeout} |
%%                     ignore |
%%                     {stop, Reason}
%% @end
%%--------------------------------------------------------------------
init([Port,Protos,Options,Module,Args] = _X) ->
    ?debug("~p: init(~p)~n", [?MODULE, _X]),
    Active = proplists:get_value(active, Options, true),
    ReuseMode = proplists:get_value(reuse_mode, Options, none),
    Options1 = proplists:delete(reuse_mode, proplists:delete(active, Options)),
    Reuse = case ReuseMode of
		none -> none;
		_ when ReuseMode==client; ReuseMode==server ->
		    {ok, RUSt} = Module:reuse_init(ReuseMode, Args),
		    #reuse{mode = ReuseMode,
			   port = Port,
			   state = RUSt}
	    end,
    case exo_socket:listen(Port,Protos,Options1) of
	{ok,Listen} ->
	    case exo_socket:async_accept(Listen) of
		{ok, Ref} ->
		    {ok, #state{ listen = Listen, 
				 active = Active, 
				 socket_reuse = Reuse,
				 ref=Ref,
				 module=Module, 
				 args=Args
			       }};
		{error, Reason} ->
		    {stop,Reason}		    
	    end;
	{error,Reason} ->
	    {stop,Reason}
    end.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Handling call messages
%%
%% @spec handle_call(Request, From, State) ->
%%                                   {reply, Reply, State} |
%%                                   {reply, Reply, State, Timeout} |
%%                                   {noreply, State} |
%%                                   {noreply, State, Timeout} |
%%                                   {stop, Reason, Reply, State} |
%%                                   {stop, Reason, State}
%% @end
%%--------------------------------------------------------------------
handle_call({get_session, Host, Port, Opts}, From,
	    #state{socket_reuse = Reuse} = State) ->
    Key = {Host, Port},
    case Reuse of
	none ->
	    {reply, connect, State};
	#reuse{mode = client, sessions = Sessions} = R ->
	    case dict:find(Key, Sessions) of
		error ->
		    Ref = start_connector(Host, Port, Opts, self(), State),
		    Sessions1 = dict:store(Key, {Ref, [From]}, Sessions),
		    R1 = R#reuse{sessions = Sessions1},
		    {noreply, State#state{socket_reuse = R1}};
		{ok, Pid} when is_pid(Pid) ->
		    {reply, Pid, State};
		{ok, {Ref, Pending}} ->
		    Sessions1 = dict:store(Key, {Ref, [From|Pending]}, Sessions),
		    R1 = R#reuse{sessions = Sessions1},
		    {noreply, State#state{socket_reuse = R1}}
	    end;
	#reuse{mode = server, sessions = Sessions} ->
	    case dict:find(Key, Sessions) of
		error ->
		    %% server never initiates connection when in reuse mode
		    {reply, rejected, State};
		{ok, Pid} when is_pid(Pid) ->
		    {reply, Pid, State}
	    end
    end;
handle_call(reusable_sessions, _From, #state{socket_reuse = R} = State) ->
    case R of
	#reuse{sessions = Sessions} ->
	    {reply, dict:to_list(Sessions), State};
	_ ->
	    {reply, [], State}
    end;
handle_call(_Request, _From, State) ->
    Reply = ok,
    {reply, Reply, State}.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Handling cast messages
%%
%% @spec handle_cast(Msg, State) -> {noreply, State} |
%%                                  {noreply, State, Timeout} |
%%                                  {stop, Reason, State}
%% @end
%%--------------------------------------------------------------------
handle_cast(_Msg, State) ->
    {noreply, State}.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Handling all non call/cast messages
%%
%% @spec handle_info(Info, State) -> {noreply, State} |
%%                                   {noreply, State, Timeout} |
%%                                   {stop, Reason, State}
%% @end
%%--------------------------------------------------------------------
handle_info({inet_async, LSocket, Ref, {ok,Socket}}, State) when 
      (State#state.listen)#exo_socket.socket =:= LSocket,
      Ref =:= State#state.ref ->
    Listen = State#state.listen,
    NewAccept = exo_socket:async_accept(Listen),
    case exo_socket:async_socket(Listen, Socket, [delay_auth]) of
	{ok, XSocket} ->
	    case exo_socket_session:start(XSocket,
					  State#state.module,
					  State#state.args) of
		{ok,Pid} ->
		    exo_socket:controlling_process(XSocket, Pid),
		    gen_server:cast(Pid, {activate,State#state.active});
		_Error ->
		    exo_socket:close(XSocket)
	    end;
    	_Error ->
    	    error
    end,
    case NewAccept of
	{ok,Ref1} ->
	    {noreply, State#state { ref = Ref1 }};
	{error, Reason} ->
	    {stop, Reason, State}
    end;
%% handle {ok,Socket} on bad ref ?
handle_info({inet_async, _LSocket, Ref, {error,Reason}}, State) when 
      Ref =:= State#state.ref ->
    case exo_socket:async_accept(State#state.listen) of
	{ok,Ref} ->
	    {noreply, State#state { ref = Ref }};
	{error, Reason} ->
	    {stop, Reason, State}
	    %% {noreply, State#state { ref = undefined }}
    end;
handle_info({Pid, ?MODULE, connected, Host, Port},
	    #state{socket_reuse = #reuse{sessions = Sessions} = R} = State) ->
    {_, Pending} = dict:fetch(Key = {Host, Port}, Sessions),
    [gen_server:reply(From, Pid) || From <- Pending],
    Sessions1 = dict:store(Key, Pid, Sessions),
    Pids = dict:store(Pid, {Host,Port}, R#reuse.session_pids),
    R1 = R#reuse{sessions = Sessions1, session_pids = Pids},
    {noreply, State#state{socket_reuse = R1}};
handle_info({Pid, reuse, Config},
	    #state{socket_reuse = #reuse{mode = server,
					 sessions = Sessions,
					 session_pids = Pids} = R} = State) ->
    {_, Port} = lists:keyfind(port, 1, Config),
    case [H || {host, H} <- Config] of
	[Host|_] ->
	    %% we could possibly handle aliases, and thus multiple host names
	    Key = {Host, Port},
	    Sessions1 = dict:store(Key, Pid, Sessions),
	    Pids1 = dict:store(Pid, Key, Pids),
	    R1 = R#reuse{sessions = Sessions1, session_pids = Pids1},
	    {noreply, State#state{socket_reuse = R1}};
	_Other ->
	    ?error("strange reuse config: ~p~n", [_Other]),
	    {noreply, State}
    end;
handle_info({'DOWN', _, process, Pid, _},
	    #state{socket_reuse = #reuse{sessions = Sessions,
					 session_pids = Pids} = R} = State) ->
    case dict:find(Pid, Pids) of
	error ->
	    {noreply, State};
	{_Host,_Port} = Key ->
	    Sessions1 = dict:erase(Key, Sessions),
	    Pids1 = dict:erase(Pid, Pids),
	    R1 = R#reuse{sessions = Sessions1, session_pids = Pids1},
	    {noreply, State#state{socket_reuse = R1}}
    end;
handle_info(_Info, State) ->
    {noreply, State}.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% This function is called by a gen_server when it is about to
%% terminate. It should be the opposite of Module:init/1 and do any
%% necessary cleaning up. When it returns, the gen_server terminates
%% with Reason. The return value is ignored.
%%
%% @spec terminate(Reason, State) -> void()
%% @end
%%--------------------------------------------------------------------
terminate(_Reason, State) ->
    exo_socket:close(State#state.listen),
    ok.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Convert process state when code is changed
%%
%% @spec code_change(OldVsn, State, Extra) -> {ok, NewState}
%% @end
%%--------------------------------------------------------------------
code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

%%%===================================================================
%%% Internal functions
%%%===================================================================


start_connector(Host, Port, ConnArgs, Parent,
		#state{module = M, args = Args, active = Active,
		       socket_reuse = #reuse{port = MyPort}}) ->
    Pid =
	proc_lib:spawn(
	  fun() ->
		  {ok, XSocket} =
		      case ConnArgs of
			  [Protos, Opts, Timeout] ->
			      exo_socket:connect(
				Host, Port, Protos, Opts, Timeout);
			  [Protos, Opts] ->
			      exo_socket:connect(Host, Port, Protos, Opts)
		      end,
		  exo_socket:send(
		    XSocket, <<"reuse%port:", (to_bin(MyPort))/binary>>),
		  {ok, XSt} = exo_socket_session:init([XSocket, M, Args]),
		  {noreply, XSt1} = exo_socket_session:handle_cast(
				      {activate, Active}, XSt),
		  Parent ! {self(), ?MODULE, connected, Host, Port},
		  gen_server:enter_loop(exo_socket_session, [], XSt1)
	  end),
    erlang:monitor(process, Pid),
    Pid.

to_bin(I) when is_integer(I) ->
    list_to_binary(integer_to_list(I));
to_bin(B) when is_binary(B) ->
    B;
to_bin(L) when is_list(L) ->
    list_to_binary(L).
