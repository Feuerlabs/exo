%%%-------------------------------------------------------------------
%%% @author Tony Rogvall <tony@rogvall.se>
%%% @copyright (C) 2011, Tony Rogvall
%%% @doc
%%%   EXO TCP session
%%% @end
%%% Created : 22 Aug 2011 by Tony Rogvall <tony@rogvall.se>
%%%-------------------------------------------------------------------
-module(exo_socket_session).

-behaviour(gen_server).

%% API
-export([start/3, start_link/3]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
	 terminate/2, code_change/3]).

-define(SERVER, ?MODULE). 

-record(state, {
	  module,
	  args,
	  socket,
	  active,
	  state
	 }).

-include("exo_socket.hrl").


-ifdef(debug).
-define(dbg(F, A), io:format((F), (A))).
-else.
-define(dbg(F, A), ok).
-endif.

-type exo_socket() :: #exo_socket {}.
%%%===================================================================
%%% API
%%%===================================================================

%%--------------------------------------------------------------------
%% @doc
%% Starts the server
%% @end
%%--------------------------------------------------------------------

-spec start_link(Socket::exo_socket(), Module::atom(), Args::[term()]) ->
			{ok, pid()} | ignore | {error, Error::term()}.

start_link(XSocket,Module,Args) ->
    gen_server:start_link(?MODULE, [XSocket,Module,Args], []).

-spec start(Socket::exo_socket(), Module::atom(), Args::[term()]) ->
		   {ok, pid()} | ignore | {error, Error::term()}.

start(XSocket, Module, Args) ->
    gen_server:start(?MODULE, [XSocket,Module,Args], []).


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
init([XSocket, Module, Args]) ->
    {ok, #state{ socket=XSocket,
		 module=Module,
		 args=Args,
		 state=undefined }}.

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
handle_cast({activate,Active}, State) ->
    case apply(State#state.module, init, [State#state.socket,State#state.args]) of
	{ok,CSt0} ->
	    %% enable active mode here (if ever wanted) once is handled,
	    %% automatically anyway. exit_on_close is default and
	    %% allow session statistics retrieval in the close callback
	    SessionOpts = [{active,Active},{exit_on_close, false}],
	    
	    _Res = exo_socket:setopts(State#state.socket, SessionOpts),
	    ?dbg("exo_socket:setopts(~w) = ~w\n", [SessionOpts, _Res]),
	    {noreply, State#state { active = Active, state = CSt0 }};

	{stop,Reason,CSt1} ->
	    {stop, Reason, State#state { state = CSt1 }}
    end;
    
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
handle_info({Tag,Socket,Data}, State) when 
      %% FIXME: put socket tag in State for correct matching
      (Tag =:= tcp orelse Tag =:= ssl orelse Tag =:= http), 
      Socket =:= (State#state.socket)#exo_socket.socket ->
    io:format("exo_socket_session: got ~p\n", [{Tag,Socket,Data}]),
    CSt0 = State#state.state,
    case apply(State#state.module, data, [State#state.socket,Data,CSt0]) of
	{ok,CSt1} ->
	    if State#state.active == once ->
		    exo_socket:setopts(State#state.socket, [{active,once}]);
	       true ->
		    ok
	    end,
	    {noreply, State#state { state = CSt1 }};

	{close, CSt1} ->
	    exo_socket:shutdown(State#state.socket, write),
	    {noreply, State#state { state = CSt1 }};

	{stop,Reason,CSt1} ->
	    {stop, Reason, State#state { state = CSt1 }}
    end;
handle_info({Tag,Socket}, State) when
      (Tag =:= tcp_closed orelse Tag =:= ssl_closed),
      Socket =:= (State#state.socket)#exo_socket.socket ->
    io:format("exo_socket_session: got ~p\n", [{Tag,Socket}]),
    CSt0 = State#state.state,
    case apply(State#state.module, close, [State#state.socket,CSt0]) of
	{ok,CSt1} ->
	    {stop, normal, State#state { state = CSt1 }}
    end;
handle_info({Tag,Socket,Error}, State) when 
      (Tag =:= tcp_error orelse Tag =:= ssl_error),
      Socket =:= (State#state.socket)#exo_socket.socket ->
    io:format("exo_socket_session: got ~p\n", [{Tag,Socket,Error}]),
    CSt0 = State#state.state,
    case apply(State#state.module, error, [State#state.socket,Error,CSt0]) of
	{ok,CSt1} ->
	    {noreply, State#state { state = CSt1 }};
	{stop,Reason,CSt1} ->
	    {stop, Reason, State#state { state = CSt1 }}
    end;
    
handle_info(_Info, State) ->
    io:format("Got info: ~p\n", [_Info]),
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
    exo_socket:close(State#state.socket),
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

