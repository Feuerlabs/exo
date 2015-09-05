%%%---- BEGIN COPYRIGHT -------------------------------------------------------
%%%
%%% Copyright (C) 2012 Feuerlabs, Inc. All rights reserved.
%%%
%%% This Source Code Form is subject to the terms of the Mozilla Public
%%% License, v. 2.0. If a copy of the MPL was not distributed with this
%%% file, You can obtain one at http://mozilla.org/MPL/2.0/.
%%%
%%%---- END COPYRIGHT ---------------------------------------------------------
%%% @author Tony Rogvall <tony@rogvall.se>
%%% @author Marina Westman Lonne <malotte@malotte.net>
%%% @copyright (C) 2012, Feuerlabs, Inc. All rights reserved.
%%% @doc
%%%   Simple exo_http_server
%%% @end
%%% Created : 2010 by Tony Rogvall <tony@rogvall.se>

-module(exo_http_server).

-behaviour(exo_socket_server).

%% exo_socket_server callbacks
-export([init/2,
	 data/3,
	 close/2,
	 error/3]).

-export([control/4]).

-include("log.hrl").
-include("exo_socket.hrl").
-include("exo_http.hrl").

-define(Q, $\").

-type path() :: string().
-type user() :: binary().
-type password() :: binary().
-type realm() :: string().

-record(state,
	{
	  request,
	  response,
	  authorized = false :: boolean(),
	  private_key = "" :: string(),
	  access = [] :: [{basic,path(),user(),password(),realm()} |
			  {digest,path(),user(),password(),realm()}],
	  request_handler
	}).

%% Configurable start
-export([start/2,
	 start_link/2,
	 response/5, response/6]).

%% For testing
-export([test/0]).
-export([handle_http_request/3]).

%%-----------------------------------------------------------------------------
%% @doc
%%  Starts a socket server on port Port with server options ServerOpts
%% that are sent to the server when a connection is established,
%% i.e init is called.
%%
%% @end
%%-----------------------------------------------------------------------------
-spec start(Port::integer(),
	    ServerOptions::list({Option::atom(), Value::term()})) ->
		   {ok, ChildPid::pid()} |
		   {error, Reason::term()}.

start(Port, Options) ->
    do_start(start, Port, Options).

%%-----------------------------------------------------------------------------
%% @doc
%%  Starts and links a socket server on port Port with server options ServerOpts
%% that are sent to the server when a connection is established,
%% i.e init is called.
%%
%% @end
%%-----------------------------------------------------------------------------
-spec start_link(Port::integer(),
		 ServerOptions::list({Option::atom(), Value::term()})) ->
			{ok, ChildPid::pid()} |
			{error, Reason::term()}.

start_link(Port, Options) ->
    do_start(start_link, Port, Options).


do_start(Start, Port, Options) ->
    ?debug("exo_http_server: ~w: port ~p, server options ~p",
	   [Start, Port, Options]),
    {ServerOptions,Options1} = opts_take([request_handler,access,private_key],
					 Options),
    Dir = code:priv_dir(exo),
    exo_socket_server:Start(Port, [tcp,probe_ssl,http],
			    [{active,once},{reuseaddr,true},
			     {verify, verify_none},
			     {keyfile, filename:join(Dir, "host.key")},
			     {certfile, filename:join(Dir, "host.cert")} |
			     Options1],
			    ?MODULE, ServerOptions).

%%-----------------------------------------------------------------------------
%% @doc
%%  Init function called when a connection is established.
%%
%% @end
%%-----------------------------------------------------------------------------
-spec init(Socket::#exo_socket{},
	   ServerOptions::list({Option::atom(), Value::term()})) ->
		  {ok, State::#state{}}.

init(Socket, Options) ->
    {ok,{_IP,_Port}} = exo_socket:peername(Socket),
    ?debug("exo_http_server: connection from: ~p : ~p,\n options ~p",
	   [_IP, _Port, Options]),
    Access = proplists:get_value(access, Options, []),
    Module = proplists:get_value(request_handler, Options, undefined),
    PrivateKey = proplists:get_value(private_key, Options, ""),
    {ok, #state{ access = Access, private_key=PrivateKey,
		 request_handler = Module}}.

%% To avoid a compiler warning. Should we actually support something here?
%%-----------------------------------------------------------------------------
%% @doc
%%  Control function - not used.
%%
%% @end
%%-----------------------------------------------------------------------------
-spec control(Socket::#exo_socket{},
	      Request::term(), From::term(), State::#state{}) ->
		     {ignore, State::#state{}}.

control(_Socket, _Request, _From, State) ->
    {ignore, State}.

%%-----------------------------------------------------------------------------
%% @doc
%%  Data function called when data is received.
%%
%% @end
%%-----------------------------------------------------------------------------
-spec data(Socket::#exo_socket{},
	   Data::term(),
	   State::#state{}) ->
		  {ok, NewState::#state{}} |
		  {stop, {error, Reason::term()}, NewState::#state{}}.

data(Socket, Data, State) ->
    ?debug("exo_http_server:~w: data = ~w\n", [self(),Data]),
    case Data of
	{http_request, Method, Uri, Version} ->
	    CUri = exo_http:convert_uri(Uri),
	    Req  = #http_request { method=Method,uri=CUri,version=Version},
	    case exo_http:recv_headers(Socket, Req) of
		{ok, Req1} ->
		    handle_request(Socket, Req1, State);
		Error ->
		    {stop, Error, State}
	    end;
	{http_error, ?CRNL} ->
	    {ok, State};
	{http_error, ?NL} ->
	    {ok, State};
	_ when is_list(Data); is_binary(Data) ->
	    ?debug("exo_http_server: request data: ~p\n", [Data]),
	    {stop, {error,sync_error}, State};
	Error ->
	    {stop, Error, State}
    end.

%%-----------------------------------------------------------------------------
%% @doc
%%  Close function called when a connection is closed.
%%
%% @end
%%-----------------------------------------------------------------------------
-spec close(Socket::#exo_socket{},
	    State::#state{}) ->
		   {ok, NewState::#state{}}.

close(_Socket, State) ->
    ?debug("exo_http_server: close\n", []),
    {ok,State}.

%%-----------------------------------------------------------------------------
%% @doc
%%  Error function called when an error is detected.
%%  Stops the server.
%%
%% @end
%%-----------------------------------------------------------------------------
-spec error(Socket::#exo_socket{},
	    Error::term(),
	    State::#state{}) ->
		   {stop, {error, Reason::term()}, NewState::#state{}}.

error(_Socket,Error,State) ->
    ?debug("exo_http_serber: error = ~p\n", [Error]),
    {stop, Error, State}.


handle_request(Socket, R, State) ->
    ?debug("exo_http_server: request = ~s\n",
	 [[exo_http:format_request(R),?CRNL,
	   exo_http:format_hdr(R#http_request.headers),
	   ?CRNL]]),
    case exo_http:recv_body(Socket, R) of
	{ok, Body} ->
	    case handle_auth(Socket, R, Body, State) of
		ok ->
		    handle_body(Socket, R, Body, State);
		{required,AuthenticateValue,State} ->
		    response(Socket,undefined, 401, "Unauthorized", "",
			     [{'WWW-Authenticate', AuthenticateValue}]),
		    {ok,State}
	    end;

	{error, closed} ->
	    {stop, normal,State};
	Error ->
	    {stop, Error, State}
    end.

handle_auth(_Socket, _Request, _Body, State) when State#state.authorized ->
    ok;
handle_auth(Socket, Request, Body, State) when not State#state.authorized ->
    Access = State#state.access,
    if Access =:= [] ->
	    ok;
       true ->
	    Header = Request#http_request.headers,
	    Autorization = get_authorization(Header#http_chdr.authorization),
	    ?debug("authorization = ~p", [Autorization]),
	    case match_access(Request#http_request.uri, Access) of
		[Cred={basic,_Path,_User,_Password,_Realm}|_] ->
		    ?debug("cred = ~p", [Cred]),
		    handle_basic_auth(Socket, Request, Body, Autorization,
				      Cred, State);
		[Cred={digest,_Path,_User,_Password,_Realm}|_] ->
		    handle_digest_auth(Socket, Request, Body, Autorization,
				       Cred, State);
		[] -> ok
	    end
    end.

handle_basic_auth(_Socket, _Request, _Body, {basic,AuthParams},
		  _Cred={basic,_Path,User,Password,Realm}, State) ->
    AuthUser =  proplists:get_value(<<"user">>, AuthParams),
    AuthPassword = proplists:get_value(<<"password">>, AuthParams),
    if AuthUser =:= User, AuthPassword =:= Password ->
	    ok;
       true ->
	    {required, ["Basic realm=",?Q,Realm,?Q], State}
    end;
handle_basic_auth(_Socket, _Request, _Body, _,
		  _Cred={basic,_Path,_User,_Password,Realm}, State) ->
    {required, ["Basic realm=",?Q,Realm,?Q], State}.


handle_digest_auth(_Socket, Request, _Body, {digest,AuthParams},
		   Cred={digest,_Path,_User,_Password,Realm}, State) ->
    Response = proplists:get_value(<<"response">>,AuthParams,""),
    Nonce = proplists:get_value(<<"nonce">>,AuthParams,""),
    DigestUriValue = proplists:get_value(<<"uri">>,AuthParams,""),
    %% FIXME! Verify Nonce!!!
    A1 = a1(Cred),
    %% ?debug("A1 = \"~s\"", [A1]),
    HA1 = hex(crypto:md5(A1)),
    A2 = a2(Request#http_request.method, DigestUriValue),
    %% ?debug("A2 = \"~s\"", [A2]),
    HA2 = hex(crypto:md5(A2)),
    Digest = hex(kd(HA1, Nonce++":"++HA2)),
    %% ?debug("Digest = \"~s\"", [Digest]),
    if Digest =:= Response ->
	    ok;
       true ->
	    Nonce1 = nonce_value(Request, State),
	    {required, ["Digest realm=",?Q,Realm,?Q," ",
			"nonce=",?Q,Nonce1,?Q], State}
    end;
handle_digest_auth(_Socket, Request, _Body, _,
		   _Cred={digest,_Path,_User,_Password,Realm}, State) ->
    Nonce = nonce_value(Request, State),
    {required, ["Digest realm=",?Q,Realm,?Q," ",
		"nonce=",?Q,Nonce,?Q], State}.

nonce_value(Request, State) ->
    Header = Request#http_request.headers,
    ETag = unq(proplists:get_value('ETag',Header#http_chdr.other,"")),
    T = now64(),
    TimeStamp = hex(<<T:64>>),
    hex(crypto:md5([TimeStamp,":",ETag,":",State#state.private_key])).

a1({_,_Path,User,Password,Realm}) ->
    iolist_to_binary([User,":",Realm,":",Password]).

a2(Method, Uri) ->
    iolist_to_binary([atom_to_list(Method),":",Uri]).

kd(Secret, Data) ->
    crypto:md5([Secret,":",Data]).

%% convert binary to ASCII hex
hex(Bin) ->
    [ element(X+1, {$0,$1,$2,$3,$4,$5,$6,$7,$8,$9,$a,$b,$c,$d,$e,$f}) ||
	<<X:4>> <= Bin ].

now64() ->
    {M,S,Us} = now(),
    (M*1000000+S)*1000000+Us.

match_access(Url, Access) ->
    match_access(Url, Access, []).

match_access(Url, [A={_Type,Path,_U,_P,_R}|Access], Acc) ->
    case lists:prefix(Path, Url#url.path) of
	true ->
	    match_access(Url, Access, [A|Acc]);
	false ->
	    match_access(Url, Access, Acc)
    end;
match_access(_Url, [], Acc) ->
    %% find the access with the longest path match
    lists:sort(
      fun({_,Path1,_,_,_},{_,Path2,_,_,_}) ->
	      length(Path1) > length(Path2)
      end, Acc).


%% Read and parse Authorization header value
get_authorization(undefined) ->
    {none,[]};
get_authorization([]) ->
    {none,[]};
get_authorization([$\s|Cs]) ->
    get_authorization(Cs);
get_authorization("Basic "++Cs) ->
    [User,Password] = binary:split(base64:decode(Cs), <<":">>),
    {basic, [{<<"user">>,User}, {<<"password">>, Password}]};
get_authorization("Digest "++Cs) ->
    {digest, get_params(list_to_binary(Cs))}.

get_params(Bin) ->
    Ps = binary:split(Bin, <<", ">>, [global]),
    [ case binary:split(P, <<"=">>) of
	  [K,V] -> {K,unq(V)};
	  [K] -> {K,true}
      end || P <- Ps ].

%% "unquote" a string or a binary
unq(String) when is_binary(String) -> unq(binary_to_list(String));
unq([$\s|Cs]) -> unq(Cs);
unq([?Q|Cs]) -> unq_(Cs);
unq(Cs) -> Cs.

unq_([?Q|_]) -> [];
unq_([C|Cs]) -> [C|unq_(Cs)];
unq_([]) -> [].

handle_body(Socket, Request, Body, State) ->
    RH = State#state.request_handler,
    {M, F, As} = request_handler(RH,Socket, Request, Body),
    ?debug("exo_http_server: calling ~p with -BODY:\n~s\n-END-BODY\n",
	   [RH, Body]),
    case apply(M, F, As) of
	ok -> {ok, State};
	stop -> {stop, normal, State};
	{error, Error} ->  {stop, Error, State}
    end.

%% @private
request_handler(undefined, Socket, Request, Body) ->
    {?MODULE, handle_http_request, [Socket, Request, Body]};
request_handler(Module, Socket, Request, Body) when is_atom(Module) ->
    {Module, handle_http_request, [Socket, Request, Body]};
request_handler({Module, Function}, Socket, Request, Body) ->
    {Module, Function, [Socket, Request, Body]};
request_handler({Module, Function, XArgs}, Socket, Request, Body) ->
    {Module, Function, [Socket, Request, Body | XArgs]}.

%%-----------------------------------------------------------------------------
%% @doc
%%  Support function for sending an http response.
%%
%% @end
%%-----------------------------------------------------------------------------
-spec response(Socket::#exo_socket{},
	      Connection::string() | undefined,
	      Status::integer(),
	      Phrase::string(),
	      Body::string()) ->
				ok |
				{error, Reason::term()}.

response(S, Connection, Status, Phrase, Body) ->
    response(S, Connection, Status, Phrase, Body, []).

%%-----------------------------------------------------------------------------
%% @doc
%%  Support function for sending an http response.
%%
%% @end
%%-----------------------------------------------------------------------------
-spec response(Socket::#exo_socket{},
	      Connection::string() | undefined,
	      Status::integer(),
	      Phrase::string(),
	      Body::string(),
	      Opts::list()) ->
				ok |
				{error, Reason::term()}.
response(S, Connection, Status, Phrase, Body, Opts) ->
    {Content_type, Opts1} = opt_take(content_type, Opts, "text/plain"),
    {Set_cookie, Opts2} = opt_take(set_cookie, Opts1, undefined),
    {Transfer_encoding,Opts3} = opt_take(transfer_encoding, Opts2, undefined),
    {Location,Opts4} = opt_take(location, Opts3, undefined),
    ContentLength = if Transfer_encoding =:= "chunked", Body == "" ->
			    undefined;
		       true ->
			    content_length(Body)
		    end,
    H = #http_shdr { connection = Connection,
		     content_length = ContentLength,
		     content_type = Content_type,
		     set_cookie = Set_cookie,
		     transfer_encoding = Transfer_encoding,
		     location = Location,
		     other = Opts4 },

    R = #http_response { version = {1, 1},
			 status = Status,
			 phrase = Phrase,
			 headers = H },
    Response = [exo_http:format_response(R),
		?CRNL,
		exo_http:format_hdr(H),
		?CRNL,
		Body],
    ?debug("exo_http_server: response:\n~s\n", [Response]),
    exo_socket:send(S, Response).

content_length(B) when is_binary(B) ->
    byte_size(B);
content_length(L) when is_list(L) ->
    iolist_size(L).

%% return value or defaule and the option list without the key
opt_take(K, L, Def) ->
    case lists:keytake(K, 1, L) of
	{value,{_,V},L1} -> {V,L1};
	false -> {Def,L}
    end.

%% return a option list of value from Ks remove the keys found
opts_take(Ks, L) ->
    opts_take_(Ks, L, []).

opts_take_([K|Ks], L, Acc) ->
    case lists:keytake(K, 1, L) of
	{value,Kv,L1} ->
	    opts_take_(Ks, L1, [Kv|Acc]);
	false ->
	    opts_take_(Ks, L, Acc)
    end;
opts_take_([], L, Acc) ->
    {lists:reverse(Acc), L}.

%% @private
handle_http_request(Socket, Request, Body) ->
    Url = Request#http_request.uri,
    ?debug("exo_http_server: -BODY:\n~s\n-END-BODY\n", [Body]),
    if Request#http_request.method =:= 'GET',
       Url#url.path =:= "/quit" ->
	    response(Socket, "close", 200, "OK", "QUIT"),
	    exo_socket:shutdown(Socket, write),
	    stop;
       Url#url.path =:= "/test" ->
	    response(Socket, undefined, 200, "OK", "OK"),
	    ok;
       true ->
	    response(Socket, undefined, 404, "Not Found",
		     "Object not found"),
	    ok
    end.

test() ->
    Dir = code:priv_dir(exo),
    Access = [],
%%    Access = [{basic,"/foo",<<"user">>,<<"password">>,"world"},
%%	      {digest,"/test",<<"test">>,<<"password">>,"region"}],
    exo_socket_server:start(9000, [tcp,probe_ssl,http],
			    [{active,once},{reuseaddr,true},
			     {verify, verify_none},
			     {keyfile, filename:join(Dir, "host.key")},
			     {certfile, filename:join(Dir, "host.cert")}],
			    ?MODULE, [{access,Access}]).
