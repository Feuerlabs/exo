%%%---- BEGIN COPYRIGHT -------------------------------------------------------
%%%
%%% Copyright (C) 2012-2016 Feuerlabs, Inc. All rights reserved.
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

-include("exo_socket.hrl").
-include("exo_http.hrl").

-define(Q, $\").

-type path() :: string().
-type user() :: binary().
-type password() :: binary().
-type realm() :: string().
-type ip_address() :: {integer(),integer(),integer(),integer()} |
		      {integer(),integer(),integer(),integer(),integer(),integer()}.
-type cred() :: {basic,path(),user(),password(),realm()} |
		{digest,path(),user(),password(),realm()}. %% Old type
-type guard() :: ip_address() | 
		 {ip_address(), integer()} |
		 afunix |
		 http |
		 https.
-type action() :: accept | reject | {accept , list(cred())}.
-type access() :: cred() | {guard(), action()}.

-record(state,
	{
	  request,
	  response,
	  authorized = false :: boolean(),
	  private_key = "" :: string(),
	  access = [] :: [access()],
	  request_handler
	}).

%% Configurable start
-export([start/2,
	 start_link/2,
	 response/5, response/6]).

%% For testing
-export([test/0, test/1]).
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
    lager:debug("exo_http_server: ~w: port ~p, server options ~p",
	   [Start, Port, Options]),
    {ServerOptions,Options1} = opts_take([request_handler,access,private_key],
					 Options),
    Dir = code:priv_dir(exo),
    Access = lists:sort(proplists:get_value(access, Options, [])),
    case validate_auth(Access) of
	ok ->
	    exo_socket_server:Start(Port, 
				    [tcp,probe_ssl,http],
				    [{active,once},{reuseaddr,true},
				     {verify, verify_none},
				     {keyfile, filename:join(Dir, "host.key")},
				     {certfile, filename:join(Dir, "host.cert")}
				     | Options1],
				    ?MODULE, ServerOptions);
	E -> E
    end.

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
    lager:debug("exo_http_server: connection on: ~p ", [Socket]),
    {ok, _PeerName} = exo_socket:peername(Socket),
    {ok, _SockName} = exo_socket:sockname(Socket),
    lager:debug("exo_http_server: connection from peer: ~p, sockname: ~p,\n"
		"options ~p", [_PeerName, _SockName, Options]),
    Access = lists:sort(proplists:get_value(access, Options, [])),
    Module = proplists:get_value(request_handler, Options, undefined),
    PrivateKey = proplists:get_value(private_key, Options, ""),
    {ok, #state{access = Access, private_key=PrivateKey,
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
    lager:debug("exo_http_server:~w: data = ~w\n", [self(),Data]),
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
	    lager:debug("exo_http_server: request data: ~p\n", [Data]),
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
    lager:debug("exo_http_server: close\n", []),
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
    lager:debug("exo_http_serber: error = ~p\n", [Error]),
    {stop, Error, State}.


handle_request(Socket, R, State) ->
    lager:debug("exo_http_server: request = ~s\n",
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
		    {ok,State};
		{error, unauthorised} ->
		    response(Socket,undefined, 401, "Unauthorized", "", []),
		    {ok,State}
	    end;

	{error, closed} ->
	    {stop, normal,State};
	Error ->
	    {stop, Error, State}
    end.

handle_auth(_Socket, _Request, _Body, State) 
  when State#state.authorized ->
    ok;
handle_auth(_Socket, _Request, _Body, State=#state {access = []}) 
  when not State#state.authorized ->
    %% No access specied, all is allowed.
    ok;
handle_auth(Socket, Request, Body, State=#state {access = Access})  
  when not State#state.authorized ->
    handle_access(Access, Socket, Request, Body, State).

handle_access([], _Socket, _Request, _Body, _State) ->
    %% No access found
    {error, unauthorised};
handle_access([{Guard, Action} | Rest], Socket, Request, Body, State) ->
    case match_access(Guard, Socket, Request) of
	true -> do(Action, Socket, Request, Body, State);
	false -> handle_access(Rest, Socket, Request, Body, State)
    end;
handle_access([[{Tag, Path, User, Pass, Realm}| _T] = Creds | Rest], 
	      Socket, Request, Body, State) 
  when (Tag =:= basic orelse Tag =:= digest) andalso
       is_list(Path) andalso is_binary(User) andalso 
       is_binary(Pass) andalso is_list(Realm) ->
    %% Is this format possible ???
    case handle_creds(Socket, Request, Body, Creds, State) of
	ok -> ok;
	_ -> handle_access(Rest, Socket, Request, Body, State)
    end;
handle_access([{Tag, Path, User, Pass, Realm}| _T] = Creds, 
	      Socket, Request, Body, State) 
  when (Tag =:= basic orelse Tag =:= digest) andalso
       is_list(Path) andalso is_binary(User) andalso 
       is_binary(Pass) andalso is_list(Realm) ->
    %% Old way
    handle_creds(Socket, Request, Body, Creds, State).
	    
do(accept, _Socket, _Request, _Body, _State) -> ok;
do(reject, _Socket, _Request, _Body, _State) -> {error, unauthorised};
do({accept, AccessList}, Socket, Request, Body, State) ->
    handle_creds(Socket, Request, Body, AccessList, State).
    
match_access({any, GuardList}, Socket, Request) ->
    lists:any(fun(Guard) -> match_access(Guard, Socket, Request) end, 
	      GuardList);
match_access({all, GuardList}, Socket, Request) ->
    lists:all(fun(Guard) -> match_access(Guard, Socket, Request) end, 
	      GuardList);
match_access(afunix, #exo_socket {mdata = afunix}, _Request) ->
    true;
match_access(afunix, _Socket, _Request) ->
    false;
match_access(http, Socket, _Request) ->
    %%% ???
    not exo_socket:is_ssl(Socket);
match_access(https, Socket, _Request) ->
    %%% ???
    exo_socket:is_ssl(Socket);
match_access({Ip, Port}, Socket, _R) ->
    case exo_socket:peername(Socket) of
	{ok, {PeerIP, PeerPort}} ->
	    ((Port =:= '*') orelse (Port =:= PeerPort)) andalso
		match_ip(Ip, PeerIP);
	_ -> false
    end;
match_access(Ip, Socket, _R) ->
    case exo_socket:peername(Socket) of
	{ok, {PeerIP, _Port}} -> 
	    match_ip(Ip, PeerIP);
	_ -> false
    end.

match_ip({Pa,Pb,Pc,Pd}, {A,B,C,D}) ->
    if ((Pa =:= '*') orelse (Pa =:= A)) andalso
       ((Pb =:= '*') orelse (Pb =:= B)) andalso
       ((Pc =:= '*') orelse (Pc =:= C)) andalso
       ((Pd =:= '*') orelse (Pd =:= D)) ->
	    true;
       true -> false
    end;
match_ip({Pa,Pb,Pc,Pd,Pe,Pf,Pg,Ph}, {A,B,C,D,E,F,G,H}) ->
    if ((Pa =:= '*') orelse (Pa =:= A)) andalso
       ((Pb =:= '*') orelse (Pb =:= B)) andalso
       ((Pc =:= '*') orelse (Pc =:= C)) andalso
       ((Pd =:= '*') orelse (Pd =:= D)) andalso
       ((Pe =:= '*') orelse (Pe =:= E)) andalso
       ((Pf =:= '*') orelse (Pf =:= F)) andalso
       ((Pg =:= '*') orelse (Pg =:= G)) andalso
       ((Ph =:= '*') orelse (Ph =:= H)) ->
	    true;
       true -> false
    end;
match_ip(_, _) ->
    false.


handle_creds(Socket, Request, Body, Creds, State) ->
    Header = Request#http_request.headers,
    Autorization = get_authorization(Header#http_chdr.authorization),
    lager:debug("authorization = ~p", [Autorization]),
    case match_access_path(Request#http_request.uri, Creds) of
	[Cred={basic,_Path,_User,_Password,_Realm}|_] ->
	    lager:debug("cred = ~p", [Cred]),
	    handle_basic_auth(Socket, Request, Body, Autorization,
			      Cred, State);
	[Cred={digest,_Path,_User,_Password,_Realm}|_] ->
	    handle_digest_auth(Socket, Request, Body, Autorization,
				       Cred, State);
	[] -> ok
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
		   Cred={digest,_Path,_User,_Password,_Realm}, State) ->
    Response = proplists:get_value(<<"response">>,AuthParams,""),
    Method = Request#http_request.method,
    Digest = exo_http:make_digest_response(Cred, Method, AuthParams),
    %% io:format("response=~p, digest=~p\n", [Response,Digest]),
    if Digest =:= Response ->
	    ok;
       true ->
	    digest_required(Request, Cred, State)
    end;
handle_digest_auth(_Socket, Request, _Body, _, Cred, State) ->
    digest_required(Request, Cred, State).

digest_required(Request,_Cred={digest,_Path,_User,_Password,Realm},State) ->
    Nonce = nonce_value(Request, State),
    {required, ["Digest realm=",?Q,Realm,?Q," ",
%%		"url=",?Q,Path,?Q," ",
		"nonce=",?Q,Nonce,?Q], State}.

nonce_value(Request, State) ->
    Header = Request#http_request.headers,
    ETag = unq(proplists:get_value('ETag',Header#http_chdr.other,"")),
    T = now64(),
    TimeStamp = hex(<<T:64>>),
    hex(crypto:md5([TimeStamp,":",ETag,":",State#state.private_key])).


%% convert binary to ASCII hex
hex(Bin) ->
    [ element(X+1, {$0,$1,$2,$3,$4,$5,$6,$7,$8,$9,$a,$b,$c,$d,$e,$f}) ||
	<<X:4>> <= Bin ].

now64() ->
    try
	erlang:system_time(milli_seconds)
    catch
	error:undef ->
	    {M,S,Us} = erlang:now(),
	    (M*1000000+S)*1000000+Us
    end.

match_access_path(Url, Access) ->
    match_access_path(Url, Access, []).

match_access_path(Url, [A={_Type,Path,_U,_P,_R}|Access], Acc) ->
    case lists:prefix(Path, Url#url.path) of
	true ->
	    match_access_path(Url, Access, [A|Acc]);
	false ->
	    match_access_path(Url, Access, Acc)
    end;
match_access_path(_Url, [], Acc) ->
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
    lager:debug("exo_http_server: calling ~p with -BODY:\n~s\n-END-BODY\n",
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
    {Version, Opts5} = opt_take(version, Opts4, {1,1}),
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
		     other = Opts5 },

    R = #http_response { version = Version,
			 status = Status,
			 phrase = Phrase,
			 headers = H },
    Response = [exo_http:format_response(R),
		?CRNL,
		exo_http:format_hdr(H),
		?CRNL,
		Body],
    lager:debug("exo_http_server: response:\n~s\n", [Response]),
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
    lager:debug("exo_http_server: -BODY:\n~s\n-END-BODY\n", [Body]),
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


%%-----------------------------------------------------------------------------
validate_auth([]) ->
    ok;
validate_auth([{Guard, Action} | Rest]) ->
    case {validate_guard(Guard), validate_action(Action)} of
	{ok, ok} -> validate_auth(Rest);
	_O -> {error, invalid_access}
    end;
validate_auth([Other | Rest]) ->
    %% Maybe old format?
    case validate_access(Other) of
	ok -> validate_auth(Rest);
	_O -> {error, invalid_access}
    end.
	    
validate_access({Tag, Path, User, Pass, Realm}) 
  when (Tag =:= basic orelse Tag =:= digest) andalso
       is_list(Path) andalso is_binary(User) andalso
       is_binary(Pass) andalso is_list(Realm) ->
    %% old format ok
    ok;
validate_access(_Other) ->
    lager:error("Unknown access ~p", [_Other]),
    {error, invalid_access}.

validate_guard([]) ->
    ok;
validate_guard([Guard | Rest]) ->
    case validate_guard(Guard) of
	ok -> validate_guard(Rest);
	E -> E
    end;
validate_guard({Tag, GuardList}) when Tag =:= any; Tag =:= all -> 
    validate_guard(GuardList);
validate_guard({IP, '*'}) -> validate_ip(IP);
validate_guard({IP, Port}) when is_integer(Port) -> validate_ip(IP);
validate_guard(http) -> ok;
validate_guard(https) -> ok;
validate_guard(afunix) -> ok;
validate_guard(IP) 
  when is_tuple(IP) andalso 
       (tuple_size(IP) =:= 4 orelse tuple_size(IP) =:= 8) -> 
    validate_ip(IP);
validate_guard(_Other) -> 
    lager:error("Unknown access guard ~p", [_Other]),
    {error, invalid_access}.

validate_ip(_IP={A, B, C, D}) ->
    if (is_integer(A) orelse (A =:= '*')) andalso
       (is_integer(B) orelse (B =:= '*')) andalso
       (is_integer(C) orelse (C =:= '*')) andalso
       (is_integer(D) orelse (D =:= '*')) ->
	    ok;
       false ->
	    lager:error("Illegal IP address ~p", [_IP]),
	    {error, invalid_access}
    end;
validate_ip(_IP={A, B, C, D, E, F, G, H}) ->
    if (is_integer(A) orelse (A =:= '*')) andalso
       (is_integer(B) orelse (B =:= '*')) andalso
       (is_integer(C) orelse (C =:= '*')) andalso
       (is_integer(D) orelse (D =:= '*')) andalso
       (is_integer(E) orelse (E =:= '*')) andalso
       (is_integer(F) orelse (F =:= '*')) andalso
       (is_integer(G) orelse (G =:= '*')) andalso
       (is_integer(H) orelse (H =:= '*')) ->
	    ok;
       false ->
	    lager:error("Illegal IP address ~p", [_IP]),
	    {error, invalid_access}
    end;
validate_ip(_Other) ->
    lager:error("Illegal IP address ~p", [_Other]),
    {error, invalid_access}.
	    
validate_action(Auth)
  when Auth =:= accept;
       Auth =:= reject ->
    ok;
validate_action({accept, AccessList} = A)->
    case lists:all(fun(Access) ->
			   validate_access(Access) =:= ok
		   end, AccessList) of
	true -> 
	    ok;
	false -> 
	    lager:error("Illegal access ~p", [A]),
	    {error, invalid_access}
    end.



%%-----------------------------------------------------------------------------
test() ->
    %% Access = [],
    Access = [{basic,"/foo",<<"user">>,<<"password">>,"world"},
	      {digest,"/test/a",<<"test">>,<<"a">>,"region"},
	      {digest,"/test/b",<<"test">>,<<"b">>,"region"},
	      {digest,"/test/b/c",<<"test">>,<<"c">>,"region"},
	      {digest,"/test/b/d",<<"test">>,<<"d">>,"region"},
	      {digest,"/test",<<"test">>,<<"x">>,"region"},
	      {digest,"/bar",<<"test">>,<<"bar">>,"region"}
	     ],
    test(Access).

test(old) ->
    test();
test(new) ->
   Access = [{afunix, accept},
	     {{127, 0, 0, 1},
	      {access, [
			{basic,"/foo",<<"user">>,<<"password">>,"world"},
			{digest,"/test/a",<<"test">>,<<"a">>,"region"},
			{digest,"/test/b",<<"test">>,<<"b">>,"region"},
			{digest,"/test/b/c",<<"test">>,<<"c">>,"region"},
			{digest,"/test/b/d",<<"test">>,<<"d">>,"region"},
			{digest,"/test",<<"test">>,<<"x">>,"region"},
			{digest,"/bar",<<"test">>,<<"bar">>,"region"}]}}
	     ],
    test(Access);
test(Access) ->
    Dir = code:priv_dir(exo),
    exo_socket_server:start(9000, [tcp,probe_ssl,http],
			    [{active,once},{reuseaddr,true},
			     {verify, verify_none},
			     {keyfile, filename:join(Dir, "host.key")},
			     {certfile, filename:join(Dir, "host.cert")}],
			    ?MODULE, [{access,Access}]).
