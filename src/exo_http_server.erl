%%% @author Tony Rogvall <tony@rogvall.se>
%%% @copyright (C) 2010, Tony Rogvall
%%% @doc
%%%   Simple exo_http_server
%%% @end
%%% Created : 26 Apr 2010 by Tony Rogvall <tony@rogvall.se>

-module(exo_http_server).

-compile(export_all).

-behaviour(exo_socket_server).

-export([init/2, data/3, close/2, error/3]).

-include("../include/exo_http.hrl").

-record(state,
	{
	  request,
	  response,
	  access = []
	}).

-ifdef(debug).
-define(dbg(F, A), io:format((F), (A))).
-else.
-define(dbg(F, A), ok).
-endif.

-export([test/0]).

test() ->
    Dir = code:priv_dir(exo),
    exo_socket_server:start(9000, [tcp,probe_ssl,http],
			    [{active,once},{reuseaddr,true},
			     {verify, verify_none},
			     {keyfile, filename:join(Dir, "host.key")},
			     {certfile, filename:join(Dir, "host.cert")}],
			    ?MODULE, []).

init(Socket, Options) ->
    {ok,{_IP,_Port}} = exo_socket:peername(Socket),
    ?dbg("exo_http_server: connection from: ~p : ~p\n",[_IP, _Port]),
    Access = proplists:get_value(access, Options, []),
    {ok, #state{ access=Access}}.    

data(Socket, Data, State) ->
    ?dbg("exo_http_server:~w: data = ~w\n", [self(),Data]),
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
	    ?dbg("Request data: ~p\n", [Data]),
	    {stop, {error,sync_error}, State};
	Error ->
	    {stop, Error, State}
    end.

close(_Socket, State) ->
    ?dbg("exo_http_server: close\n", []),
    {ok,State}.

error(_Socket,Error,State) ->
    ?dbg("exo_http_serber: error = ~p\n", [Error]),
    {stop, Error, State}.    


handle_request(Socket, R, State) ->
    ?dbg("exo_http_server: request = ~s\n", 
	 [[exo_http:format_request(R),?CRNL,
	   exo_http:format_hdr(R#http_request.headers),
	   ?CRNL]]),
    case exo_http:recv_body(Socket, R) of
	{ok, _Body} ->
	    U = R#http_request.uri,
	    ?dbg("-BODY:\n~s\n-END-BODY\n", [_Body]),
	    if R#http_request.method == 'GET',
	       U#url.path == "/quit" ->
		    response(Socket, "close", 200, "OK", "QUIT"),
		    exo_socket:shutdown(Socket, write),
		    {stop, normal, State};
	       U#url.path == "/test" ->
		    response(Socket, undefined, 200, "OK", "OK"),
		    {ok, State};
	       true ->
		    response(Socket, undefined, 404, "Not Found", 
			     "Object not found"),
		    {ok, State}
	    end;
	{error, closed} ->
	    {stop, normal,State};
	Error ->
	    {stop, Error, State}
    end.
	    
response(S, Connection, Status, Phrase, String) ->
    H = #http_shdr { connection = Connection,
		     content_length = length(String),
		     content_type = "text/plain" },
    R = #http_response { version = {1,1},
			status = Status,
			phrase = Phrase,
			headers = H},	
    Response = [exo_http:format_response(R),
		?CRNL,
		exo_http:format_hdr(H),
		?CRNL,
		String],
    ?dbg("Response:\n~s\n", [Response]),
    exo_socket:send(S, Response).
