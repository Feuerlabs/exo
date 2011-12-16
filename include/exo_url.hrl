%%% @author Tony Rogvall <tony@rogvall.se>
%%% @copyright (C) 2011, Tony Rogvall
%%% @doc
%%%    URL definition
%%% @end
%%% Created : 16 Dec 2011 by Tony Rogvall <tony@rogvall.se>

-ifndef(_EXO_URL_HRL_).
-define(_EXO_URL_HRL_, true).

-record(url,
	{
	  scheme,
	  host, 
	  port,            %% undefined means not set
	  path = "",
	  querypart = ""
	 }). 

-endif.

