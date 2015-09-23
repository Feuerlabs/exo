%%%---- BEGIN COPYRIGHT -------------------------------------------------------
%%%
%%% Copyright (C) 2012 Feuerlabs, Inc. All rights reserved.
%%%
%%% This Source Code Form is subject to the terms of the Mozilla Public
%%% License, v. 2.0. If a copy of the MPL was not distributed with this
%%% file, You can obtain one at http://mozilla.org/MPL/2.0/.
%%%
%%%---- END COPYRIGHT ---------------------------------------------------------

-module(exo_sup).

-behaviour(supervisor).

%% API
-export([start_link/0,
	 start_link/1]).

%% Supervisor callbacks
-export([init/1]).

%% Helper macro for declaring children of supervisor
-define(CHILD(I,T,A), {I, {I,start_link,A},permanent,5000,T,[I]}).

%% ===================================================================
%% API functions
%% ===================================================================

start_link() ->
    supervisor:start_link({local, ?MODULE}, ?MODULE, []).

start_link(Args) ->
    supervisor:start_link({local, ?MODULE}, ?MODULE, [Args]).

%% ===================================================================
%% Supervisor callbacks
%% ===================================================================

init(Args) ->
    F = ?CHILD(exo_flow,worker,Args),
    {ok, { {one_for_all, 5, 10}, [F]} }.

