%%
%% mod_rayo_gateway.erl
%%
%% Copyright 2013 Grasshopper.  All rights reserved.
%%
%% Contributors:
%%   Chris Rienzo <chris.rienzo@grasshopper.com>
%%
-module(mod_rayo_gateway).

-include("ejabberd.hrl").
-include("jlib.hrl").

-behavior(gen_server).
-behavior(gen_mod).

%%  JID mappings
%%
%%  Entity          Internal JID                     Mapped JID
%%  ======          ===============                  ===============
%%  Client          user@domain/resource             gateway@internal_domain/gw-resource
%%  Node            node_domain                      external_domain
%%  Call            uuid@node_domain                 uuid-node_domain@external_domain
%%  Call Resource   uuid@node_domain/resource        uuid-node_domain@external_domain/resource
%%  Mixer           name@node_domain                 name-node_domain@external_domain
%%  Mixer Resource  name@node_domain/resource        name-node_domain@external_domain/resource

%%  Node <-> Client comms
%%
%%  IQ mappings
%%   <iq type="set" id="12345" from="client JID"><dial...
%%            mapped to
%%   <iq type="set" id="12345@client JID" from="gateway@internal_domain...
%%

%% TODO don't allow nodes to act as clients
%% TODO don't allow clients to act as nodes

-export([
	start_link/2,
	start/2,
	stop/1,
	init/1,
	handle_call/3,
	handle_cast/2,
	handle_info/2,
	terminate/2,
	code_change/3,
	route_node/3,
	route_client/3
]).

-define(PROCNAME, ejabberd_mod_rayo_gateway).
-define(RAYO_NS, "urn:xmpp:rayo:1").
-define(PING_NS, "urn:xmpp:ping").

-record(rayo_config, {name, value}).
-record(rayo_clients, {jid, status}).
-record(rayo_nodes, {jid, status}).
-record(rayo_entities, {external_jid, internal_jid, dcp_jid}).
-record(rayo_requests, {id, original_request, from, to}).

start_link(Host, Opts) ->
	Proc = gen_mod:get_module_proc(Host, ?PROCNAME),
	gen_server:start_link({local, Proc}, ?MODULE, [Host, Opts], []).

start(Host, Opts) ->
	Proc = gen_mod:get_module_proc(Host, ?PROCNAME),
	ChildSpec = {Proc,
		{?MODULE, start_link, [Host, Opts]},
		temporary,
		1000,
		worker,
		[?MODULE]},
	supervisor:start_child(ejabberd_sup, ChildSpec).

stop(Host) ->
	Proc = gen_mod:get_module_proc(Host, ?PROCNAME),
	gen_server:call(Proc, stop),
	supervisor:terminate_child(ejabberd_sup, Proc),
	supervisor:delete_child(ejabberd_sup, Proc).

init([Host, Opts]) ->
	?DEBUG("MOD_RAYO_GATEWAY: Starting", []),

	mnesia:delete_table(rayo_clients),
	mnesia:create_table(rayo_clients, [{attributes, record_info(fields, rayo_clients)}]),
	mnesia:delete_table(rayo_nodes),
	mnesia:create_table(rayo_nodes, [{attributes, record_info(fields, rayo_nodes)}]),
	mnesia:delete_table(rayo_entities),
	mnesia:create_table(rayo_entities, [{attributes, record_info(fields, rayo_entities)}]),
	mnesia:delete_table(rayo_requests),
	mnesia:create_table(rayo_requests, [{atttributes, record_info(fields, rayo_requests)}]),
	mnesia:delete_table(rayo_config),
	mnesia:create_table(rayo_config, [{attributes, record_info(fields, rayo_config)}]),

	% create virtual domains
	InternalDomain = gen_mod:get_opt_host(Host, Opts, "rayo-int.@HOST@"),
	ExternalDomain = gen_mod:get_opt_host(Host, Opts, "rayo.@HOST@"),
	{ok, Hostname} = inet:gethostname(),
	InternalClient = "gateway@" ++ InternalDomain ++ "/" ++ Hostname ++ "-" ++ integer_to_list(random:uniform(65535)),
	?DEBUG("MOD_RAYO_GATEWAY: InternalDomain = ~p, ExternalDomain = ~p, InternalClient = ~p", [InternalDomain, ExternalDomain, InternalClient]),
	{A1,A2,A3} = now(),
	random:seed(A1, A2, A3),
	mnesia:transaction(
		fun() ->
			mnesia:write(#rayo_config{name = "internal_domain", value = InternalDomain}),
			mnesia:write(#rayo_config{name = "internal_client", value = InternalClient}),
			mnesia:write(#rayo_config{name = "external_domain", value = ExternalDomain})
		end
	),

	% set up routes to virtual domains
	ejabberd_router:register_route(InternalDomain, {apply, ?MODULE, route_node}),
	ejabberd_router:register_route(ExternalDomain, {apply, ?MODULE, route_client}),
	{ok, Host}.

handle_call(stop, _From, Host) ->
	{stop, normal, ok, Host}.

handle_cast(_Msg, Host) ->
	{noreply, Host}.

handle_info(_Msg, Host) ->
	{noreply, Host}.

terminate(_Reason, Host) ->
	ejabberd_router:unregister_route(Host),
	ok.

code_change(_OldVsn, Host, _Extra) ->
	{ok, Host}.

% Handle presence from client
route_client(From, _To, {xmlelement, "presence", _Attrs, _Els} = Presence) ->
	?DEBUG("MOD_RAYO_GATEWAY: got client presence ~n~p", [Presence]),
	case get_attribute_as_list(Presence, "type", "") of
		"" ->
			case get_element(Presence, "show") of
				undefined ->
					?DEBUG("MOD_RAYO_GATEWAY: ignoring empty presence", []);
				Show ->
					case get_cdata_as_list(Show) of
						"chat" ->
							register_client(From);
						"dnd" ->
							unregister_client(From);
						_ ->
							unregister_client(From)
					end
			end;
		"unavailable" ->
			unregister_client(From);
		"probe" ->
			%TODO maybe support
			ok;
		_ ->
			ok
	end,
	ok;

% Handle <message> from client
route_client(_From, _To, {xmlelement, "message", _Attrs, _Els} = Message) ->
	% ignore
	?DEBUG("MOD_RAYO_GATEWAY: got client message ~n~p", [Message]),
	ok;

% Handle <iq> from client to internal domain gateway
route_client(From, To = {jid, [], _Domain, [], [], _Domain, []}, {xmlelement, "iq", _Attrs, _Els} = IQ) ->
	?DEBUG("MOD_RAYO_GATEWAY: got client iq to gateway ~n~p", [IQ]),
	case get_attribute_as_list(IQ, "type", "") of
		"get" ->
			case get_element(IQ, ?PING_NS, "ping") of
				undefined ->
					route_error_reply(To, From, IQ, ?ERR_BAD_REQUEST);
				_ ->
					route_result_reply(To, From, IQ)
			end;
		"set" ->
			case get_element(IQ, ?RAYO_NS, "dial") of
				undefined->
					route_error_reply(To, From, IQ, ?ERR_BAD_REQUEST);
				_ ->
					route_dial_call(To, From, IQ)
			end;
		"" ->
			route_error_reply(To, From, IQ, ?ERR_BAD_REQUEST)
	end;

% Handle <iq> from client to internal domain resource
route_client(From, To, {xmlelement, "iq", _Attrs, _Els} = IQ) ->
	?DEBUG("MOD_RAYO_GATEWAY: got client iq ~n~p", [IQ]),
	case is_entity_dcp(From, To) of
		{true, _} ->
			route_rayo_command(From, To, IQ);
		{false, _} ->
			route_error_reply(To, From, IQ, ?ERR_CONFLICT);
		_ ->
			route_error_reply(To, From, IQ, ?ERR_BAD_REQUEST)
	end,
	ok.

% Handle <presence> from node to internal domain
route_node(From, {jid, [], _Domain, [], [], _Domain, []}, {xmlelement, "presence", _Attrs, _Els} = Presence) ->
	?DEBUG("MOD_RAYO_GATEWAY: got node presence to internal domain ~n~p", [Presence]),
	case get_attribute_as_list(Presence, "type", "") of
		"" ->
			case get_element(Presence, "show") of
				undefined ->
					?DEBUG("MOD_RAYO_GATEWAY: ignoring empty presence", []);
				Show ->
					case get_cdata_as_list(Show) of
						"chat" ->
							register_node(From);
						"dnd" ->
							unregister_node(From);
						"" ->
							unregister_node(From)
					end
			end;
		"unavailable" ->
			%TODO treat differently?
			unregister_node(From);
		"probe" ->
			%TODO maybe support...
			ok
	end,
	ok;

% Handle <presence> from node
route_node(From, To, {xmlelement, "presence", _Attrs, _Els} = Presence) ->
	?DEBUG("MOD_RAYO_GATEWAY: got node presence to internal domain ~n~p", [Presence]),
	case get_attribute_as_list(Presence, "type", "") of
		"" ->
			case get_element(Presence, ?RAYO_NS, "offer") of
				undefined ->
					ok;
				_ ->
					route_offer_call(From, To, Presence)
			end;
		_ ->
			ok
	end;

% Handle <message> from node
route_node(_From, _To, {xmlelement, "message", _Attrs, _Els} = Message) ->
	?DEBUG("MOD_RAYO_GATEWAY: got node message ~n~p", [Message]),
	% ignore
	ok;

% Handle <iq> from node.  Only allow ping, send error for all other requests.
route_node(From, {jid, [], _Domain, [], [], _Domain, []} = To, {xmlelement, "iq", _Attrs, _Els} = IQ) ->
	?DEBUG("MOD_RAYO_GATEWAY: got node iq ~n~p", [IQ]),
	case get_attribute_as_list(IQ, "type", "") of
		"get" ->
			case get_element(IQ, ?PING_NS, "ping") of
				undefined ->
					route_error_reply(To, From, IQ, ?ERR_BAD_REQUEST);
				_ ->
					route_result_reply(To, From, IQ)
			end;
		"" ->
			route_error_reply(To, From, IQ, ?ERR_BAD_REQUEST)
	end,
	ok;

% Handle <iq> from node to entity.  Only allow request replies.
route_node(From, To, {xmlelement, "iq", _Attrs, _Els} = IQ) ->
	?DEBUG("MOD_RAYO_GATEWAY: got node iq ~n~p", [IQ]),
	route_rayo_command_reply(From, To, IQ).

register_node(JID) ->
	Write = fun() ->
		mnesia:write(#rayo_nodes{jid = JID, status = "online" })
	end,
	Result = mnesia:transaction(Write),
	Size = num_nodes(),
	?DEBUG("MOD_RAYO_GATEWAY: register node: ~p, result = ~p, ~p nodes total", [jlib:jid_to_string(JID), Result, Size]),
	case num_clients() >= 1 of
		true ->
			ejabberd_router:route(internal_client(), JID, online_presence());
		_ ->
			ok
	end,
	ok.

% TODO call this when s2s connection is dropped?
unregister_node(JID) ->
	Delete = fun() ->
		mnesia:delete({rayo_nodes, JID})
	end,
	Result = mnesia:transaction(Delete),
	Size = mnesia:table_info(rayo_nodes, size),
	?DEBUG("MOD_RAYO_GATEWAY: unregister node: ~p, result = ~p, ~p nodes total", [jlib:jid_to_string(JID), Result, Size]),
	ok.

% Add client
register_client(JID) ->
	Write = fun() ->
		mnesia:write(#rayo_clients{jid = JID, status = "online" })
	end,
	Result = mnesia:transaction(Write),
	Size = num_clients(),
	?DEBUG("MOD_RAYO_GATEWAY: register client: ~p, result = ~p, ~p clients total", [jlib:jid_to_string(JID), Result, Size]),
	case Size of
		1 ->
			route_to_list(internal_client(), all_nodes(), online_presence());
		_ ->
			ok
	end,
	ok.

% Remove client
unregister_client(JID) ->
	Delete = fun() ->
		mnesia:delete({rayo_clients, JID})
	end,
	Result = mnesia:transaction(Delete),
	Size = num_clients(),
	?DEBUG("MOD_RAYO_GATEWAY: unregister client: ~p, result = ~p, ~p clients total", [jlib:jid_to_string(JID), Result, Size]),
	case Size of
		0 ->
			route_to_list(internal_client(), all_nodes(), offline_presence());
		_->
			ok
	end,
	ok.

% map jid to proxy domain
% user@user_domain/resource -> user_domain|user@domain/resource
map_jid(Jid, Domain) ->
	OrigUser = exmpp_jid:node_as_list(Jid),
	OrigResource = exmpp_jid:resource_as_list(Jid),
	OrigDomain = exmpp_jid:domain_as_list(Jid),
	exmpp_jid:make(OrigDomain ++ "|" ++ OrigUser, exmpp_jid:domain_as_list(Domain), OrigResource).

% unmap jid from proxy domain
% user_domain|user@domain/resource -> user@user_domain/resource
unmap_jid(Jid) ->
	ExtUser = exmpp_jid:node_as_list(Jid),
	{OrigDomain, OrigUser} = case ExtUser of
		[] ->
			{[], []};
		_ ->
			case string:chr(ExtUser, $|) of
				0 ->
					{[], []};
				Index ->
					{string:substr(ExtUser, 1, Index - 1), string:substr(ExtUser, Index + 1)}
			end
	end,
	OrigResource = exmpp_jid:resource_as_list(Jid),
	exmpp_jid:make(OrigUser, OrigDomain, OrigResource).

% Take control of entity
% Return {true, internal entity JID} if successful
set_entity_dcp(PCPJID, EntityJID) ->
	SetDCP = fun() ->
		case mnesia:wread(rayo_entities, EntityJID) of
			[{EntityJID, InternalJID, none}] ->
				% take control
				case mnesia:write(#rayo_entities{external_jid = EntityJID, internal_jid = InternalJID, dcp_jid = PCPJID}) of
					ok ->
						{true, InternalJID};
					Else ->
						{error, Else}
				end;
			_ ->
				{false, []}
		end
	end,
	{_, Result} = mnesia:transaction(SetDCP),
	Result.

% Check if PCP has control of entity
% Return {true, internal entity JID} if true
is_entity_dcp(PCPJID, EntityJID) ->
	% quick check first
	case mnesia:dirty_read(rayo_entities, EntityJID) of
		[{EntityJID, _, none}] ->
			set_entity_dcp(PCPJID, EntityJID);
		[{EntityJID, InternalJID, PCPJID}] ->
			{true, InternalJID};
		[{EntityJID, InternalJID, _}] ->
			{false, InternalJID}
	end.

% Forward offer to all clients
route_offer_call(From, _To, Offer) ->
	% Any clients available?
	case num_clients() > 0 of
		true ->
			% Remember call...
			MappedFrom = map_jid(From, external_node()),
			Call = fun() ->
				mnesia:write(#rayo_entities{external_jid = MappedFrom, internal_jid = From, dcp_jid = none})
			end,
			mnesia:transaction(Call),
			% Forward to all clients
			route_to_list(MappedFrom, all_clients(), Offer);
		_ ->
			% TODO reject ??
			ok
	end,
	ok.

% Forward dial to node
route_dial_call(From, To, Dial) ->
	% any nodes available?
	case num_nodes() > 0 of
		true ->
			% TODO forward to server
			route_error_reply(To, From, Dial, ?ERR_RESOURCE_CONSTRAINT);
		_ ->
			route_error_reply(To, From, Dial, ?ERR_RESOURCE_CONSTRAINT)
	end.

% route rayo IQ to server entity
route_rayo_command(_From, _To, _CMD) ->
	% TODO
	ok.

% route rayo IQ reply from server entity
route_rayo_command_reply(_From, _To, CMD) ->
	case get_attribute_as_list(CMD, "type", "") of
		"result" ->
			case get_element_attribute_as_list(CMD, ?RAYO_NS, "ref", "uri", undefined) of
				undefined ->
					?DEBUG("MOD_RAYO_GATEWAY: ignoring malformed rayo command result (missing <ref uri>)", []);
				_URI ->
					% TODO
					ok
			end;
		"error" ->
			% TODO forward error to client
			ok;
		_ ->
			ok
	end,
	ok.

config_value(Name) ->
	case catch mnesia:dirty_read(rayo_config, Name) of
		[{rayo_config, Name, Value}] ->
			Value;
		_ ->
			""
	end.

internal_client() ->
	jlib:string_to_jid(config_value("internal_client")).

external_node() ->
	jlib:string_to_jid(config_value("external_domain")).

num_clients() ->
	mnesia:table_info(rayo_clients, size).

all_clients() ->
	case mnesia:transaction(fun() -> mnesia:all_keys(rayo_clients) end) of
		{atomic, Keys} ->
			Keys;
		_ ->
			[]
	end.

num_nodes() ->
	mnesia:table_info(rayo_nodes, size).

all_nodes() ->
	case mnesia:transaction(fun() -> mnesia:all_keys(rayo_nodes) end) of
		{atomic, Keys} ->
			Keys;
		_ ->
			[]
	end.

presence(Status) ->
	{xmlelement, "presence", [],
		[{xmlelement, "show", [], [{xmlcdata, Status}]}]}.

online_presence() ->
	presence(<<"chat">>).

offline_presence() ->
	presence(<<"dnd">>).


route_to_list(From, ToList, Stanza) ->
	lists:map(fun(To) -> ejabberd_router:route(From, To, Stanza) end, ToList),
	ok.

route_error_reply(From, To, IQ, Reason) ->
	ejabberd_router:route(From, To, jlib:make_error_reply(IQ, Reason)).

route_result_reply(From, To, IQ) ->
	ejabberd_router:route(From, To, jlib:make_result_iq_reply(IQ)).

% XML parsing helpers

get_element(Element, Name) ->
	case xml:get_subtag(Element, Name) of
		false ->
			undefined;
		Subtag ->
			Subtag
	end.

get_element(Element, NS, Name) ->
	case get_element(Element, Name) of
		undefined ->
			undefined;
		Subtag ->
			case get_attribute_as_list(Subtag, "xmlns", "") of
				"" ->
					undefined;
				NS ->
					Subtag
			end
	end.

get_cdata_as_list(undefined) ->
	"";

get_cdata_as_list(Element) ->
	xml:get_tag_cdata(Element).

get_element_cdata_as_list(Element, Name) ->
	get_cdata_as_list(get_element(Element, Name)).

get_element_cdata_as_list(Element, NS, Name) ->
	get_cdata_as_list(get_element(Element, NS, Name)).

get_element_attribute_as_list(Element, Name, AttrName, Default) ->
	get_attribute_as_list(get_element(Element, Name), AttrName, Default).

get_element_attribute_as_list(Element, NS, Name, AttrName, Default) ->
	get_attribute_as_list(get_element(Element, NS, Name), AttrName, Default).

get_attribute_as_list(undefined, _Name, _Default) ->
	undefined;

get_attribute_as_list(Element, Name, Default) ->
	case xml:get_tag_attr_s(Name, Element) of
		"" ->
			Default;
		Attr ->
			Attr
	end.

