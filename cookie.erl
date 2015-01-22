-module(cookie).
-compile(export_all).

% auth(<<"tornado key here">>, <<"cookie value here">>).
auth(Key, Value)->
	[H1, H2, TS, K, V, S] = re:split(erlang:binary_to_list(Value),"\\|", [{return,list}]),
	Origin = lists:flatten([H1, "|", H2, "|", TS, "|", K, "|", V, "|"]),
	<<Mac:256/integer>> = crypto:hmac(sha256, Key, Origin),
	SOut = lists:flatten(io_lib:format("~64.16.0b", [Mac])),
	[_, Timestamp] = re:split(TS,":", [{return,list}]),
	[_, Ke] = re:split(K,":", [{return,list}]),
	[_, Va] = re:split(V,":", [{return,list}]),
	Val = 'base64':'decode_to_string'(Va),
	{ok, S =:= SOut, Timestamp, Ke, Val}.