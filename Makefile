all: deps
	rebar compile

deps:
	rebar get-deps

pkg:	all
	tetrapak pkg:ipkg

clean:
	rebar clean

clean-all: clean
	rm -rf deps
