all:
	ocamldoc -html -css-style mystyle.css \
        -I ../cryptokit/src ../cryptokit/src/cryptokit.mli

publish:
	git push origin gh-pages
