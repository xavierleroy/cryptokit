all:
	ocamldoc -html -I ../cryptokit/src ../cryptokit/src/cryptokit.mli

publish:
	git push origin gh-pages
