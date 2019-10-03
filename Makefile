all:
	ocamldoc -html -css-style mystyle.css \
        -I ../src ../src/cryptokit.mli

publish:
	git push origin gh-pages
