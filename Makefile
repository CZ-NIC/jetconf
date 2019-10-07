PROJECT = jetconf
VERSION = 0.3.6
.PHONY = tags deps install-deps test

tags:
	find $(PROJECT) -name "*.py" | etags -

deps:
	mv requirements.txt requirements.txt.old
	pip3 freeze > requirements.txt

install-deps:
	pip3 install -r requirements.txt

test:
	@py.test tests

release:
	git tag -a -m "Jetconf release $(VERSION)" $(VERSION)
	rm -f dist/*
	python3 setup.py sdist
	python3 setup.py bdist_wheel
	twine check dist/*

upload:
	twine upload dist/*
