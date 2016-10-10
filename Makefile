PROJECT = jetconf
.PHONY = tags deps install-deps

tags:
	find $(PROJECT) -name "*.py" | etags -

deps:
	pip freeze > requirements.txt

install-deps:
	pip install -r requirements.txt
