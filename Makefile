PROJECT = jetconf
YANGSON_URL = https://gitlab.labs.nic.cz/llhotka/yangson.git

tags:
	find $(PROJECT) -name "*.py" | etags -

deps:
	pip freeze > requirements.txt

install-deps:
	pip install -r requirements.txt

yangson:
	pip install --upgrade git+$(YANGSON_URL)
