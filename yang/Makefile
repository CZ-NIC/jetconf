MODULES ?= $(wildcard *.yang)
.PHONY: all clean

all: model.tree

model.tree: hello.xml
	pyang -f tree -o $@ -L $<

hello.xml: $(MODULES)
	@echo '<hello xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">' > $@
	@echo '<capabilities>' >> $@
	@echo '<capability>urn:ietf:params:netconf:base:1.1</capability>' >> $@
	@for m in $(MODULES); do \
	  capa=$$(pyang -f capability --capability-entity $$m); \
	  if [ "$$capa" != "" ]; then \
	    echo "<capability>$$capa</capability>" >> $@; \
	  fi \
	done
	@echo '</capabilities>' >> $@
	@echo '</hello>' >> $@

clean:
	@rm hello.xml model.tree
