SHELL := /usr/bin/env bash

.PHONY: install audit tui test clean

install:
	python3 -m pip install -r requirements.txt

audit:
	bash audit.sh

tui:
	python3 tui/dashboard.py

test:
	python3 -m unittest -v tests/test_parsers.py

clean:
	rm -f tmp/*.txt tmp/*.json output/reports/audit-*.json
