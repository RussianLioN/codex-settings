.PHONY: contracts test-contracts tests docs compile quality

contracts test-contracts:
	uv run --locked python scripts/validate_contracts.py

tests:
	uv run --locked python -m unittest discover -s tests/smart_subagents -p 'test_*.py'

docs:
	uv run --locked python scripts/validate_docs_navigation.py

compile:
	uv run --locked python -m compileall -q scripts plugins/codex-smart-subagents/src tests/smart_subagents

quality: contracts docs tests compile
