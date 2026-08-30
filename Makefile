PYTHON ?= python3

.PHONY: verify verify-netns schedules-check field-population

verify:
	$(PYTHON) -m compileall -q src analysis scripts
	$(PYTHON) -m pytest -q -m "not netns"
	$(PYTHON) -m pip check

verify-netns:
	@test "$$(id -u)" -eq 0 || { echo "verify-netns requires root" >&2; exit 2; }
	$(PYTHON) -m pytest -q -m netns

schedules-check:
	$(PYTHON) scripts/freeze_schedules.py --check

field-population:
	$(PYTHON) scripts/freeze_field_population.py \
		--design experiments/field-design.yaml \
		--write-dir build/field-population
