.PHONY: install uninstall test

# First run: create reaparr.conf from the example and stop so it can be edited.
# Later runs: regenerate the plist and (re)load the job (reload.sh boots out
# any running instance first).
install:
	@if [ ! -f reaparr.conf ]; then \
		cp reaparr.conf.example reaparr.conf; \
		echo "Created reaparr.conf; edit it, then run 'make install' again."; \
	else \
		./reload.sh; \
	fi

# Stop the job and remove its plist so it doesn't start again at login.
uninstall:
	-launchctl bootout gui/$$(id -u)/io.github.stephan5.reaparr
	rm -f $$HOME/Library/LaunchAgents/io.github.stephan5.reaparr.plist

test:
	python3 -m unittest discover -s tests
