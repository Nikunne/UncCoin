PYTHON := python3

.PHONY: 9000 9001

9000:
	$(PYTHON) -m network.p2p_server --port 9000

9001:
	$(PYTHON) -m network.p2p_server --port 9001 --peer 127.0.0.1:9000
