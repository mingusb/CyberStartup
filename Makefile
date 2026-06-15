export COLORTERM=truecolor
export FORCE_COLOR=1

ifneq ($(CYBERSTARTUP_NO_SUDO),)
SUDO_CMD =
SUDO_PASSWORD_PIPE =
else ifneq ($(CYBERSTARTUP_BUILD_STEP),)
SUDO_CMD =
SUDO_PASSWORD_PIPE =
else ifneq ($(CYBERSTARTUP_MOCK_TELEMETRY),)
SUDO_CMD =
SUDO_PASSWORD_PIPE =
else
SUDO_CMD = sudo -S
SUDO_PASSWORD_PIPE = echo b |
endif



# Component paths
PYTHON_SRC = src/cyberstartup
EBPF_SRC = src/ebpf
P4_SRC = src/p4
SGX_SRC = src/sgx

# Tooling
CC = clang
P4C = p4c
PYTEST = venv/bin/python3 -m pytest

.PHONY: all phase1 phase2 phase3 loop clean ebpf sgx p4

all: phase3

# --- Component Builds ---

ebpf:
	@echo "[-] Compiling eBPF probes..."
	$(CC) -O2 -target bpf -I/usr/include/x86_64-linux-gnu -c $(EBPF_SRC)/tc_shaper.c -o $(EBPF_SRC)/tc_shaper.o
	$(CC) -O2 -target bpf -I/usr/include/x86_64-linux-gnu -c $(EBPF_SRC)/pmu_monitor.c -o $(EBPF_SRC)/pmu_monitor.o

sgx:
	@echo "[-] Compiling SGX Enclave..."
	$(CC) -shared -fPIC -DUSE_REAL_SGX=1 -I$(SGX_SRC)/include -o $(SGX_SRC)/sgx_enclave.so $(SGX_SRC)/sgx_enclave.c -lcrypto

p4:
	@echo "[-] Compiling P4 logic..."
	mkdir -p $(P4_SRC)/out
	# Prefer local p4c if available, fallback to docker
	$(P4C) --target bmv2 --arch v1model $(P4_SRC)/containment_router.p4 -o $(P4_SRC)/out/containment_router.json || \
	docker run --rm -v $$(pwd):/workdir -w /workdir opennetworking/p4c:latest p4c-bm2-ss --target bmv2 --arch v1model $(P4_SRC)/containment_router.p4 -o $(P4_SRC)/out/containment_router.json

# --- Audit Pipeline Deprecated ---
# The teamwork swarm now natively spawns subagents via invoke_subagent for these personas.

phase3: ebpf sgx
	@echo "[-] Phase 3: Finalizing Project (Tests, Compilation, Packaging)..."
	ln -sf venv_test venv && \
	for f in tests/test_*.py; do $(SUDO_PASSWORD_PIPE) $(SUDO_CMD) env PYTHONPATH=src $(PYTEST) $$f -q || exit 1; done
	cp website/dashboard.json docs/dashboard.json || true
	$(SUDO_PASSWORD_PIPE) $(SUDO_CMD) chown -R $$(id -un):$$(id -gn) docs/
	cd docs/patent && $(MAKE) clean > /dev/null 2>&1 && $(MAKE) > /dev/null 2>&1
	cd docs/whitepaper && rm -f pitch_deck.pdf && pandoc cyberstartup_whitepaper.md -o cyberstartup_whitepaper.pdf -V geometry:margin=1in && ../../venv/bin/python ../../scripts/gen_pitch_deck.py
	tar --exclude='./venv' --exclude='./venv_test' --exclude='./.hypothesis' --exclude='./test_env' --exclude='./venv2' --exclude='./pip-target' --exclude='./.git' --exclude='*/__pycache__' --exclude='./.pytest_cache' --exclude='./cyber_feed_patent_release.tar.gz' --exclude='./.agents' --exclude='./gh_2.50.0_linux_amd64' --exclude='./gh_2.50.0_linux_amd64.tar.gz' -czf cyber_feed_patent_release.tar.gz . || true
	@echo "[-] Archiving old reports for historical review..."
	@RUN_ID=$$(date +%Y%m%d_%H%M%S); \
	mkdir -p docs/audits/archive/$$RUN_ID; \
	mv docs/audits/remedied/*.md docs/audits/archive/$$RUN_ID/ 2>/dev/null || true; \
	mv docs/audits/active/gap_analysis_*.md docs/audits/archive/$$RUN_ID/ 2>/dev/null || true; \
	echo "[+] Archived reports to docs/audits/archive/$$RUN_ID"
	@echo "=========================================================="
	@echo " CYBERSTARTUP: Autonomous Improvement Loop Completed"
	@echo "=========================================================="



clean:
	rm -f $(EBPF_SRC)/*.o
	rm -f $(SGX_SRC)/*.so
	rm -rf $(P4_SRC)/out
	$(SUDO_PASSWORD_PIPE) $(SUDO_CMD) rm -rf venv
	rm -f cyber_feed_patent_release.tar.gz
	$(SUDO_PASSWORD_PIPE) $(SUDO_CMD) rm -f docs/whitepaper/*.pdf docs/patent/*.pdf docs/patent/*.aux docs/patent/*.log docs/patent/*.toc docs/patent/*.out 2>/dev/null || true
