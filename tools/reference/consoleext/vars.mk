# Read by scripts/build-reference.sh as a second makefile beside Ghidra's own
# (`make -f Makefile -f vars.mk bk-vars ...`): prints the variables the
# extension's compile and link lines are built from, evaluated by make with
# the same overrides as every other target, so the consoles with the
# extension are linked from exactly the objects of decomp_opt / decomp_dbg.
# Nothing here builds anything.
.PHONY: bk-vars
bk-vars:
	@echo 'BK_CXX=$(CXX)'
	@echo 'BK_ARCH_TYPE=$(ARCH_TYPE)'
	@echo 'BK_OPT_CXXFLAGS=$(OPT_CXXFLAGS)'
	@echo 'BK_DBG_CXXFLAGS=$(DBG_CXXFLAGS)'
	@echo 'BK_ADDITIONAL_FLAGS=$(ADDITIONAL_FLAGS)'
	@echo 'BK_COMMANDLINE_OPT=$(COMMANDLINE_OPT)'
	@echo 'BK_COMMANDLINE_DEBUG=$(COMMANDLINE_DEBUG)'
	@echo 'BK_OPT_OBJS=$(COMMANDLINE_OPT_OBJS)'
	@echo 'BK_DBG_OBJS=$(COMMANDLINE_DBG_OBJS)'
	@echo 'BK_BFDLIB=$(BFDLIB)'
	@echo 'BK_LNK=$(LNK)'
