all:
	@cd sma && make  all 
	@cd gen && make  all 
install:
	test -e $(NCA_TGTDIR)/install/bin || mkdir -p $(NCA_TGTDIR)/install/bin
	@cd sma && make install
	@cd gen && make install
clean:
	@cd sma && make clean
	@cd gen && make clean
