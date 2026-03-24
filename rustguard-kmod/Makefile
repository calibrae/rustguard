KDIR ?= /lib/modules/$(shell uname -r)/build

obj-m := rustguard.o

# Cross-platform sed -i (macOS needs '', GNU doesn't)
SED_I := $(shell if sed --version 2>/dev/null | grep -q GNU; then echo 'sed -i'; else echo 'sed -i ""'; fi)

# Stage shared protocol code from the workspace crates into the kmod source tree.
# Kbuild can't resolve Cargo crate deps, so we copy the sources and rewrite imports.
.PHONY: stage modules clean

stage:
	@echo "  STAGE   shared crate sources"
	@mkdir -p src/gen/crypto src/gen/protocol
	@cp ../rustguard-crypto/src/aead.rs    src/gen/crypto/
	@cp ../rustguard-crypto/src/blake2s.rs src/gen/crypto/
	@cp ../rustguard-crypto/src/x25519.rs  src/gen/crypto/
	@cp ../rustguard-crypto/src/tai64n.rs  src/gen/crypto/
	@cp ../rustguard-crypto/src/lib.rs     src/gen/crypto/mod.rs
	@cp ../rustguard-core/src/handshake.rs src/gen/protocol/
	@cp ../rustguard-core/src/session.rs   src/gen/protocol/
	@cp ../rustguard-core/src/replay.rs    src/gen/protocol/
	@cp ../rustguard-core/src/timers.rs    src/gen/protocol/
	@cp ../rustguard-core/src/cookie.rs    src/gen/protocol/
	@cp ../rustguard-core/src/messages.rs  src/gen/protocol/
	@cp ../rustguard-core/src/lib.rs       src/gen/protocol/mod.rs
	@# Rewrite external crate references to local module paths
	@find src/gen/protocol/ -name '*.rs' -exec $(SED_I) 's/use rustguard_crypto::/use crate::crypto::/g' {} +
	@find src/gen/protocol/ -name '*.rs' -exec $(SED_I) 's/rustguard_crypto as crypto/crate::crypto as crypto/g' {} +
	@find src/gen/protocol/ -name '*.rs' -exec $(SED_I) 's/pub use rustguard_crypto as crypto/pub use crate::crypto as crypto/g' {} +
	@# Strip std/test-only code for kernel build
	@find src/gen/ -name '*.rs' -exec $(SED_I) '/#\[cfg(test)\]/,$$d' {} +
	@find src/gen/ -name '*.rs' -exec $(SED_I) 's/#!\[cfg_attr(not(feature = "std"), no_std)\]/#![no_std]/' {} +
	@echo "  OK"

modules: stage
	$(MAKE) -C $(KDIR) M=$(PWD) LLVM=1 modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
	rm -rf src/gen
