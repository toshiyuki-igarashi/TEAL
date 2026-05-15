obj-$(CONFIG_SECURITY_TEAL) := teal.o
teal-y := teal_lsm.o teal_rs.o

# カーネルのバージョンが 6.8 なら、Rustコンパイラにフラグを渡す
ifeq ($(VERSION).$(PATCHLEVEL), 6.8)
    rustflags-y += --cfg is_v6_8
endif
