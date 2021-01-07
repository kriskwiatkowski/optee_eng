# The UUID for the Trusted Application
BINARY=8aaaf200-2450-11e4-0060-0dc0ffee0000

CFG_TEE_TA_LOG_LEVEL = 4
CPPFLAGS += -O2 -DCFG_TEE_TA_LOG_LEVEL=$(CFG_TEE_TA_LOG_LEVEL)
TA_DEV_KIT_DIR=$(OPTEE_ROOT)/optee_os/out/arm/export-ta_arm64
TEEC_EXPORT=$(OPTEE_ROOT)/optee_client/public
HOST_CROSS_COMPILE=$(OPTEE_ROOT)/toolchains/aarch64/bin/aarch64-linux-gnu-
CROSS_COMPILE=${HOST_CROSS_COMPILE}

-include $(TA_DEV_KIT_DIR)/mk/ta_dev_kit.mk

ifeq ($(wildcard $(TA_DEV_KIT_DIR)/mk/ta_dev_kit.mk), )
clean:
	@echo 'Note: $$(TA_DEV_KIT_DIR)/mk/ta_dev_kit.mk not found, cannot clean TA'
	@echo 'Note: TA_DEV_KIT_DIR=$(TA_DEV_KIT_DIR)'
	rm -rf ${BINARY}.*
	rm -rf *.o
endif
