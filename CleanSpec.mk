$(call add-clean-step, rm -rf $(HOST_OUT)/obj/SHARED_LIBRARIES/libselinux_intermediates)
$(call add-clean-step, rm -rf $(HOST_OUT)/obj/lib/libselinux.so)
$(call add-clean-step, rm -rf $(HOST_OUT)/obj/STATIC_LIBRARIES/libselinux_intermediates)
$(call add-clean-step, rm -rf $(HOST_OUT)/obj/STATIC_LIBRARIES/libselinux_intermediates/libselinux.a)
$(call add-clean-step, rm -rf $(HOST_OUT)/lib64/libselinux.so)
$(call add-clean-step, rm -rf $(HOST_OUT)/obj/include/selinux)

