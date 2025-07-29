# DNS Filter Module for OpenWrt
# Copyright (c) 2024

include $(TOPDIR)/rules.mk

PKG_NAME:=dns-filter
PKG_VERSION:=1.1
PKG_RELEASE:=1

PKG_MAINTAINER:=DNS Filter Team
PKG_LICENSE:=GPL-2.0

include $(INCLUDE_DIR)/package.mk
include $(INCLUDE_DIR)/kernel.mk

define Package/dns-filter
  SECTION:=net
  CATEGORY:=Network
  TITLE:=DNS Site Filtering Module with IPv6 support
  DESCRIPTION:=Kernel module for DNS site filtering that works regardless of user DNS settings, with IPv6 and whitelist support
  KCONFIG:=CONFIG_NETFILTER=y CONFIG_NETFILTER_NETLINK=y CONFIG_IP6_NF_IPTABLES=y
  DEPENDS:=+kmod-ipt-core +kmod-nf-conntrack +kmod-ip6tables
endef

define Package/dns-filter/description
  This package provides advanced DNS site filtering functionality at the kernel level
  using netfilter hooks. It can filter DNS requests even when users manually
  set DNS servers to 114.114.114.114, 8.8.8.8, or other public DNS services.
  
  Features:
  - IPv4 and IPv6 DNS filtering
  - Domain whitelist and blacklist support
  - Time-based filtering rules
  - Custom DNS response generation
  - High-performance red-black tree storage
  - Comprehensive statistics and logging
  - UCI integration for OpenWrt
endef

define Package/dns-filter/conffiles
/etc/config/dns-filter
/etc/dns-filter/blocked-domains.txt
/etc/dns-filter/whitelisted-domains.txt
endef

define Build/Configure
endef

define Build/Compile
	$(MAKE) -C "$(LINUX_DIR)" \
		CROSS_COMPILE="$(TARGET_CROSS)" \
		ARCH="$(LINUX_KARCH)" \
		SUBDIRS="$(PKG_BUILD_DIR)" \
		EXTRA_CFLAGS="$(BUILDFLAGS)" \
		modules
	$(TARGET_CC) $(TARGET_CFLAGS) $(TARGET_LDFLAGS) \
		-o $(PKG_BUILD_DIR)/dns-filter-ctl \
		$(PKG_BUILD_DIR)/dns_filter_ctl.c
endef

define Package/dns-filter/install
	$(INSTALL_DIR) $(1)/lib/modules/$(LINUX_VERSION)
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/dns_filter.ko $(1)/lib/modules/$(LINUX_VERSION)/
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/dns-filter-ctl $(1)/usr/sbin/
	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_DATA) ./files/dns-filter.config $(1)/etc/config/dns-filter
	$(INSTALL_DIR) $(1)/etc/dns-filter
	$(INSTALL_DATA) ./files/blocked-domains.txt $(1)/etc/dns-filter/
	$(INSTALL_DATA) ./files/whitelisted-domains.txt $(1)/etc/dns-filter/
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/dns-filter.init $(1)/etc/init.d/dns-filter
endef

$(eval $(call BuildPackage,dns-filter))