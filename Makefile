#
# Copyright (C) 2024 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=site-filter
PKG_VERSION:=1.0.0
PKG_RELEASE:=1

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)
PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
PKG_SOURCE_SUBDIR:=$(PKG_NAME)-$(PKG_VERSION)
PKG_SOURCE_VERSION:=HEAD
PKG_SOURCE_PROTO:=git
PKG_MIRROR_HASH:=skip

PKG_LICENSE:=GPL-2.0
PKG_LICENSE_FILES:=

PKG_MAINTAINER:=OpenWrt Developers <developers@openwrt.org>

include $(INCLUDE_DIR)/package.mk

define Package/site-filter
	SECTION:=net
	CATEGORY:=Network
	SUBMENU:=IP Addresses and Names
	TITLE:=Site filtering daemon
	URL:=
	DEPENDS:=+libc
endef

define Package/site-filter/description
	Site Filter is a lightweight DNS filtering daemon that blocks or redirects
	specific domains based on configuration rules. It provides functionality
	similar to dnsmasq's site filtering capabilities but as a standalone service.
	
	Features:
	- Block access to specific domains
	- Redirect domains to custom IP addresses
	- Support for wildcard domain matching
	- Configurable via simple text file
	- Daemon mode with PID file support
	- Signal-based configuration reloading
endef

define Package/site-filter/conffiles
/etc/config/site-filter
/etc/site_filter.conf
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./site_filter.c $(PKG_BUILD_DIR)/
endef

define Build/Compile
	$(TARGET_CC) $(TARGET_CFLAGS) $(TARGET_LDFLAGS) \
		-o $(PKG_BUILD_DIR)/site_filter $(PKG_BUILD_DIR)/site_filter.c
endef

define Package/site-filter/install
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/site_filter $(1)/usr/sbin/

	$(INSTALL_DIR) $(1)/etc
	$(INSTALL_CONF) ./site_filter.conf $(1)/etc/

	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_CONF) ./files/site-filter.config $(1)/etc/config/site-filter

	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/site-filter.init $(1)/etc/init.d/site-filter

	$(INSTALL_DIR) $(1)/etc/hotplug.d/iface
	$(INSTALL_DATA) ./files/20-site-filter $(1)/etc/hotplug.d/iface/
endef

define Package/site-filter/postinst
#!/bin/sh
if [ -z "$$IPKG_INSTROOT" ]; then
	echo "Enabling site-filter service..."
	/etc/init.d/site-filter enable
	echo "To start the service, run: /etc/init.d/site-filter start"
	echo "Configuration file: /etc/site_filter.conf"
fi
exit 0
endef

define Package/site-filter/prerm
#!/bin/sh
if [ -z "$$IPKG_INSTROOT" ]; then
	echo "Stopping and disabling site-filter service..."
	/etc/init.d/site-filter stop
	/etc/init.d/site-filter disable
fi
exit 0
endef

$(eval $(call BuildPackage,site-filter))
