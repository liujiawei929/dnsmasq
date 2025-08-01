# OpenWrt Package Makefile for Site Filter
# 站点过滤器 OpenWrt 包 Makefile

include $(TOPDIR)/rules.mk

PKG_NAME:=site-filter
PKG_VERSION:=1.0.0
PKG_RELEASE:=1

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)
PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
PKG_SOURCE_URL:=https://github.com/your-repo/site-filter/releases/download/v$(PKG_VERSION)/
PKG_HASH:=skip

PKG_MAINTAINER:=Your Name <your.email@example.com>
PKG_LICENSE:=GPL-2.0
PKG_LICENSE_FILES:=COPYING

PKG_BUILD_PARALLEL:=1
PKG_USE_MIPS16:=0

include $(INCLUDE_DIR)/package.mk

define Package/site-filter
    SECTION:=net
    CATEGORY:=Network
    SUBMENU:=Web Servers/Proxies
    TITLE:=DNS-based Site Filter
    DEPENDS:=+libc
    URL:=https://github.com/your-repo/site-filter
endef

define Package/site-filter/description
    A lightweight DNS-based site filtering solution for OpenWrt.
    Similar to dnsmasq's site filtering functionality but as a
    standalone service. Supports domain blocking, allowing, and
    redirection based on configurable rules.
    
    Features:
    - DNS query interception and filtering
    - Domain blacklist/whitelist support
    - Domain redirection to custom IPs
    - Wildcard domain matching
    - Real-time configuration reload
    - Detailed logging and statistics
    - UCI configuration integration
    - Web management interface
endef

define Package/site-filter/conffiles
/etc/site_filter.conf
/etc/config/site_filter
endef

TARGET_CFLAGS += $(FPIC) -std=gnu99
TARGET_LDFLAGS += -Wl,-rpath-link=$(STAGING_DIR)/usr/lib

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
	$(CP) ./Makefile.openwrt $(PKG_BUILD_DIR)/Makefile
endef

define Build/Compile
	$(MAKE) -C $(PKG_BUILD_DIR) \
		CC="$(TARGET_CC)" \
		CFLAGS="$(TARGET_CFLAGS)" \
		LDFLAGS="$(TARGET_LDFLAGS)" \
		all
endef

define Package/site-filter/install
	# 安装可执行文件
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/site_filter $(1)/usr/sbin/
	
	# 安装配置文件
	$(INSTALL_DIR) $(1)/etc
	$(INSTALL_CONF) ./site_filter.conf $(1)/etc/
	
	# 安装UCI配置文件
	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_CONF) ./config/site_filter $(1)/etc/config/
	
	# 安装初始化脚本
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./init.d/site_filter $(1)/etc/init.d/
	
	# 安装hotplug脚本
	$(INSTALL_DIR) $(1)/etc/hotplug.d/iface
	$(INSTALL_BIN) ./hotplug.d/99-site-filter $(1)/etc/hotplug.d/iface/
	
	# 创建日志目录
	$(INSTALL_DIR) $(1)/var/log
	
	# 创建运行时目录
	$(INSTALL_DIR) $(1)/var/run
endef

define Package/site-filter/postinst
#!/bin/sh
[ -n "$${IPKG_INSTROOT}" ] || {
	# 启用服务
	/etc/init.d/site_filter enable
	
	# 创建默认UCI配置（如果不存在）
	if ! uci -q get site_filter.general >/dev/null; then
		uci set site_filter.general=site_filter
		uci set site_filter.general.enabled='1'
		uci set site_filter.general.dns_port='53'
		uci set site_filter.general.block_ip='0.0.0.0'
		uci set site_filter.general.log_level='6'
		uci commit site_filter
	fi
	
	echo "Site Filter installed successfully!"
	echo "Configure via: /etc/config/site_filter or /etc/site_filter.conf"
	echo "Start service: /etc/init.d/site_filter start"
}
exit 0
endef

define Package/site-filter/prerm
#!/bin/sh
[ -n "$${IPKG_INSTROOT}" ] || {
	# 停止并禁用服务
	/etc/init.d/site_filter stop
	/etc/init.d/site_filter disable
}
exit 0
endef

define Package/site-filter/postrm
#!/bin/sh
[ -n "$${IPKG_INSTROOT}" ] || {
	# 清理运行时文件
	rm -f /var/run/site_filter.pid
	rm -f /var/log/site_filter.log
	
	# 可选：删除配置文件（询问用户）
	echo "Configuration files preserved in /etc/"
	echo "Remove manually if needed: /etc/site_filter.conf /etc/config/site_filter"
}
exit 0
endef

$(eval $(call BuildPackage,site-filter))