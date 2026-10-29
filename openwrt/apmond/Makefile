#
# Copyright (C) 2026 Rob White <rob@blue-wave.net>
#
# This is free software, licensed under the GNU General Public License v2.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=apmond
PKG_VERSION:=2.0.0_beta
PKG_RELEASE:=3

PKG_SOURCE:=apmon-$(PKG_VERSION).tar.gz
PKG_SOURCE_URL:=https://codeload.github.com/openNDS/apmon/tar.gz/v$(PKG_VERSION)?
PKG_HASH:=skip
PKG_BUILD_DIR:=$(BUILD_DIR)/apmon-$(PKG_VERSION)

PKG_MAINTAINER:=Rob White <rob@blue-wave.net>
PKG_LICENSE:=GPL-2.0-only
PKG_LICENSE_FILES:=LICENSE

include $(INCLUDE_DIR)/package.mk
include $(INCLUDE_DIR)/cmake.mk

define Package/apmond
  SECTION:=net
  CATEGORY:=Network
  TITLE:=Access point monitoring daemon (protocol 2, C)
  URL:=https://github.com/openNDS/apmon
  DEPENDS:=+libubox +libubus +libuci +libblobmsg-json +libmbedtls +libmicrohttpd-no-ssl +rpcd-mod-iwinfo
endef

define Package/apmond/description
  apmond collects access point, Wi-Fi client and wired client data from every
  node of a network and reports it, encrypted with AES-256-GCM, to a collector
  node, where it is available on ubus (ubus call apmond nodes / clients).
  Version 2 is a rewrite in C with a new protocol; all nodes must run 2.x.
endef

define Package/apmond/conffiles
/etc/config/apmond
endef

CMAKE_OPTIONS += -DBUILD_DAEMON=ON -DBUILD_TESTS=OFF -DCRYPTO_BACKEND=mbedtls

define Package/apmond/install
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/apmond $(1)/usr/sbin/apmond
	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_CONF) ./files/apmond.config $(1)/etc/config/apmond
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/apmond.init $(1)/etc/init.d/apmond
endef

$(eval $(call BuildPackage,apmond))
