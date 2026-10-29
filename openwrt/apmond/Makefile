#
# Copyright (C) 2026 Rob White <rob@blue-wave.net>
#
# This is free software, licensed under the GNU General Public License v2.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=apmond
PKG_VERSION:=2.0.0_beta
PKG_RELEASE:=13

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

# Build identity: the commit comes from PKG_SOURCE_VERSION when set, else from .build_commit
# in the source (written by the release/build script), else "unknown" (see CMakeLists.txt).
APMOND_BUILD_COMMIT:=$(if $(PKG_SOURCE_VERSION),$(shell echo $(PKG_SOURCE_VERSION) | cut -c1-7))

CMAKE_OPTIONS += -DBUILD_DAEMON=ON -DBUILD_TESTS=OFF -DCRYPTO_BACKEND=mbedtls
CMAKE_OPTIONS += -DAPMOND_PACKAGE_VERSION=$(PKG_VERSION)-r$(PKG_RELEASE)
CMAKE_OPTIONS += -DAPMOND_BUILD_COMMIT=$(APMOND_BUILD_COMMIT)

define Package/apmond/install
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/apmond $(1)/usr/sbin/apmond
	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_CONF) ./files/apmond.config $(1)/etc/config/apmond
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/apmond.init $(1)/etc/init.d/apmond
endef

define Package/apmond/postinst
#!/bin/sh
# Appended after default_postinst, which has already run "/etc/init.d/apmond start".
# On an upgrade procd ignores that start (same command line), so the old code keeps running: restart it.
# Fresh install: PKG_UPGRADE is unset, default_postinst started it once. Image build: IPKG_INSTROOT is set.
if [ -z "$${IPKG_INSTROOT}" ] && [ "$${PKG_UPGRADE}" = "1" ] && /etc/init.d/apmond running; then
	/etc/init.d/apmond restart
fi
endef

$(eval $(call BuildPackage,apmond))
