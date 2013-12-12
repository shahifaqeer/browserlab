#
# Copyright (C) 2007-2010 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=pathload
PKG_VERSION:=2013-12-11

PKG_SOURCE_PROTO:=git
PKG_SOURCE_URL:=git://github.com/apietila/pathload.git
PKG_SOURCE:=$(PKG_NAME).tar.gz
PKG_SOURCE_VERSION:=HEAD
PKG_SOURCE_SUBDIR:=$(PKG_NAME)

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)

include $(INCLUDE_DIR)/package.mk

define Package/pathload
	SECTION:=net
	CATEGORY:=Network
	TITLE:=Bandwidth estimation tool based on one-way-delay trends under load.
	URL:=http://www.measurementlab.net/tools/pathload2
endef

define Package/shaperprobe/description
	Pathload bandwidth estimation tool server and client.
endef

define Build/Compile
	$(MAKE) CC="$(TARGET_CC)" CFLAGS="$(TARGET_CFLAGS)" LDFLAGS="-lm" -C $(PKG_BUILD_DIR)/pathload2-linux-client clean pathload2
	$(MAKE) CC="$(TARGET_CC)" CFLAGS="$(TARGET_CFLAGS)" LDFLAGS="-lm" -C $(PKG_BUILD_DIR)/pathload2-linux-server clean pathload_rcv
endef

define Package/pathload/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/pathload2-linux-client/pathload2 $(1)/usr/bin/pathload
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/pathload2-linux-server/pathload_rcv $(1)/usr/bin/pathloadserver
endef

$(eval $(call BuildPackage,pathload))