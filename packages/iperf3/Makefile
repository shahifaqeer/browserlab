#
# Copyright (C) 2007-2010 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=iperf3
PKG_VERSION:=2013-12-11

PKG_SOURCE_PROTO:=git
PKG_SOURCE_URL:=git://github.com/apietila/iperf.git
PKG_SOURCE:=$(PKG_NAME).tar.gz
PKG_SOURCE_VERSION:=HEAD
PKG_SOURCE_SUBDIR:=$(PKG_NAME)

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)

include $(INCLUDE_DIR)/package.mk

define Package/iperf3
	SECTION:=net
	CATEGORY:=Network
	TITLE:=Iperf3
	URL:=http://code.google.com/p/iperf
endef

define Package/iperf3/description
	UDP and TCP bandwidth measurement tool.
endef

define Package/iperf3/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/src/iperf3 $(1)/usr/bin/iperf3

$(eval $(call BuildPackage,iperf3))
