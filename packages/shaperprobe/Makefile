#
# Copyright (C) 2007-2010 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=shaperprobe
PKG_VERSION:=2013-12-11

PKG_SOURCE_PROTO:=git
PKG_SOURCE_URL:=git://github.com:apietila/shaperprobe.git
PKG_SOURCE:=$(PKG_NAME).tar.gz
PKG_SOURCE_VERSION:=HEAD
PKG_SOURCE_SUBDIR:=$(PKG_NAME)

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)

include $(INCLUDE_DIR)/package.mk

define Package/shaperprobe
  SECTION:=net
  CATEGORY:=Network
  TITLE:=Bandwidth estimation tool
  URL:=http://www.measurementlab.net/tools/shaperprobe
endef

define Package/shaperprobe/description
  ShaperProbe based bandwidth estimation tool server and client.
endef

define Build/Compile
  $(MAKE) -C $(PKG_BUILD_DIR)/shaperprobe/linux
  $(MAKE) -C $(PKG_BUILD_DIR)/shaperprobeserver
endef

define Package/shaperprobe/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/shaperprobe/linux/prober $(1)/usr/bin/shaperprobe
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/shaperprobeserver/shaperprobeserver $(1)/usr/bin/shaperprobeserver
endef

$(eval $(call BuildPackage,shaperprobe))
