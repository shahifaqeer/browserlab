#
# Copyright (C) 2007-2010 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=udpprobe
PKG_VERSION:=2014-03-09

PKG_SOURCE_PROTO:=git
PKG_SOURCE_URL:=git://github.com/shahifaqeer/udpprobe.git
PKG_SOURCE:=$(PKG_NAME).tar.gz
PKG_SOURCE_VERSION:=HEAD
PKG_SOURCE_SUBDIR:=$(PKG_NAME)

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)

include $(INCLUDE_DIR)/package.mk

define Package/udpprobe
	SECTION:=net
	CATEGORY:=Network
	TITLE:=Bandwidth estimation tool
	URL:=http://www.measurementlab.net/tools/shaperprobe
endef

define Package/udpprobe/description
	ShaperProbe based bandwidth estimation tool server and client.
endef

define Build/Compile
	$(MAKE) CC="$(TARGET_CC)" CFLAGS="$(TARGET_CFLAGS) -c -fno-strict-aliasing -DOSX" LDFLAGS="-lm" -C $(PKG_BUILD_DIR)/shaperprobe/linux all
	$(MAKE) CC="$(TARGET_CC)" CFLAGS="$(TARGET_CFLAGS) -c -fno-strict-aliasing -DOSX" LDFLAGS="-lm" -C $(PKG_BUILD_DIR)/shaperprobeserver all
endef

define Package/udpprobe/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/shaperprobe/linux/udpprober $(1)/usr/bin/udpprober
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/shaperprobeserver/udpprobeserver $(1)/usr/bin/udpprobeserver
endef

$(eval $(call BuildPackage,udpprobe))
