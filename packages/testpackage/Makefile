#
# Copyright (C) 2006-2010 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.

include $(TOPDIR)/rules.mk

PKG_NAME:=testpackage
PKG_VERSION:=1.0
PKG_RELEASE:=1

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)

include $(INCLUDE_DIR)/package.mk

define Package/testpackage
  SECTION:=utils
  CATEGORY:=Utilities
  DEFAULT:=n
  TITLE:=Gateway luci RPC-JSON module for Fathom home network troubleshooting
  URL:=http://github.com/shahifaqeer/browserlab
endef

define Package/testpackage/description
  Allows Fathom browser side extension to remotely call
  procedures on bismark or openwrt gateway, such as pings,
  traceroute, iperf, shaperprobe etc. Fathom can also retreive
  information such as arp and conntrack using json-rpc.

  Needs luci json and rpc modules to work, and custom iperf code.
endef

define Build/Prepare
endef

define Build/Compile
endef

define Package/testpackage/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(CP) ./files/usr/bin/bismark-command $(1)/usr/bin
endef

define Package/testpackage/preinst
endef

define Package/testpackage/prerm
endef

define Package/testpackage/postinst
endef

$(eval $(call BuildPackage,testpackage))
