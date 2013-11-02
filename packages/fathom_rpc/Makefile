#
# Copyright (C) 2006-2010 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.

include $(TOPDIR)/rules.mk

PKG_NAME:=fathom_rpc
PKG_VERSION:=1.0
PKG_RELEASE:=1

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)

include $(INCLUDE_DIR)/package.mk

define Package/fathom_rpc
  SECTION:=utils
  CATEGORY:=Utilities
  DEFAULT:=n
  TITLE:=Gateway luci RPC-JSON module for Fathom home network troubleshooting
  URL:=http://github.com/shahifaqeer/browserlab
  DEPENDS:=+luci-mod-rpc +luci-lib-json +avahi-daemon
endef

define Package/fathom_rpc/description
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

define Package/fathom_rpc/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(CP) ./files/usr/bin/bismark-command $(1)/usr/bin/bismark-command
	$(INSTALL_DIR) $(1)/usr/lib/lua/luci/bismark
	$(CP) ./files/usr/lib/lua/luci/bismark.lua $(1)/usr/lib/lua/luci/bismark.lua
	$(INSTALL_DIR) $(1)/usr/lib/lua/luci/controller/fathom_rpc
	$(CP) ./files/usr/lib/lua/luci/controller/fathom_rpc.lua $(1)/usr/lib/lua/luci/controller/fathom_rpc.lua
	$(INSTALL_DIR) $(1)/etc/avahi/services
	$(CP) ./files/etc/avahi/services/* $(1)/etc/avahi/services

endef

define Package/fathom_rpc/preinst
endef

define Package/fathom_rpc/prerm
endef

define Package/fathom_rpc/postinst
	/etc/init.d/avahi-daemon enable
	/etc/init.d/avahi-daemon restart
endef

$(eval $(call BuildPackage,fathom_rpc))
