include $(TOPDIR)/rules.mk

PKG_NAME:=wfb-ng
PKG_VERSION:=24.9.3
PKG_RELEASE:=1
PKG_LICENSE:=GPL-3.0-only
PKG_LICENSE_FILES:=LICENSE

PKG_SOURCE_PROTO:=git
PKG_SOURCE_URL:=https://github.com/svpcom/wfb-ng.git
PKG_SOURCE_VERSION:=7d53559455bc4aa4df34c666de1ec7c9655d8f43
PKG_MIRROR_HASH:=afa8bd06d3119e3fa8edc10d4a205e8b9ad21d0157e151aecba4dc24329a0d76

PKG_BUILD_PARALLEL:=1
PKG_MAINTAINER:=Vasily Evseenko <svpcom@p2ptech.org>

include $(INCLUDE_DIR)/package.mk

define Build/Compile
        $(MAKE) $(PKG_JOBS) -C $(PKG_BUILD_DIR)/$(MAKE_PATH) \
                $(MAKE_FLAGS) \
	        VERSION=$(PKG_VERSION) COMMIT=$(PKG_SOURCE_VERSION) \
		all_bin
endef

define Package/wfb-ng
  SECTION:=net
  CATEGORY:=Network
  DEPENDS:=+libpcap +libsodium +libstdcpp
  TITLE:=Long-range packet radio link using raw WiFi
  URL:=https://github.com/svpcom/wfb-ng
  SUBMENU:=Wireless
endef

define Package/wfb-ng/description
  The next generation of long-range packet radio link using raw WiFi
  This is a base version that have only binaries and can act as cluster node,
  standalone receiver or transmitter without diversity.
endef

define Package/wfb-ng/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/wfb_rx $(1)/usr/bin/
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/wfb_tx $(1)/usr/bin/
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/wfb-ng.init $(1)/etc/init.d/wfb-ng
endef

$(eval $(call BuildPackage,wfb-ng))
