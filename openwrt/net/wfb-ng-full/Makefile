include $(TOPDIR)/rules.mk

PKG_NAME:=wfb-ng-full
PKG_VERSION:=24.9.4
PKG_RELEASE:=1

PKG_SOURCE_PROTO:=git
PKG_SOURCE_URL:=https://github.com/svpcom/wfb-ng.git
PKG_SOURCE_VERSION:=0787977f8979392739fe703a4c9716023950e4eb
#PKG_MIRROR_HASH:=2451a64be61a5052c2625c859548adcea141afece7ad297e0043bb911035dcdd

PKG_LICENSE:=GPL-3.0-only
PKG_LICENSE_FILES:=LICENSE
PKG_MAINTAINER:=Vasily Evseenko <svpcom@p2ptech.org>

PKG_BUILD_PARALLEL:=1
PYPI_SOURCE_NAME:=wfb_ng

include $(INCLUDE_DIR)/package.mk
include $(TOPDIR)/feeds/packages/lang/python/python3-package.mk

PYTHON3_VARS:=$(PYTHON3_VARS) VERSION=$(PKG_VERSION) COMMIT=$(PKG_SOURCE_VERSION) OMIT_DATA_FILES=1
MAKE_FLAGS += VERSION=$(PKG_VERSION) COMMIT=$(PKG_SOURCE_VERSION) all_bin

define Package/wfb-ng-full
  SECTION:=net
  CATEGORY:=Network
  SUBMENU:=Wireless
  CONFLICTS:=wfb-ng
  TITLE:=Long-range packet radio link using raw WiFi
  URL:=https://github.com/svpcom/wfb-ng
  DEPENDS:=+bash +iw +kmod-tun +openssh-client +libpcap +libsodium +libstdcpp +python3-twisted +python3-pyserial +python3-msgpack +python3-jinja2 +python3-pyroute2
endef

define Package/wfb-ng-full/description
  The next generation of long-range packet radio link using raw WiFi.
  This is a full version that can act as cluster manager, standalone
  receiver or transmitter with divesity.
endef

define Py3Package/wfb-ng-full/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(CP) $(PKG_INSTALL_DIR)/usr/bin/* $(1)/usr/bin/
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/wfb_rx $(1)/usr/bin/
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/wfb_tx $(1)/usr/bin/
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/wfb_tx_cmd $(1)/usr/bin/
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/wfb_keygen $(1)/usr/bin/
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/wfb-ng.init $(1)/etc/init.d/wfb-ng
endef

$(eval $(call Py3Package,wfb-ng-full))
$(eval $(call BuildPackage,wfb-ng-full))
