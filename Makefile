include $(TOPDIR)/rules.mk

PKG_NAME:=easy-websockd
PKG_RELEASE:=1

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)

PKG_MAINTAINER:=Jiwan Kim <wldhks1004@naver.com>

include $(INCLUDE_DIR)/package.mk
include $(INCLUDE_DIR)/kernel.mk

define Package/easy-websockd
  CATEGORY:=Kaonbroadband
  TITLE:=Easy WebSocket Server
  DEPENDS:=+libwebsockets +libjson-c +libopenssl
endef

define Package/easy-websockd/description
  Provides a WebSocket server with JSON-RPC functionality using libwebsockets, JSON-C, and OpenSSL for encryption.
endef

TARGET_CFLAGS += \
	-Werror \
	-I$(PKG_BUILD_DIR) \
	-I$(STAGING_DIR)/usr/include

TARGET_LDFLAGS += \
	-Wl,-rpath-link=$(STAGING_DIR)/usr/lib \
	-L$(STAGING_DIR)/usr/lib \
	-lcrypto -lssl

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
endef

define Build/Compile
	$(TARGET_CC) $(TARGET_CFLAGS) -o $(PKG_BUILD_DIR)/easy-websockd $(PKG_BUILD_DIR)/websocket-server.c \
		-lwebsockets -ljson-c -lcrypto -lssl
endef

define Package/easy-websockd/install
	$(INSTALL_DIR) $(1)/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/easy-websockd $(1)/bin/

	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/etc/init.d/easy-websockd $(1)/etc/init.d/easy-websockd
endef

$(eval $(call BuildPackage,easy-websockd))
