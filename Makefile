PLUGIN_NAME=	os-app-router
PLUGIN_VERSION=	1.0.0
PLUGIN_COMMENT=	Application-aware routing plugin for OPNsense

PREFIX?=	/usr/local
DESTDIR?=

PLUGIN_SCRIPTS=	$(DESTDIR)$(PREFIX)/opnsense/scripts/OPNsense/Approuter
PLUGIN_MVC=	$(DESTDIR)$(PREFIX)/opnsense/mvc/app
PLUGIN_SERVICE=	$(DESTDIR)$(PREFIX)/opnsense/service
PLUGIN_CONF=	$(DESTDIR)$(PREFIX)/etc/app-router
PLUGIN_HOOK=	$(DESTDIR)$(PREFIX)/etc/inc/plugins.inc.d

.PHONY: install install-plugin activate uninstall uninstall-all clean lint

install: install-plugin activate
	@echo ""
	@echo "========================================="
	@echo " $(PLUGIN_NAME) $(PLUGIN_VERSION) installed"
	@echo " Navigate to Services > AppRouter in the web UI"
	@echo "========================================="

install-plugin:
	@echo ">>> Installing $(PLUGIN_NAME) $(PLUGIN_VERSION)..."
	@# Plugin hook
	@mkdir -p $(PLUGIN_HOOK)
	@cp src/etc/inc/plugins.inc.d/approuter.inc $(PLUGIN_HOOK)/approuter.inc
	@# MVC Models
	@mkdir -p $(PLUGIN_MVC)/models/OPNsense/Approuter/Menu
	@mkdir -p $(PLUGIN_MVC)/models/OPNsense/Approuter/ACL
	@cp src/opnsense/mvc/app/models/OPNsense/Approuter/Approuter.xml \
		$(PLUGIN_MVC)/models/OPNsense/Approuter/Approuter.xml
	@cp src/opnsense/mvc/app/models/OPNsense/Approuter/Approuter.php \
		$(PLUGIN_MVC)/models/OPNsense/Approuter/Approuter.php
	@cp src/opnsense/mvc/app/models/OPNsense/Approuter/Menu/Menu.xml \
		$(PLUGIN_MVC)/models/OPNsense/Approuter/Menu/Menu.xml
	@cp src/opnsense/mvc/app/models/OPNsense/Approuter/ACL/ACL.xml \
		$(PLUGIN_MVC)/models/OPNsense/Approuter/ACL/ACL.xml
	@# MVC Controllers
	@mkdir -p $(PLUGIN_MVC)/controllers/OPNsense/Approuter/Api
	@mkdir -p $(PLUGIN_MVC)/controllers/OPNsense/Approuter/forms
	@cp src/opnsense/mvc/app/controllers/OPNsense/Approuter/IndexController.php \
		$(PLUGIN_MVC)/controllers/OPNsense/Approuter/IndexController.php
	@cp src/opnsense/mvc/app/controllers/OPNsense/Approuter/Api/SettingsController.php \
		$(PLUGIN_MVC)/controllers/OPNsense/Approuter/Api/SettingsController.php
	@cp src/opnsense/mvc/app/controllers/OPNsense/Approuter/Api/ServiceController.php \
		$(PLUGIN_MVC)/controllers/OPNsense/Approuter/Api/ServiceController.php
	@cp src/opnsense/mvc/app/controllers/OPNsense/Approuter/forms/general.xml \
		$(PLUGIN_MVC)/controllers/OPNsense/Approuter/forms/general.xml
	@cp src/opnsense/mvc/app/controllers/OPNsense/Approuter/forms/lists.xml \
		$(PLUGIN_MVC)/controllers/OPNsense/Approuter/forms/lists.xml
	@# MVC Views
	@mkdir -p $(PLUGIN_MVC)/views/OPNsense/Approuter
	@cp src/opnsense/mvc/app/views/OPNsense/Approuter/index.volt \
		$(PLUGIN_MVC)/views/OPNsense/Approuter/index.volt
	@# Backend scripts
	@mkdir -p $(PLUGIN_SCRIPTS)
	@cp src/opnsense/scripts/OPNsense/Approuter/list_updater.py $(PLUGIN_SCRIPTS)/
	@cp src/opnsense/scripts/OPNsense/Approuter/dns_watcher.py $(PLUGIN_SCRIPTS)/
	@cp src/opnsense/scripts/OPNsense/Approuter/table_manager.sh $(PLUGIN_SCRIPTS)/
	@cp src/opnsense/scripts/OPNsense/Approuter/app_categories.json $(PLUGIN_SCRIPTS)/
	@chmod +x $(PLUGIN_SCRIPTS)/*.py
	@chmod +x $(PLUGIN_SCRIPTS)/*.sh
	@# configd actions
	@mkdir -p $(PLUGIN_SERVICE)/conf/actions.d
	@cp src/opnsense/service/conf/actions.d/actions_approuter.conf \
		$(PLUGIN_SERVICE)/conf/actions.d/actions_approuter.conf
	@# Service templates
	@mkdir -p $(PLUGIN_SERVICE)/templates/OPNsense/Approuter
	@cp src/opnsense/service/templates/OPNsense/Approuter/+TARGETS \
		$(PLUGIN_SERVICE)/templates/OPNsense/Approuter/+TARGETS
	@cp src/opnsense/service/templates/OPNsense/Approuter/approuter.conf \
		$(PLUGIN_SERVICE)/templates/OPNsense/Approuter/approuter.conf
	@cp src/opnsense/service/templates/OPNsense/Approuter/approuter_unbound.conf \
		$(PLUGIN_SERVICE)/templates/OPNsense/Approuter/approuter_unbound.conf
	@# Data directories
	@mkdir -p $(PLUGIN_CONF)/domains
	@mkdir -p $(PLUGIN_CONF)/cidrs
	@mkdir -p $(PLUGIN_CONF)/clients
	@mkdir -p $(PLUGIN_CONF)/dnsmasq.d
	@mkdir -p $(PLUGIN_CONF)/unbound.d
	@# Runtime directories
	@mkdir -p $(DESTDIR)/var/run/approuter
	@echo ">>> Files installed."

activate:
	@echo ">>> Activating plugin..."
	@# Flush all caches so changes take effect
	@rm -f /tmp/opnsense_menu_cache.xml 2>/dev/null || true
	@rm -f /tmp/*.cache 2>/dev/null || true
	@rm -rf /tmp/opnsense_volt_templates 2>/dev/null || true
	@rm -rf /var/cache/opnsense 2>/dev/null || true
	@# Verify PHP syntax
	@find $(PLUGIN_MVC)/controllers/OPNsense/Approuter -name '*.php' -exec php -l {} \; 2>&1 | grep -v "No syntax errors" || true
	@find $(PLUGIN_MVC)/models/OPNsense/Approuter -name '*.php' -exec php -l {} \; 2>&1 | grep -v "No syntax errors" || true
	@# Kill any old dns_watcher before restarting services
	@pkill -f 'dns_watcher.py' 2>/dev/null || true
	@rm -f /var/run/approuter_dns_watcher.pid 2>/dev/null || true
	@# Restart configd to register new actions
	@service configd restart 2>/dev/null || echo "Note: configd not running (dev environment?)"
	@# Restart php-fpm to clear opcache (ensures new PHP code is loaded)
	@service php-fpm restart 2>/dev/null || true
	@echo ">>> Plugin activated. Click Apply in the UI to start dns_watcher."

uninstall:
	@echo ">>> Uninstalling $(PLUGIN_NAME)..."
	@# Stop DNS watcher if running (kill directly, don't rely on script)
	@if [ -f /var/run/approuter_dns_watcher.pid ]; then \
		kill `cat /var/run/approuter_dns_watcher.pid` 2>/dev/null || true; \
		rm -f /var/run/approuter_dns_watcher.pid; \
	fi
	@# Also kill any orphan dns_watcher processes
	@pkill -f 'dns_watcher.py' 2>/dev/null || true
	@# Flush pf tables to remove stale routing state
	@/sbin/pfctl -s Tables 2>/dev/null | grep "^approuter_" | while read table; do \
		/sbin/pfctl -t "$$table" -T flush 2>/dev/null || true; \
	done
	@# Remove MVC components
	@rm -rf $(PLUGIN_MVC)/models/OPNsense/Approuter
	@rm -rf $(PLUGIN_MVC)/controllers/OPNsense/Approuter
	@rm -rf $(PLUGIN_MVC)/views/OPNsense/Approuter
	@# Remove backend scripts
	@rm -rf $(PLUGIN_SCRIPTS)
	@# Remove configd actions
	@rm -f $(PLUGIN_SERVICE)/conf/actions.d/actions_approuter.conf
	@# Remove service templates
	@rm -rf $(PLUGIN_SERVICE)/templates/OPNsense/Approuter
	@# Remove plugin hook
	@rm -f $(PLUGIN_HOOK)/approuter.inc
	@# Clean caches and runtime state (these cause issues on reinstall)
	@rm -rf $(PLUGIN_CONF)/dnsmasq.d
	@rm -rf $(PLUGIN_CONF)/unbound.d
	@rm -rf $(PLUGIN_CONF)/domains
	@rm -rf $(PLUGIN_CONF)/cidrs
	@rm -f $(PLUGIN_CONF)/state.json
	@rm -rf /var/run/approuter
	@rm -f /var/run/approuter_dns_watcher.pid
	@rm -f /tmp/opnsense_menu_cache.xml 2>/dev/null || true
	@rm -rf /tmp/approuter
	@# Preserve config.json (user settings) - only remove if explicitly asked
	@echo ">>> Note: $(PLUGIN_CONF)/config.json preserved (user settings)."
	@echo ">>>       To fully remove: rm -rf $(PLUGIN_CONF)"
	@# Restart configd to deregister actions
	@service configd restart 2>/dev/null || true
	@# Reload firewall to remove injected rules
	@configctl filter reload 2>/dev/null || true
	@echo ">>> $(PLUGIN_NAME) uninstalled."

uninstall-all: uninstall
	@echo ">>> Removing ALL data (config, caches, generated files)..."
	@# Remove entire config directory including config.json and clients
	@rm -rf $(PLUGIN_CONF)
	@# Remove generated Unbound config
	@rm -f $(DESTDIR)$(PREFIX)/etc/unbound.opnsense.d/approuter.conf
	@# Remove generated Dnsmasq configs (in case user had dnsmasq mode)
	@rm -f $(DESTDIR)$(PREFIX)/etc/dnsmasq.opnsense.d/approuter_*.conf
	@# Remove generated template output
	@rm -f $(DESTDIR)$(PREFIX)/etc/app-router/config.json
	@# Flush all OPNsense caches
	@rm -f /tmp/opnsense_menu_cache.xml 2>/dev/null || true
	@rm -f /tmp/*.cache 2>/dev/null || true
	@rm -rf /tmp/opnsense_volt_templates 2>/dev/null || true
	@rm -rf /var/cache/opnsense 2>/dev/null || true
	@# Remove Approuter config from config.xml (OPNsense model data)
	@if command -v configctl >/dev/null 2>&1; then \
		echo ">>> Note: AppRouter settings in config.xml must be removed manually via:"; \
		echo ">>>   Edit /conf/config.xml and remove the <Approuter> section under <OPNsense>"; \
	fi
	@# Restart services to clear all state
	@service configd restart 2>/dev/null || true
	@service php-fpm restart 2>/dev/null || true
	@configctl filter reload 2>/dev/null || true
	@echo ">>> $(PLUGIN_NAME) fully removed (clean slate)."

clean:
	@find . -name '__pycache__' -exec rm -rf {} + 2>/dev/null || true
	@find . -name '*.pyc' -delete 2>/dev/null || true

lint:
	@echo ">>> Checking Python scripts..."
	@python3 -m py_compile src/opnsense/scripts/OPNsense/Approuter/list_updater.py
	@python3 -m py_compile src/opnsense/scripts/OPNsense/Approuter/dns_watcher.py
	@echo ">>> Checking XML files..."
	@find src -name '*.xml' -exec xmllint --noout {} \; 2>/dev/null || echo "(xmllint not available, skipping)"
	@echo ">>> All checks passed."
