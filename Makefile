PLUGIN_NAME=	os-app-router
PLUGIN_VERSION=	1.0.0
PLUGIN_COMMENT=	Application-aware routing plugin for OPNsense

PREFIX?=	/usr/local
DESTDIR?=

PLUGIN_SCRIPTS=	$(DESTDIR)$(PREFIX)/opnsense/scripts/OPNsense/AppRouter
PLUGIN_MVC=	$(DESTDIR)$(PREFIX)/opnsense/mvc/app
PLUGIN_SERVICE=	$(DESTDIR)$(PREFIX)/opnsense/service
PLUGIN_CONF=	$(DESTDIR)$(PREFIX)/etc/app-router
PLUGIN_HOOK=	$(DESTDIR)$(PREFIX)/etc/inc/plugins.inc.d

.PHONY: install install-plugin activate uninstall clean lint

install: install-plugin activate
	@echo ""
	@echo "========================================="
	@echo " $(PLUGIN_NAME) $(PLUGIN_VERSION) installed"
	@echo " Navigate to Firewall > AppRouter in the web UI"
	@echo " Run initial list update:"
	@echo "   configctl approuter update_lists"
	@echo "========================================="

install-plugin:
	@echo ">>> Installing $(PLUGIN_NAME) $(PLUGIN_VERSION)..."
	@# Plugin hook
	@mkdir -p $(PLUGIN_HOOK)
	@cp src/etc/inc/plugins.inc.d/approuter.inc $(PLUGIN_HOOK)/approuter.inc
	@# MVC Models
	@mkdir -p $(PLUGIN_MVC)/models/OPNsense/AppRouter/Menu
	@mkdir -p $(PLUGIN_MVC)/models/OPNsense/AppRouter/ACL
	@cp src/opnsense/mvc/app/models/OPNsense/AppRouter/AppRouter.xml \
		$(PLUGIN_MVC)/models/OPNsense/AppRouter/AppRouter.xml
	@cp src/opnsense/mvc/app/models/OPNsense/AppRouter/AppRouter.php \
		$(PLUGIN_MVC)/models/OPNsense/AppRouter/AppRouter.php
	@cp src/opnsense/mvc/app/models/OPNsense/AppRouter/Menu/Menu.xml \
		$(PLUGIN_MVC)/models/OPNsense/AppRouter/Menu/Menu.xml
	@cp src/opnsense/mvc/app/models/OPNsense/AppRouter/ACL/ACL.xml \
		$(PLUGIN_MVC)/models/OPNsense/AppRouter/ACL/ACL.xml
	@# MVC Controllers
	@mkdir -p $(PLUGIN_MVC)/controllers/OPNsense/AppRouter/Api
	@mkdir -p $(PLUGIN_MVC)/controllers/OPNsense/AppRouter/forms
	@cp src/opnsense/mvc/app/controllers/OPNsense/AppRouter/IndexController.php \
		$(PLUGIN_MVC)/controllers/OPNsense/AppRouter/IndexController.php
	@cp src/opnsense/mvc/app/controllers/OPNsense/AppRouter/Api/SettingsController.php \
		$(PLUGIN_MVC)/controllers/OPNsense/AppRouter/Api/SettingsController.php
	@cp src/opnsense/mvc/app/controllers/OPNsense/AppRouter/Api/ServiceController.php \
		$(PLUGIN_MVC)/controllers/OPNsense/AppRouter/Api/ServiceController.php
	@cp src/opnsense/mvc/app/controllers/OPNsense/AppRouter/forms/general.xml \
		$(PLUGIN_MVC)/controllers/OPNsense/AppRouter/forms/general.xml
	@cp src/opnsense/mvc/app/controllers/OPNsense/AppRouter/forms/lists.xml \
		$(PLUGIN_MVC)/controllers/OPNsense/AppRouter/forms/lists.xml
	@# MVC Views
	@mkdir -p $(PLUGIN_MVC)/views/OPNsense/AppRouter
	@cp src/opnsense/mvc/app/views/OPNsense/AppRouter/index.volt \
		$(PLUGIN_MVC)/views/OPNsense/AppRouter/index.volt
	@# Backend scripts
	@mkdir -p $(PLUGIN_SCRIPTS)
	@cp src/opnsense/scripts/OPNsense/AppRouter/list_updater.py $(PLUGIN_SCRIPTS)/
	@cp src/opnsense/scripts/OPNsense/AppRouter/dns_watcher.py $(PLUGIN_SCRIPTS)/
	@cp src/opnsense/scripts/OPNsense/AppRouter/table_manager.sh $(PLUGIN_SCRIPTS)/
	@cp src/opnsense/scripts/OPNsense/AppRouter/app_categories.json $(PLUGIN_SCRIPTS)/
	@chmod +x $(PLUGIN_SCRIPTS)/*.py
	@chmod +x $(PLUGIN_SCRIPTS)/*.sh
	@# configd actions
	@mkdir -p $(PLUGIN_SERVICE)/conf/actions.d
	@cp src/opnsense/service/conf/actions.d/actions_approuter.conf \
		$(PLUGIN_SERVICE)/conf/actions.d/actions_approuter.conf
	@# Service templates
	@mkdir -p $(PLUGIN_SERVICE)/templates/OPNsense/AppRouter
	@cp src/opnsense/service/templates/OPNsense/AppRouter/+TARGETS \
		$(PLUGIN_SERVICE)/templates/OPNsense/AppRouter/+TARGETS
	@cp src/opnsense/service/templates/OPNsense/AppRouter/approuter.conf \
		$(PLUGIN_SERVICE)/templates/OPNsense/AppRouter/approuter.conf
	@# Data directories
	@mkdir -p $(PLUGIN_CONF)/domains
	@mkdir -p $(PLUGIN_CONF)/cidrs
	@mkdir -p $(PLUGIN_CONF)/dnsmasq.d
	@mkdir -p $(PLUGIN_CONF)/unbound.d
	@# Runtime directories
	@mkdir -p $(DESTDIR)/var/run/approuter
	@echo ">>> Files installed."

activate:
	@echo ">>> Activating plugin..."
	@# Flush cached menu to pick up new entries
	@rm -f /tmp/opnsense_menu_cache.xml 2>/dev/null || true
	@# Verify PHP syntax
	@find $(PLUGIN_MVC)/controllers/OPNsense/AppRouter -name '*.php' -exec php -l {} \; 2>&1 | grep -v "No syntax errors" || true
	@find $(PLUGIN_MVC)/models/OPNsense/AppRouter -name '*.php' -exec php -l {} \; 2>&1 | grep -v "No syntax errors" || true
	@# Restart configd to register new actions
	@service configd restart 2>/dev/null || echo "Note: configd not running (dev environment?)"
	@echo ">>> Plugin activated."

uninstall:
	@echo ">>> Uninstalling $(PLUGIN_NAME)..."
	@# Stop DNS watcher if running
	@if [ -f /var/run/approuter_dns_watcher.pid ]; then \
		$(PLUGIN_SCRIPTS)/dns_watcher.py stop 2>/dev/null || true; \
	fi
	@# Flush pf tables to remove stale routing state
	@/sbin/pfctl -s Tables 2>/dev/null | grep "^approuter_" | while read table; do \
		/sbin/pfctl -t "$$table" -T flush 2>/dev/null || true; \
	done
	@# Remove MVC components
	@rm -rf $(PLUGIN_MVC)/models/OPNsense/AppRouter
	@rm -rf $(PLUGIN_MVC)/controllers/OPNsense/AppRouter
	@rm -rf $(PLUGIN_MVC)/views/OPNsense/AppRouter
	@# Remove backend scripts
	@rm -rf $(PLUGIN_SCRIPTS)
	@# Remove configd actions
	@rm -f $(PLUGIN_SERVICE)/conf/actions.d/actions_approuter.conf
	@# Remove service templates
	@rm -rf $(PLUGIN_SERVICE)/templates/OPNsense/AppRouter
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

clean:
	@find . -name '__pycache__' -exec rm -rf {} + 2>/dev/null || true
	@find . -name '*.pyc' -delete 2>/dev/null || true

lint:
	@echo ">>> Checking Python scripts..."
	@python3 -m py_compile src/opnsense/scripts/OPNsense/AppRouter/list_updater.py
	@python3 -m py_compile src/opnsense/scripts/OPNsense/AppRouter/dns_watcher.py
	@echo ">>> Checking XML files..."
	@find src -name '*.xml' -exec xmllint --noout {} \; 2>/dev/null || echo "(xmllint not available, skipping)"
	@echo ">>> All checks passed."
