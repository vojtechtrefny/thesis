PKGNAME=bitlockersetup
SPECFILE=bitlockersetup.spec
VERSION=$(shell awk '/Version:/ { print $$2 }' $(SPECFILE))

pylint:
	@echo "*** Running pylint ***"
	PYTHONPATH=. tests/pylint/runpylint.py

pep8:
	@echo "*** Running pep8 compliance check ***"
	@if test `which pycodestyle-3` ; then \
		pep8='pycodestyle-3' ; \
	else \
		echo "You need to install pycodestyle/pep8 to run this check."; exit 1; \
	fi ; \
	$$pep8 --ignore=E501,E402,E731,W504 bitlockersetup/ tests/

build:
	python3 setup.py build

check:
	@status=0; \
	$(MAKE) pylint || status=1; \
	$(MAKE) pep8 || status=1; \
	exit $$status

clean:
	-@rm -f bitlockersetup/*.pyc
	-@rm -rf dist bitlockersetup.egg-info pylint-log build
	@python3 setup.py -q clean

install:
	python3 setup.py install --root=$(DESTDIR)

local:
	@rm -rf $(PKGNAME)-$(VERSION).tar.gz
	@rm -rf /tmp/$(PKGNAME)-$(VERSION) /tmp/$(PKGNAME)
	@dir=$$PWD; cp -a $$dir /tmp/$(PKGNAME)-$(VERSION)
	@cd /tmp/$(PKGNAME)-$(VERSION) ; python3 setup.py -q sdist
	@cp /tmp/$(PKGNAME)-$(VERSION)/dist/$(PKGNAME)-$(VERSION).tar.gz .
	@rm -rf /tmp/$(PKGNAME)-$(VERSION)
	@echo "The archive is in $(PKGNAME)-$(VERSION).tar.gz"

srpm: local
	rpmbuild -bs --nodeps $(PKGNAME).spec --define "_sourcedir `pwd`"
	rm -f $(PKGNAME)-$(VERSION).tar.gz

rpm: local
	rpmbuild -bb --nodeps $(PKGNAME).spec --define "_sourcedir `pwd`"
	rm -f $(PKGNAME)-$(VERSION).tar.gz

.PHONY: check pep8 pylint clean install local
