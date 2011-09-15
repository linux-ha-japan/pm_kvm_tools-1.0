#
# Makefile.am for pm_kvm_tools
#

MAINTAINERCLEANFILES	= Makefile.in aclocal.m4 configure libtool.m4 ltdl.m4 libltdl.tar

SUBDIRS			= include lib tools plugins resources conf

SPEC			= $(PACKAGE_NAME).spec
TARFILE			= $(PACKAGE_NAME)-$(VERSION).tar.gz
EXTRA_DIST		= $(SPEC) autogen.sh include/vm_connect.h \
			  conf/vm-manager.conf conf/vm-connectd.conf.sample

$(TARFILE):
	$(MAKE) dist

RPM_ROOT		= $(shell pwd)
RPMBUILDOPTS		= --define "_sourcedir $(RPM_ROOT)" \
			  --define "_specdir $(RPM_ROOT)"

srpm: clean
	rm -f $(TARFILE)
	$(MAKE) $(SPEC) $(TARFILE)
	rpmbuild $(RPMBUILDOPTS) --nodeps -bs --rmsource $(SPEC)

rpm: clean
	rm -f $(TARFILE)
	$(MAKE) $(SPEC) $(TARFILE)
	rpmbuild $(RPMBUILDOPTS) -ba --rmsource $(SPEC)
