%global pypi_name distributedcloud

%global with_doc %{!?_without_doc:1}%{?_without_doc:0}
%{!?upstream_version: %global upstream_version %{version}%{?milestone}}

%if 0%{?fedora}
%global with_python3 1
%{!?python3_shortver: %global python3_shortver %(%{__python3} -c 'import sys; print(str(sys.version_info.major) + "." + str(sys.version_info.minor))')}
%endif

Name:          %{pypi_name}
Version:       1.0.0
Release:       1%{?_tis_dist}.%{tis_patch_ver}
Summary:       Distributed Cloud Services

License:       ASL 2.0
URL:           unknown
Source0:       %{pypi_name}-%{version}.tar.gz
Source1:       dcmanager-api.service
Source2:       dcmanager-manager.service
Source3:       dcorch-api.service
Source4:       dcorch-engine.service
Source5:       dcorch-sysinv-api-proxy.service
Source6:       dcorch-identity-api-proxy.service
Source7:       dcdbsync-api.service
Source8:       dcdbsync-openstack-api.service
Source9:       dcmanager.conf
Source10:      dcorch.conf
Source11:      dcdbsync.conf
Source12:      clean-dcorch
Source13:      dcmanager-audit.service
Source14:      dcmanager-orchestrator.service
Source15:      distcloud-syslog.conf
Source16:      distcloud-logrotate.conf
Source17:      dcmanager-audit-worker.service

BuildArch:     noarch

BuildRequires: python3-crypto
BuildRequires: python3-cryptography
BuildRequires: python3-devel
BuildRequires: python3-eventlet
BuildRequires: python3-setuptools
BuildRequires: python3-pip
BuildRequires: python3-wheel
BuildRequires: python3-jsonschema
BuildRequires: python3-keyring
BuildRequires: python3-keystonemiddleware
BuildRequires: python3-keystoneauth1
BuildRequires: python3-netaddr
BuildRequires: python3-oslo-concurrency >= 3.29.1
BuildRequires: python3-oslo-config
BuildRequires: python3-oslo-context
BuildRequires: python3-oslo-db
BuildRequires: python3-oslo-i18n
BuildRequires: python3-oslo-log
BuildRequires: python3-oslo-messaging
BuildRequires: python3-oslo-middleware
BuildRequires: python3-oslo-policy
BuildRequires: python3-oslo-rootwrap
BuildRequires: python3-oslo-serialization
BuildRequires: python3-oslo-service
BuildRequires: python3-oslo-utils
BuildRequires: python3-oslo-versionedobjects
BuildRequires: python3-pbr
BuildRequires: python3-pecan
BuildRequires: python3-routes
BuildRequires: python3-sphinx
BuildRequires: python3-pyOpenSSL
BuildRequires: systemd
# Required to compile translation files
BuildRequires: python3-babel

%description
Distributed Cloud provides configuration and management of distributed clouds

# DC Common
%package dccommon
Summary: DC common module
Requires: python-kubernetes

%description dccommon
Distributed Cloud Common Module

# DC Manager
%package dcmanager
Summary: DC Manager

%description dcmanager
Distributed Cloud Manager

%package dcorch
Summary: DC Orchestrator
# TODO(John): should we add Requires lines?
Requires: openstack-ras

%description dcorch
Distributed Cloud Orchestrator

%package dcdbsync
Summary: DC DCorch DBsync Agent

%description dcdbsync
Distributed Cloud DCorch DBsync Agent

%prep
%autosetup -n %{pypi_name}-%{version}

# Remove the requirements file so that pbr hooks don't add it
# to distutils requires_dist config
rm -rf {test-,}requirements.txt tools/{pip,test}-requires

%build
export PBR_VERSION=%{version}
%{__python3} setup.py build
%py3_build_wheel
# Generate sample config and add the current directory to PYTHONPATH so
# oslo-config-generator doesn't skip heat's entry points.
PYTHONPATH=. oslo-config-generator --config-file=./dcmanager/config-generator.conf
PYTHONPATH=. oslo-config-generator --config-file=./dcorch/config-generator.conf
PYTHONPATH=. oslo-config-generator --config-file=./dcdbsync/config-generator.conf


%install
export PBR_VERSION=%{version}
%{__python3} setup.py install -O1 --skip-build --root %{buildroot} \
                                  --single-version-externally-managed
install -d $RPM_BUILD_ROOT/wheels
install -m 644 dist/*.whl $RPM_BUILD_ROOT/wheels/
install -d -m 755 %{buildroot}%{_tmpfilesdir}
install -d -m 755 %{buildroot}/var/log/dcmanager
install -d -m 755 %{buildroot}/var/cache/dcmanager
install -d -m 755 %{buildroot}%{_sysconfdir}/dcmanager/
# install systemd unit files
install -p -D -m 644 %{SOURCE1} %{buildroot}%{_unitdir}/dcmanager-api.service
install -p -D -m 644 %{SOURCE2} %{buildroot}%{_unitdir}/dcmanager-manager.service
install -p -D -m 644 %{SOURCE13} %{buildroot}%{_unitdir}/dcmanager-audit.service
install -p -D -m 644 %{SOURCE17} %{buildroot}%{_unitdir}/dcmanager-audit-worker.service
install -p -D -m 644 %{SOURCE14} %{buildroot}%{_unitdir}/dcmanager-orchestrator.service
install -p -D -m 644 %{SOURCE9} %{buildroot}%{_tmpfilesdir}
# install default config files
cd %{_builddir}/%{pypi_name}-%{version} && oslo-config-generator --config-file ./dcmanager/config-generator.conf --output-file %{_builddir}/%{pypi_name}-%{version}%{_sysconfdir}/dcmanager/dcmanager.conf.sample
install -p -D -m 640 %{_builddir}/%{pypi_name}-%{version}%{_sysconfdir}/dcmanager/dcmanager.conf.sample %{buildroot}%{_sysconfdir}/dcmanager/dcmanager.conf

install -p -D -m 644 %{SOURCE15} %{buildroot}%{_sysconfdir}/syslog-ng/conf.d/distcloud.conf
install -p -D -m 644 %{SOURCE16} %{buildroot}%{_sysconfdir}/logrotate.d/distcloud.conf

install -d -m 755 %{buildroot}/var/log/dcorch
install -d -m 755 %{buildroot}/var/cache/dcorch
install -d -m 755 %{buildroot}%{_sysconfdir}/dcorch/
# install systemd unit files
install -p -D -m 644 %{SOURCE3} %{buildroot}%{_unitdir}/dcorch-api.service
install -p -D -m 644 %{SOURCE4} %{buildroot}%{_unitdir}/dcorch-engine.service
install -p -D -m 644 %{SOURCE5} %{buildroot}%{_unitdir}/dcorch-sysinv-api-proxy.service
install -p -D -m 644 %{SOURCE6} %{buildroot}%{_unitdir}/dcorch-identity-api-proxy.service
install -p -D -m 644 %{SOURCE10} %{buildroot}%{_tmpfilesdir}

# install ocf scripts
install -d -m 755 ${RPM_BUILD_ROOT}/usr/lib/ocf/resource.d/openstack
install -p -D -m 755 ocf/* ${RPM_BUILD_ROOT}/usr/lib/ocf/resource.d/openstack/

# install default config files
cd %{_builddir}/%{pypi_name}-%{version} && oslo-config-generator --config-file ./dcorch/config-generator.conf --output-file %{_builddir}/%{pypi_name}-%{version}%{_sysconfdir}/dcorch/dcorch.conf.sample
install -p -D -m 640 %{_builddir}/%{pypi_name}-%{version}%{_sysconfdir}/dcorch/dcorch.conf.sample %{buildroot}%{_sysconfdir}/dcorch/dcorch.conf

# dc dbsync agent
install -d -m 755 %{buildroot}/var/log/dcdbsync
install -d -m 755 %{buildroot}/var/cache/dcdbsync
install -d -m 755 %{buildroot}%{_sysconfdir}/dcdbsync/
# install systemd unit files
install -p -D -m 644 %{SOURCE7} %{buildroot}%{_unitdir}/dcdbsync-api.service
# install systemd unit files for optional second instance
install -p -D -m 644 %{SOURCE8} %{buildroot}%{_unitdir}/dcdbsync-openstack-api.service
install -p -D -m 644 %{SOURCE11} %{buildroot}%{_tmpfilesdir}
# install default config files
cd %{_builddir}/%{pypi_name}-%{version} && oslo-config-generator --config-file ./dcdbsync/config-generator.conf --output-file %{_builddir}/%{pypi_name}-%{version}%{_sysconfdir}/dcdbsync/dcdbsync.conf.sample
install -p -D -m 640 %{_builddir}/%{pypi_name}-%{version}%{_sysconfdir}/dcdbsync/dcdbsync.conf.sample %{buildroot}%{_sysconfdir}/dcdbsync/dcdbsync.conf

# install ansible overrides dir
install -d -m 600 ${RPM_BUILD_ROOT}/opt/dc/ansible

# install dcorch cleaner
install -m 755 -D -p %{SOURCE12} %{buildroot}/%{_bindir}/clean-dcorch

%files dccommon
%license LICENSE
%{python3_sitelib}/dccommon*
%{python3_sitelib}/distributedcloud-*.egg-info
%exclude %{python3_sitelib}/dccommon/tests
%{_sysconfdir}/syslog-ng/conf.d/distcloud.conf
%{_sysconfdir}/logrotate.d/distcloud.conf

%files dcmanager
%license LICENSE
%{python3_sitelib}/dcmanager*
%exclude %{python3_sitelib}/dcmanager/tests
%{_bindir}/dcmanager-api
%{_unitdir}/dcmanager-api.service
%{_bindir}/dcmanager-audit
%{_unitdir}/dcmanager-audit.service
%{_bindir}/dcmanager-audit-worker
%{_unitdir}/dcmanager-audit-worker.service
%{_bindir}/dcmanager-orchestrator
%{_unitdir}/dcmanager-orchestrator.service
%{_bindir}/dcmanager-manager
%{_unitdir}/dcmanager-manager.service
%{_bindir}/dcmanager-manage
%{_tmpfilesdir}/dcmanager.conf
%dir %attr(0755,root,root) %{_localstatedir}/log/dcmanager
%dir %attr(0755,root,root) %{_localstatedir}/cache/dcmanager
%dir %attr(0755,root,root) %{_sysconfdir}/dcmanager
%config(noreplace) %attr(-, root, root) %{_sysconfdir}/dcmanager/dcmanager.conf
%dir %attr(0755,root,root) /usr/lib/ocf/resource.d/openstack
%dir %attr(0600,root,root) /opt/dc/ansible
%defattr(-,root,root,-)
/usr/lib/ocf/resource.d/openstack/dcmanager-*


%files dcorch
%license LICENSE
%{python3_sitelib}/dcorch*
%exclude %{python3_sitelib}/dcorch/tests
%{_bindir}/dcorch-api
%{_unitdir}/dcorch-api.service
%{_bindir}/dcorch-engine
%{_unitdir}/dcorch-engine.service
%{_bindir}/dcorch-api-proxy
%{_unitdir}/dcorch-sysinv-api-proxy.service
%{_unitdir}/dcorch-identity-api-proxy.service
%{_bindir}/dcorch-manage
%{_bindir}/clean-dcorch
%{_tmpfilesdir}/dcorch.conf
%dir %attr(0755,root,root) %{_localstatedir}/log/dcorch
%dir %attr(0755,root,root) %{_localstatedir}/cache/dcorch
%dir %attr(0755,root,root) %{_sysconfdir}/dcorch
%config(noreplace) %attr(-, dcorch, dcorch) %{_sysconfdir}/dcorch/dcorch.conf
%dir %attr(0755,root,root) /usr/lib/ocf/resource.d/openstack
%defattr(-,root,root,-)
/usr/lib/ocf/resource.d/openstack/dcorch-*


%files dcdbsync
%license LICENSE
%{python3_sitelib}/dcdbsync*
%exclude %{python3_sitelib}/dcdbsync/tests
%{_bindir}/dcdbsync-api
%{_unitdir}/dcdbsync-api.service
%{_unitdir}/dcdbsync-openstack-api.service
%{_tmpfilesdir}/dcdbsync.conf
%dir %attr(0755,root,root) %{_localstatedir}/log/dcdbsync
%dir %attr(0755,root,root) %{_localstatedir}/cache/dcdbsync
%dir %attr(0755,root,root) %{_sysconfdir}/dcdbsync
%config(noreplace) %attr(-, root, root) %{_sysconfdir}/dcdbsync/dcdbsync.conf
%dir %attr(0755,root,root) /usr/lib/ocf/resource.d/openstack
%defattr(-,root,root,-)
/usr/lib/ocf/resource.d/openstack/dcdbsync-*

%pre dcorch
getent group dcorch >/dev/null || groupadd -r --gid 173 dcorch
getent passwd dcorch >/dev/null || \
useradd --uid 173 -r -g dcorch -d /var/lib/dcorch -s /sbin/nologin \
-c "dcorch Daemons" dcorch
exit 0

%package wheels
Summary: %{name} wheels

%description wheels
Contains python wheels for %{name}

%files wheels
/wheels/*
