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
Source5:       dcorch-nova-api-proxy.service
Source6:       dcorch-sysinv-api-proxy.service
Source7:       dcorch-snmp.service
Source8:       dcorch-cinder-api-proxy.service
Source9:       dcorch-neutron-api-proxy.service
Source10:      dcorch-identity-api-proxy.service

BuildArch:     noarch

BuildRequires: python-crypto
BuildRequires: python-cryptography
BuildRequires: python2-devel
BuildRequires: python-eventlet
BuildRequires: python-setuptools
BuildRequires: python-jsonschema >= 2.0.0
BuildRequires: python-keyring
BuildRequires: python-keystonemiddleware
BuildRequires: python-keystoneauth1 >= 3.1.0
BuildRequires: python-netaddr
BuildRequires: python-oslo-concurrency
BuildRequires: python-oslo-config
BuildRequires: python-oslo-context
BuildRequires: python-oslo-db
BuildRequires: python-oslo-i18n
BuildRequires: python-oslo-log
BuildRequires: python-oslo-messaging
BuildRequires: python-oslo-middleware
BuildRequires: python-oslo-policy
BuildRequires: python-oslo-rootwrap
BuildRequires: python-oslo-serialization
BuildRequires: python-oslo-service
BuildRequires: python-oslo-utils
BuildRequires: python-oslo-versionedobjects
BuildRequires: python-pbr >= 1.8
BuildRequires: python-pecan >= 1.0.0
BuildRequires: python-routes >= 1.12.3
BuildRequires: python-sphinx
BuildRequires: python-sphinxcontrib-httpdomain
BuildRequires: pyOpenSSL
BuildRequires: systemd
# Required to compile translation files
BuildRequires: python-babel

%description
Distributed Cloud provides configuration and management of distributed clouds

# DC Manager
%package dcmanager
Summary: DC Manager

%description dcmanager
Distributed Cloud Manager

%package dcorch
Summary: DC Orchestrator
# TODO(John): should we add Requires lines?

%description dcorch
Distributed Cloud Orchestrator

%prep
%autosetup -n %{pypi_name}-%{version}

# Remove the requirements file so that pbr hooks don't add it
# to distutils requires_dist config
rm -rf {test-,}requirements.txt tools/{pip,test}-requires

%build
export PBR_VERSION=%{version}
%{__python2} setup.py build
# Generate sample config and add the current directory to PYTHONPATH so
# oslo-config-generator doesn't skip heat's entry points.
PYTHONPATH=. oslo-config-generator --config-file=./dcmanager/config-generator.conf
PYTHONPATH=. oslo-config-generator --config-file=./dcorch/config-generator.conf


%install
export PBR_VERSION=%{version}
%{__python2} setup.py install -O1 --skip-build --root %{buildroot} \
                                  --single-version-externally-managed
mkdir -p %{buildroot}/var/log/dcmanager
mkdir -p %{buildroot}/var/cache/dcmanager
mkdir -p %{buildroot}/var/run/dcmanager
mkdir -p %{buildroot}/etc/dcmanager/
# install systemd unit files
install -p -D -m 644 %{SOURCE1} %{buildroot}%{_unitdir}/dcmanager-api.service
install -p -D -m 644 %{SOURCE2} %{buildroot}%{_unitdir}/dcmanager-manager.service
# install default config files
cd %{_builddir}/%{pypi_name}-%{version} && oslo-config-generator --config-file ./dcmanager/config-generator.conf --output-file %{_builddir}/%{pypi_name}-%{version}/etc/dcmanager/dcmanager.conf.sample
install -p -D -m 640 %{_builddir}/%{pypi_name}-%{version}/etc/dcmanager/dcmanager.conf.sample %{buildroot}%{_sysconfdir}/dcmanager/dcmanager.conf


mkdir -p %{buildroot}/var/log/dcorch
mkdir -p %{buildroot}/var/cache/dcorch
mkdir -p %{buildroot}/var/run/dcorch
mkdir -p %{buildroot}/etc/dcorch/
# install systemd unit files
install -p -D -m 644 %{SOURCE3} %{buildroot}%{_unitdir}/dcorch-api.service
install -p -D -m 644 %{SOURCE4} %{buildroot}%{_unitdir}/dcorch-engine.service
install -p -D -m 644 %{SOURCE5} %{buildroot}%{_unitdir}/dcorch-nova-api-proxy.service
install -p -D -m 644 %{SOURCE6} %{buildroot}%{_unitdir}/dcorch-sysinv-api-proxy.service
install -p -D -m 644 %{SOURCE7} %{buildroot}%{_unitdir}/dcorch-snmp.service
install -p -D -m 644 %{SOURCE8} %{buildroot}%{_unitdir}/dcorch-cinder-api-proxy.service
install -p -D -m 644 %{SOURCE9} %{buildroot}%{_unitdir}/dcorch-neutron-api-proxy.service
install -p -D -m 644 %{SOURCE10} %{buildroot}%{_unitdir}/dcorch-identity-api-proxy.service

# install default config files
cd %{_builddir}/%{pypi_name}-%{version} && oslo-config-generator --config-file ./dcorch/config-generator.conf --output-file %{_builddir}/%{pypi_name}-%{version}/etc/dcorch/dcorch.conf.sample
install -p -D -m 640 %{_builddir}/%{pypi_name}-%{version}/etc/dcorch/dcorch.conf.sample %{buildroot}%{_sysconfdir}/dcorch/dcorch.conf

%files dcmanager
%license LICENSE
%{python2_sitelib}/dcmanager*
%{python2_sitelib}/distributedcloud-*.egg-info
%exclude %{python2_sitelib}/dcmanager/tests
%{_bindir}/dcmanager-api
%{_unitdir}/dcmanager-api.service
%{_bindir}/dcmanager-manager
%{_unitdir}/dcmanager-manager.service
%{_bindir}/dcmanager-manage
%dir %attr(0755,root,root) %{_localstatedir}/log/dcmanager
%dir %attr(0755,root,root) %{_localstatedir}/run/dcmanager
%dir %attr(0755,root,root) %{_localstatedir}/cache/dcmanager
%dir %attr(0755,root,root) %{_sysconfdir}/dcmanager
%config(noreplace) %attr(-, root, root) %{_sysconfdir}/dcmanager/dcmanager.conf


%files dcorch
%license LICENSE
%{python2_sitelib}/dcorch*
%{python2_sitelib}/distributedcloud-*.egg-info
%exclude %{python2_sitelib}/dcorch/tests
%{_bindir}/dcorch-api
%{_unitdir}/dcorch-api.service
%{_bindir}/dcorch-engine
%{_unitdir}/dcorch-engine.service
%{_bindir}/dcorch-api-proxy
%{_unitdir}/dcorch-nova-api-proxy.service
%{_unitdir}/dcorch-sysinv-api-proxy.service
%{_unitdir}/dcorch-cinder-api-proxy.service
%{_unitdir}/dcorch-neutron-api-proxy.service
%{_unitdir}/dcorch-identity-api-proxy.service
%{_bindir}/dcorch-manage
%{_bindir}/dcorch-snmp
%{_unitdir}/dcorch-snmp.service
%dir %attr(0755,root,root) %{_localstatedir}/log/dcorch
%dir %attr(0755,root,root) %{_localstatedir}/run/dcorch
%dir %attr(0755,root,root) %{_localstatedir}/cache/dcorch
%dir %attr(0755,root,root) %{_sysconfdir}/dcorch
%config(noreplace) %attr(-, root, root) %{_sysconfdir}/dcorch/dcorch.conf
