# Copyright 2021 Hewlett Packard Enterprise Development LP
%define install_dir /opt/cray/metal
%define application /net-scripts
%global __python /usr/bin/python3

# This needs to be updated in-tandem to setup.py
# since this depends on the CRAY's python3.
Requires: python3
Requires: python3-PyYAML
Requires: python3-requests
Requires: python3-urllib3

Name: metal-net-scripts
BuildArch: noarch
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}
License: HPE Proprietary
Summary: Installs Python scripts for network configuration and trouble-shooting
Version: %(cat .version)
Release: %(echo ${BUILD_METADATA})
Source: %{name}-%{version}.tar.bz2
Vendor: Hewlett Packard Enterprise Development LP

%description

%prep
%setup -n %{name}-%{version}

%build
%{__python} setup.py build

%install
%{__python} setup.py install -O1 --root=$RPM_BUILD_ROOT --record=INSTALLED_FILES
cat INSTALLED_FILES | grep __pycache__ | xargs dirname | xargs dirname | uniq >> INSTALLED_FILES
cat INSTALLED_FILES

%clean
%{__python} setup.py clean --all

%files -f INSTALLED_FILES
%defattr(755,root,root)
%license LICENSE

%changelog
