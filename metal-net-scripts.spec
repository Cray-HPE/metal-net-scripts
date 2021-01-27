# Copyright 2020 Hewlett Packard Enterprise Development LP

%define install_dir /opt/cray/csm

Requires: python3
Requires: python3-PyYAML
Requires: python3-requests
Requires: python3-urllib3

Name: metal-net-scripts
BuildArch: noarch
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}
License: HPE Proprietary
Summary: Installs Python scripts for network configuration and troubleshooting.
Version: %(cat .version)
Release: %(echo ${BUILD_METADATA})
Source: %{name}-%{version}.tar.bz2
Vendor: Hewlett Packard Enterprise Development LP

%description

%prep

%setup -q

%build

%install

%clean

%files
%license LICENSE
%{install_dir}/scripts/

%changelog
