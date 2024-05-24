%global modname pywmi-wbem
Name:           python3-%{modname}
Version:        0.3.0
Release:        0%{?dist}
Summary:        Library for WMI interaction

License:        MIT
Source0:        %{modname}-%{version}.tar.gz

BuildArch:      noarch
BuildRequires:  python3-devel
BuildRequires:  python3-setuptools
BuildRequires:  python3-rpm-macros
Requires:       python3-requests
Requires:       python3-gssapi
Requires:       python3-lxml

%description
Library for WMI interaction

%package -n nagios-plugins-wbem
Summary: Nagios checks for WMI healtchecks using wbem
Requires: nagios-common
Requires: python3-pytz
Requires: %{name} = %{version}-%{release}

%description -n nagios-plugins-wbem
Nagios checks for WMI healtchecks using wbem

%prep
%autosetup -n %{modname}-%{version}

%build
%py3_build

%install
%{__python3} setup.py install --skip-build --root $RPM_BUILD_ROOT --install-scripts %{_libdir}/nagios/plugins

%files
%{python3_sitelib}/*

%files -n nagios-plugins-wbem
%{_libdir}/nagios/plugins/*

%changelog
