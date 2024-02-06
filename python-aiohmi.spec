%global with_python3 1
%global sname aiohmi
%global common_summary Python General Hardware Management Initiative (IPMI and others)

%global common_desc This is a pure Python implementation of IPMI protocol. \
\
The included aiohmicons and aiohmiutil scripts demonstrate how one may \
incorporate the aiohmi library into a Python application.

%global common_desc_tests Tests for the aiohmi library

Summary: %{common_summary}
Name: python-%{sname}
Version: %{?version:%{version}}%{!?version:%(python setup.py --version)}
Release: %{?release:%{release}}%{!?release:1}
Source0: http://tarballs.openstack.org/%{sname}/%{sname}-%{version}.tar.gz
License: ASL 2.0
Group: Development/Libraries
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-buildroot
Prefix: %{_prefix}
BuildArch: noarch
Vendor: Jarrod Johnson <jjohnson2@lenovo.com>
Url: https://git.openstack.org/cgit/openstack/aiohmi

%description
%{common_desc}

%package -n python2-%{sname}
Summary: %{common_summary}
%{?python_provide:%python_provide python2-%{sname}}

BuildRequires: python2-devel
BuildRequires: python2-pbr
BuildRequires: python2-setuptools

Requires: python2-cryptography >= 2.1, python2-cryptography, python2-dateutil

%description -n python2-%{sname}
%{common_desc}

%package -n python2-%{sname}-tests
Summary: %{common_desc_tests}
Requires: python2-%{sname} = %{version}-%{release}

%description -n python2-%{sname}-tests
%{common_desc_tests}

%if 0%{?with_python3}

%package -n python3-%{sname}
Summary: %{common_summary}
%{?python_provide:%python_provide python3-%{sname}}

BuildRequires: python3-devel
BuildRequires: python3-pbr
BuildRequires: python3-setuptools

Requires: python3-cryptography >= 2.1, python3-dateutil

%description -n python3-%{sname}
%{common_desc}

%package -n python3-%{sname}-tests
Summary: %{common_desc_tests}
Requires: python3-%{sname} = %{version}-%{release}

%description -n python3-%{sname}-tests
%{common_desc_tests}

%endif # with_python3

%package -n python-%{sname}-doc
Summary: The aiohmi library documentation

BuildRequires: python2-sphinx

%description -n python-%{sname}-doc
Documentation for the aiohmi library

%prep
%setup -qn %{sname}-%{version}

%build
%if 0%{?with_python3}
%py3_build
%endif # with_python3

%py2_build

# generate html docs
%{__python2} setup.py build_sphinx -b html
# remove the sphinx-build leftovers
rm -rf doc/build/html/.{doctrees,buildinfo}

%install
%if 0%{?with_python3}
%py3_install

# rename python3 binary
pushd %{buildroot}/%{_bindir}
mv aiohmicons aiohmicons-%{python3_version}
ln -s aiohmicons-%{python3_version} aiohmicons-3
mv aiohmiutil aiohmiutil-%{python3_version}
ln -s aiohmiutil-%{python3_version} aiohmiutil-3
mv virshbmc virshbmc-%{python3_version}
ln -s virshbmc-%{python3_version} virshbmc-3
mv fakebmc fakebmc-%{python3_version}
ln -s fakebmc-%{python3_version} fakebmc-3
popd

%endif # with_python3

%py2_install

%if 0%{?with_python3}
%files -n python3-%{sname}
%license LICENSE
%{_bindir}/aiohmicons-%{python3_version}
%{_bindir}/aiohmicons-3
%{_bindir}/aiohmiutil-%{python3_version}
%{_bindir}/aiohmiutil-3
%{_bindir}/virshbmc-%{python3_version}
%{_bindir}/virshbmc-3
%{_bindir}/fakebmc-%{python3_version}
%{_bindir}/fakebmc-3
%{python3_sitelib}/%{sname}
%{python3_sitelib}/%{sname}-*.egg-info
%exclude %{python3_sitelib}/%{sname}/tests

%files -n python3-%{sname}-tests
%license LICENSE
%{python3_sitelib}/%{sname}/tests
%endif # with_python3

%files -n python2-%{sname}
%license LICENSE
%{_bindir}/aiohmicons
%{_bindir}/aiohmiutil
%{_bindir}/virshbmc
%{_bindir}/fakebmc
%{python2_sitelib}/%{sname}
%{python2_sitelib}/%{sname}-*.egg-info
%exclude %{python2_sitelib}/%{sname}/tests

%files -n python2-%{sname}-tests
%license LICENSE
%{python2_sitelib}/%{sname}/tests

%files -n python-%{sname}-doc
%license LICENSE
%doc doc/build/html README.rst

%changelog
* Fri Aug 10 2018 Ilya Etingof <etingof@gmail.com> 0.1.0-1
- Add Python 3 build
