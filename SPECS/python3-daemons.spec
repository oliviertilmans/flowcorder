%global srcname daemons
%global sum A python module providing well behaved unix daemons for every occasion. 

Name:           python3-%{srcname}
Version:        1.3.0
Release:        1%{?dist}
Summary:        %{sum}

License:        APACHE-2.0
URL:            https://pypi.python.org/pypi/%{srcname}
Source0:        https://files.pythonhosted.org/packages/source/e/%{srcname}/%{srcname}-%{version}.tar.gz

BuildArch:      noarch
BuildRequires:  python34-devel python34-setuptools

%description
Daemons is a resource library for Python developers that want to create daemon processes.
The classes in this library provide the basic daemonization, signal handling, 
and pid management functionality while allowing for any implementation of behaviour and logic.

%prep
%autosetup -n %{srcname}-%{version}

%build
%py3_build

%install
%py3_install

%check
%{__python3} setup.py test

%files
%license LICENSE
%doc README.rst
%{python3_sitelib}/*


%changelog
* Fri Jan 12 2018 Olivier Tilmans <olivier.tilmans@uclouvain.be> - 1.3.0
- Initial import
