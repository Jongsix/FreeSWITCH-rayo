######################################################################################################################
#
# freeswitch-config-rayo for FreeSWITCH Modular Media Switching Software Library / Soft-Switch Application
# Copyright (C) 2013, Grasshopper
#
# Version: MPL 1.1
#
# The contents of this file are subject to the Mozilla Public License Version
# 1.1 (the "License"); you may not use this file except in compliance with
# the License. You may obtain a copy of the License at
# http://www.mozilla.org/MPL/
#
# Software distributed under the License is distributed on an "AS IS" basis,
# WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License
# for the specific language governing rights and limitations under the
# License.
#
# The Original Code is freeswitch-config-rayo for FreeSWITCH Modular Media Switching Software Library / Soft-Switch Application
#
# The Initial Developer of the Original Code is Grasshopper
# Portions created by the Initial Developer are Copyright (C)
# the Initial Developer. All Rights Reserved.
#
# Contributor(s):
# Chris Rienzo <chris.rienzo@grasshopper.com>
#
# freeswitch-rayo-config -- RPM packaging for Rayo Server configuration
#
######################################################################################################################

%define version %{VERSION_NUMBER}
%define release %{BUILD_NUMBER}

######################################################################################################################
# Layout of packages FHS (Redhat/SUSE), FS (Standard FreeSWITCH layout using /usr/local)
#
%define packagelayout	FS

%if "%{packagelayout}" == "FS"
# disable rpath checking
#%define __arch_install_post /usr/lib/rpm/check-buildroot
%define _prefix   /usr/local/freeswitch
%define prefix    %{_prefix}
%define sysconfdir   %{prefix}/conf
%define _sysconfdir   %{sysconfdir}
%define logfiledir    %{prefix}/log
%define _logfiledir   %{logfiledir}
%define runtimedir    %{prefix}/run
%define _runtimedir   %{runtimedir}

%define PREFIX          %{prefix}
%define EXECPREFIX      %{PREFIX}
%define BINDIR          %{PREFIX}/bin
%define SBINDIR         %{PREFIX}/bin
%define LIBEXECDIR      %{PREFIX}/bin
%define SYSCONFDIR      %{sysconfdir}
%define SHARESTATEDIR   %{PREFIX}
%define LOCALSTATEDIR   %{PREFIX}
%define LIBDIR          %{PREFIX}/lib
%define INCLUDEDIR      %{PREFIX}/include
%define DATAROOTDIR     %{PREFIX}
%define DATADIR         %{PREFIX}
%define INFODIR         %{PREFIX}/info
%define LOCALEDIR       %{PREFIX}/locale
%define MANDIR          %{PREFIX}/man
%define DOCDIR          %{PREFIX}/doc
%define HTMLDIR         %{DOCDIR}/html
%define DVIDIR          %{DOCDIR}/dvi
%define PDFDIR          %{DOCDIR}/pdf
%define PSDIR           %{DOCDIR}/ps
%define LOGFILEDIR      %{logfiledir}
%define MODINSTDIR      %{PREFIX}/mod
%define RUNDIR          %{runtimedir}
%define DBDIR           %{PREFIX}/db
%define HTDOCSDIR       %{PREFIX}/htdocs
%define SOUNDSDIR       %{PREFIX}/sounds
%define GRAMMARDIR      %{PREFIX}/grammar
%define SCRIPTDIR       %{PREFIX}/scripts
%define RECORDINGSDIR   %{PREFIX}/recordings
%define PKGCONFIGDIR    %{PREFIX}/pkgconfig
%define HOMEDIR         %{PREFIX}

%else

# disable rpath checking
#%define __arch_install_post /usr/lib/rpm/check-buildroot
#%define _prefix   /usr
#%define prefix    %{_prefix}
#%define sysconfdir	/etc/freeswitch
#%define _sysconfdir	%{sysconfdir}
#%define logfiledir	/var/log/freeswitch
#%define _logfiledir	%{logfiledir}
#%define runtimedir	/var/run/freeswitch
#%define _runtimedir	%{runtimedir}

%define	PREFIX		%{_prefix}
%define EXECPREFIX	%{_exec_prefix}
%define BINDIR		%{_bindir}
%define SBINDIR		%{_sbindir}
%define LIBEXECDIR	%{_libexecdir}/%name
%define SYSCONFDIR	%{_sysconfdir}/%name
%define SHARESTATEDIR	%{_sharedstatedir}/%name
%define LOCALSTATEDIR	%{_localstatedir}/lib/%name
%define LIBDIR		%{_libdir}
%define INCLUDEDIR	%{_includedir}
%define _datarootdir	%{_prefix}/share
%define DATAROOTDIR	%{_datarootdir}
%define DATADIR		%{_datadir}
%define INFODIR		%{_infodir}
%define LOCALEDIR	%{_datarootdir}/locale
%define MANDIR		%{_mandir}
%define DOCDIR		%{_defaultdocdir}/%name
%define HTMLDIR		%{_defaultdocdir}/%name/html
%define DVIDIR		%{_defaultdocdir}/%name/dvi
%define PDFDIR		%{_defaultdocdir}/%name/pdf
%define PSDIR		%{_defaultdocdir}/%name/ps
%define LOGFILEDIR	/var/log/%name
%define MODINSTDIR	%{_libdir}/%name/mod
%define RUNDIR		%{_localstatedir}/run/%name
%define DBDIR		%{LOCALSTATEDIR}/db
%define HTDOCSDIR	%{_datarootdir}/%name/htdocs
%define SOUNDSDIR	%{_datarootdir}/%name/sounds
%define GRAMMARDIR	%{_datarootdir}/%name/grammar
%define SCRIPTDIR	%{_datarootdir}/%name/scripts
%define RECORDINGSDIR	%{LOCALSTATEDIR}/recordings
%define PKGCONFIGDIR	%{_datarootdir}/%name/pkgconfig
%define HOMEDIR		%{LOCALSTATEDIR}

%endif

Name: freeswitch-config-rayo
Version: %{version}
Release: %{release}%{?dist}
License: MPL1.1
Summary: Rayo configuration for the FreeSWITCH Open Source telephone platform.
Group: System/Libraries
Packager: Chris Rienzo
URL: http://www.freeswitch.org/
Source0: freeswitch-%{version}.tar.bz2
Requires: freeswitch = %{version}
Requires: freeswitch-application-conference
Requires: freeswitch-application-distributor
Requires: freeswitch-application-esf
Requires: freeswitch-application-expr
Requires: freeswitch-application-fsv
Requires: freeswitch-application-hash
Requires: freeswitch-application-http-cache
Requires: freeswitch-asrtts-flite
Requires: freeswitch-asrtts-pocketsphinx
Requires: freeswitch-lua
Requires: freeswitch-codec-celt
Requires: freeswitch-codec-ilbc
Requires: freeswitch-codec-opus
Requires: freeswitch-codec-speex
Requires: freeswitch-event-rayo
Requires: freeswitch-format-local-stream
Requires: freeswitch-format-mod-shout
Requires: freeswitch-format-shell-stream
Requires: freeswitch-format-ssml
Requires: freeswitch-sounds-music-8000
Requires: freeswitch-sounds-music-16000
Requires: freeswitch-sounds-music-32000
Requires: freeswitch-sounds-music-48000
Requires: freeswitch-lang-en
Requires: freeswitch-sounds-en-us-callie-8000
Requires: freeswitch-sounds-en-us-callie-16000
Requires: freeswitch-sounds-en-us-callie-32000
Requires: freeswitch-sounds-en-us-callie-48000
BuildRequires: bash
BuildRoot:    %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

%description
FreeSWITCH rayo server implementation.

%prep
%setup -b0 -q -n freeswitch-%{version}

%build

%install
%{__rm} -rf %{buildroot}
%{__install} -d -m 0750 %{buildroot}/%{SYSCONFDIR}
%{__install} -d -m 0750 %{buildroot}/%{SYSCONFDIR}/autoload_configs
%{__install} -d -m 0750 %{buildroot}/%{SYSCONFDIR}/dialplan
%{__install} -d -m 0750 %{buildroot}/%{SYSCONFDIR}/sip_profiles
%{__install} -d -m 0750 %{buildroot}/%{SYSCONFDIR}/directory
%{__cp} -prv ./conf/rayo/*.{xml,types,pem} %{buildroot}/%{SYSCONFDIR}/
%{__cp} -prv ./conf/rayo/{autoload_configs,dialplan} %{buildroot}/%{SYSCONFDIR}/
%{__cp} -prv ./conf/rayo/sip_profiles/external.xml %{buildroot}/%{SYSCONFDIR}/sip_profiles
%{__cp} -prv ./conf/rayo/sip_profiles/external %{buildroot}/%{SYSCONFDIR}/sip_profiles
%{__cp} -prv ./conf/rayo/directory %{buildroot}/%{SYSCONFDIR}/

%postun

%clean
%{__rm} -rf %{buildroot}

%files
%defattr(-,freeswitch,daemon)
%dir %attr(0750, freeswitch, daemon) %{SYSCONFDIR}
%config(noreplace) %attr(0640, freeswitch, daemon) %{SYSCONFDIR}/cacert.pem
%config(noreplace) %attr(0640, freeswitch, daemon) %{SYSCONFDIR}/*.xml
%config(noreplace) %attr(0640, freeswitch, daemon) %{SYSCONFDIR}/mime.types
%config(noreplace) %attr(0640, freeswitch, daemon) %{SYSCONFDIR}/autoload_configs/acl.conf.xml
%config(noreplace) %attr(0640, freeswitch, daemon) %{SYSCONFDIR}/autoload_configs/cdr_csv.conf.xml
%config(noreplace) %attr(0640, freeswitch, daemon) %{SYSCONFDIR}/autoload_configs/conference.conf.xml
%config(noreplace) %attr(0640, freeswitch, daemon) %{SYSCONFDIR}/autoload_configs/console.conf.xml
%config(noreplace) %attr(0640, freeswitch, daemon) %{SYSCONFDIR}/autoload_configs/distributor.conf.xml
%config(noreplace) %attr(0640, freeswitch, daemon) %{SYSCONFDIR}/autoload_configs/event_socket.conf.xml
%config(noreplace) %attr(0640, freeswitch, daemon) %{SYSCONFDIR}/autoload_configs/hash.conf.xml
%config(noreplace) %attr(0640, freeswitch, daemon) %{SYSCONFDIR}/autoload_configs/http_cache.conf.xml
%config(noreplace) %attr(0640, freeswitch, daemon) %{SYSCONFDIR}/autoload_configs/local_stream.conf.xml
%config(noreplace) %attr(0640, freeswitch, daemon) %{SYSCONFDIR}/autoload_configs/logfile.conf.xml
%config(noreplace) %attr(0640, freeswitch, daemon) %{SYSCONFDIR}/autoload_configs/lua.conf.xml
%config(noreplace) %attr(0640, freeswitch, daemon) %{SYSCONFDIR}/autoload_configs/memcache.conf.xml
%config(noreplace) %attr(0640, freeswitch, daemon) %{SYSCONFDIR}/autoload_configs/modules.conf.xml
%config(noreplace) %attr(0640, freeswitch, daemon) %{SYSCONFDIR}/autoload_configs/pocketsphinx.conf.xml
%config(noreplace) %attr(0640, freeswitch, daemon) %{SYSCONFDIR}/autoload_configs/post_load_modules.conf.xml
%config(noreplace) %attr(0640, freeswitch, daemon) %{SYSCONFDIR}/autoload_configs/presence_map.conf.xml
%config(noreplace) %attr(0640, freeswitch, daemon) %{SYSCONFDIR}/autoload_configs/rayo.conf.xml
%config(noreplace) %attr(0640, freeswitch, daemon) %{SYSCONFDIR}/autoload_configs/shout.conf.xml
%config(noreplace) %attr(0640, freeswitch, daemon) %{SYSCONFDIR}/autoload_configs/sofia.conf.xml
%config(noreplace) %attr(0640, freeswitch, daemon) %{SYSCONFDIR}/autoload_configs/spandsp.conf.xml
%config(noreplace) %attr(0640, freeswitch, daemon) %{SYSCONFDIR}/autoload_configs/ssml.conf.xml
%config(noreplace) %attr(0640, freeswitch, daemon) %{SYSCONFDIR}/autoload_configs/switch.conf.xml
%config(noreplace) %attr(0640, freeswitch, daemon) %{SYSCONFDIR}/autoload_configs/timezones.conf.xml
%config(noreplace) %attr(0640, freeswitch, daemon) %{SYSCONFDIR}/dialplan/public.xml
%config(noreplace) %attr(0640, freeswitch, daemon) %{SYSCONFDIR}/directory/default.xml
%config(noreplace) %attr(0640, freeswitch, daemon) %{SYSCONFDIR}/directory/default/*.xml
%config(noreplace) %attr(0640, freeswitch, daemon) %{SYSCONFDIR}/sip_profiles/*.xml
%config(noreplace) %attr(0640, freeswitch, daemon) %{SYSCONFDIR}/sip_profiles/external/*.xml

### END OF config-rayo

######################################################################################################################
#
#						Changelog
#
######################################################################################################################
%changelog
* Mon Jun 03 2013 - chris.rienzo@grasshopper.com
- Added users and internal profile for softphone testing
* Wed May 08 2013 - chris.rienzo@grasshopper.com
- Initial revision

