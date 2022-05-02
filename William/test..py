"""here we test commands file for business logic"""
import os
import re
import unittest
from base64 import b64decode
from collections import defaultdict, namedtuple
from datetime import datetime
from subprocess import check_output
from coputils.app import AgencyFixPort

import pytest
from coputils import cluster, syslogsender, COREOPS_COMMANDS_PATH, app, apps, COREOPS_SCRIPTS_PATH
from coputils.vm import VM
from coputils.errors import CoreopsError
from coreopsUtils import isAtlasCore, getAttrs, commsGlob, get_output
from tools.commonroll import is_nlob_spin_core
from typing import Iterator
from test import set_unittest_env

# used to tell coputils/app.py to throw exceptions during unittests
set_unittest_env()

ALL_CLUSTERS = cluster.get_all_clusters(coreops_commands_path=COREOPS_COMMANDS_PATH)
IGNORE_CLUSTERS = [
    "aus01",
    "aus02",
    "aus11",
    "aus03",
    "bog01",
    "dub01",
    "dub09",
    "tyo01",
    "aus04",
    "vas08"
]
IGNORE_CLUSTERS_HST = ["aus02", "aus03", "aus04", "aus11", "vas08"]

"""
Before changing any of the count values below please confirm with apac-compliance@virtu.com as we will need to
adjust our HST registration https://theloop.virtu.com/display/COM/HST+Key+Information
"""
JAPAN_HST_CONSTS = {
    "SBIJ_BAML": [0, "^/INIT/newCApp.*gw::sbij::MLSbijTokenGateway.*venues=SBIJ"],
    "SBIJ_BARCLAYS": [24, "^/INIT/newCApp.*gw::sbij::SbijToken(|Limits)Gateway.*venues=SBIJ.*clientRef=(ML|BV)1J"],
    "SBIJ_CS": [4, "^/INIT/newCApp.*gw::sbij::SbijTokenGateway.*clientRef=11635.*venues=SBIJ"],
    "SBIX_CS": [1, "^/INIT/newCApp.*gw::sbij::SbijTokenGateway.*venues=SBIX "],
    "SBIX_NOMURA": [4, "^/INIT/newCApp.*gw::sbij::SbijTokenGateway.*venues=SBIX,SBIR"],
    "SBIX_BARCLAYS": [4, "^/INIT/newCApp.*gw::sbij::SbijTokenLimitsGateway.*venues=SBIX,SBIR"],
    "SBIU_NOMURA": [1, "^/INIT/newCApp.*gw::sbij::SbijTokenGateway.*venues=SBIU"],
    "SBIU_BARCLAYS": [1, "^/INIT/newCApp.*gw::sbij::SbijTokenLimitsGateway.*venues=SBIU"],
    "SBIN_ABN": [1, "^/INIT/newCApp.*gw::sbij::SbijTokenCollaredLimitsGateway.*venues=SBIN"],
    "CHIJ_CS": [20, "^/INIT/newCApp.*gw::chij::Chij(|Token)Gateway.*venue=CHIJ"],
    "CHIS_BARCLAYS": [2, "^/INIT/newCApp.*gw::chij::Chij(|Token)Gateway.*venue=CHIS.*clientRef=(ML|BV)1J"],
    "CHIS_NOMURA": [1, "^/INIT/newCApp.*gw::chij::Chij(|Token)Gateway.*venue=CHIS.*clientRef=VTFI"],
    "TSE_ABN": [1, "^/INIT/newCApp.*gw::tse::Arrowhead(|CollaredLimits)Gateway.*venues=.*TSEA"],
    "TSE_BAML": [4, "^/INIT/newCApp.*gw::tse::ArrowheadLimitsGateway.*venues=.*TSEM"],
    "TSE_BARCLAYS": [198, "^/INIT/newCApp.*gw::tse::Arrowhead(Collared|Obo)Gateway.*venues=.*TSEB"],
    "TSE_CS": [4, "^/INIT/newCApp.*gw::tse::Arrowhead(Obo)?Gateway.*venues=.*TSER"],
    "TSE_GOLDMAN": [4, "^/INIT/newCApp.*gw::tse::ArrowheadCollaredGateway.*venues=.*TSEG"],
    "TSE_MS": [4, "^/INIT/newCApp.*gw::tse::ArrowheadGateway.*venues=.*TSES"],
    "TSE_NOMURA": [6, "^/INIT/newCApp.*gw::tse::ArrowheadGateway.*venues=.*TSEN"],
    "TSE_PHILIP": [1, "^/INIT/newCApp.*gw::tse::ArrowheadLimitsGateway.*venues=.*TSEH"],
    "TSE_ALL": [222, "^/INIT/newCApp.*gw::tse::.*Arrowhead.*Gateway.*venues=TSE"],
    # "OSE_BARCLAYS_OM": [10, "^/INIT/newCApp.*mt_cside::applications::gw::om::lite::JpxLite(Obo)?Gateway OSE.*venues=OSE"],
    "OSE_BARCLAYS_OUCH": [82,
                          "^/INIT/newCApp.*mt_cside::applications::gw::genium::jpx::JpxOuch(Obo)?Gateway OSE[0-9].*venues=OSE"],
    "OSE_NISSAN_OUCH": [2,
                        "^/INIT/newCApp.*mt_cside::applications::gw::genium::jpx::JpxOuch(Obo)?Gateway OSEN[0-9].*venues=OSE"],
    # Note the TOCOM session should not be reported as HST as it is under a different regulator in JP, and not required -rs
    "TOCM_NISSAN_OUCH": [0,
                         "^/INIT/newCApp.*mt_cside::applications::gw::genium::jpx::JpxOuch(Obo)?Gateway OSEN[0-9].*venues=TOCM"],
    "TOCM_NISSAN_OM": [1,
                       "^/INIT/newCApp.*mt_cside::applications::gw::om::lite::JpxLite(Obo)?Gateway OSE.*venues=TOCM"],
    "OSE_ALL_OUCH": [84,
                     "^/INIT/newCApp.*mt_cside::applications::gw::genium::jpx::JpxOuch(Obo)?Gateway OSE.*venues=OSE"],
    "OSE_ALL_OM": [11, "^/INIT/newCApp.*mt_cside::applications::gw::om::lite::JpxLite(Obo)?Gateway OSE.*"],
}


def filtered_vms(ignore_clusters=IGNORE_CLUSTERS):
    # type: (list) -> Iterator[cluster.cluster]
    """
    :param ignore_clusters:
    :return: generator object containing 'cluster' objects
    """
    for cl in ALL_CLUSTERS:
        if cl.core in ignore_clusters:
            continue
        yield cl


def get_candi_classes(vms_list):
    classes = set()
    for vm in vms_list:
        for appp in vm.apps:
            if isinstance(appp, app.Gateway):
                classes.add(appp.classname)
            if isinstance(appp, apps.quotes.Quotes):
                for f, fval in appp.feeds.items():
                    classes.add(fval.classname)
    return classes


def getAppCountByCommandRegex(core, regex):
    command_regex = re.compile(r".*%s.*" % regex)
    app_count = 0
    for v in core.vms:
        for line in v.vmdata.commands:
            if command_regex.match(line):
                app_count += 1
                continue
    return app_count


def get_re_result_by_group_num(re_result, group_num):
    if re_result is None or len(re_result.groups()) < group_num:
        return None
    else:
        return re_result.group(group_num)


@pytest.mark.integtest
class TestCommonCommands(unittest.TestCase):
    """
    test commands file to ensure commands files syntax and params are present and values are
    as expected
    """

    def setUp(self):
        """setup up for later tests and by default tests basic import works"""
        self.vm_exceptions = ["CENGINE", "RESP00", "NYCMQUOTE", "CATCHAMUXUAT"]
        # getting candidates classes
        self.candi_classes = set()
        self.clusters = list(filtered_vms())
        for cl in self.clusters:
            cl.get_vms()
            clu_candi_classes = get_candi_classes(cl.getCandidateVms())
            self.candi_classes.update(clu_candi_classes)

    def my_filtered_vms(self):
        for clu in self.clusters:
            for vm in clu.get_vms():
                if vm.vmdata.vmname in self.vm_exceptions:
                    continue
                yield vm

    def list_dupes(self, l):
        return list(set([x for x in l if l.count(x) > 1]))

    def test_all_apps(self):
        """
        This test will reveal bad commands files config, since we removed exceptions from app.py
        in scope
        :return:
        """
        set_unittest_env()
        for cl in ALL_CLUSTERS:
            for vm in cl.get_vms():
                pass
        # set_prod_env()

    def test_solarflare_params(self):
        """
        See COP-68062
        1. SolarFlare onload envir variables won't work via /INIT/setProperty, onload is already initialized by then
        2. If ## DISABLE_SFC: onload settings will be ignored, we can remove them but there's no harm
        /INIT/setProperty TCP_WSNDBUF 131072
        3. EF_TCP_SNDBUF is in bytes, min 1Mb, max 64Mb
        4. TCP_WSNDBUFis in Kb, min 1Mb, max 128Mb
        https://theloop.virtu.com/display/CORE/2020/07/08/Onload+and+TCP+Send+Buffers
        """
        for clu in filtered_vms():
            for vm in clu.get_vms():
                disable_sfc = False
                for command_line in vm.vmdata.commands:
                    if "DISABLE_SFC" in command_line:
                        disable_sfc = True
                    if "export EF_TCP_SNDBUF" in command_line:
                        self.assertTrue(
                            1024 * 1024 <= int(command_line.split("=")[1]) <= 64 * 1024 * 1024,
                            f"Invalid EF_TCP_SNDBUF value, {command_line} in {vm.vmdata.filename}"
                        )
                    if "export TCP_WSNDBUF" in command_line:
                        self.assertTrue(
                            1024 <= int(command_line.split("=")[1]) <= 128 * 1024,
                            f"Invalid TCP_WSNDBUF value, {command_line} in {vm.vmdata.filename}"
                        )
                    self.assertTrue("setProperty EF_" not in command_line,
                                    "Onload will ignore this setting %s, use #$ export to define instead in %s" %
                                    (command_line, vm.vmdata.filename))
                    if not disable_sfc:
                        self.assertTrue("setProperty TCP_" not in command_line,
                                        "Please convert %s to '#$ export' format to maintain proper standards, %s. For details see COP-68062" %
                                        (command_line, vm.vmdata.filename))

    def test_Cpp_xor_Java(self):
        """
        Ensure that a VM never has both C++ and Java apps
        """
        for core in self.clusters:
            for vm in core.get_vms():
                has_Cpp = False
                has_Java = False
                for line in vm.vmdata.commands:
                    if re.match("^/INIT/newCApp", line):
                        has_Cpp = True
                    if re.match("^/INIT/newApp", line):
                        has_Java = True
                self.assertFalse(has_Cpp and has_Java,
                                 "A VM can only have C++ or Java apps; {} in {} has both".format(vm.vmdata.vmname,
                                                                                                 core.name))

    def test_XCPositionSync(self):
        """
        Tests that all XCPC have reciprocal links for each core involved
        also tests that all cores use same connection strings
        """
        summary = defaultdict(dict)
        all_xcpc = defaultdict(dict)
        conn_strings = defaultdict(set)
        for core in self.clusters:
            vms = core.getVmsByCommandRegex(
                regex="com.ewt.applications.bot.xcposition.XCPositionSync"
            )
            for vm in vms:
                all_xcpc[core.name.upper()]['vm'] = vm
                for command in vm.vmdata.commands:
                    if 'addRemoteCoreReader' in command and command not in vm.vmdata.comments:
                        """/XCPC01/addRemoteCoreReader FRA01 xcps.fra01.loc:9090"""
                        trash, remote_core, conn_string = command.split()
                        conn_strings[remote_core].add(conn_string)
                        summary[core.name.upper()][remote_core] = conn_string
        # validation
        for recv_core, remote_cores in summary.items():
            for remote_core, conn_string in remote_cores.items():
                if recv_core not in summary[remote_core]:
                    print('{0} is missing in {1} position sync - {2}'.format(
                        all_xcpc[recv_core]['vm'].vmdata.filename,
                        remote_core,
                        all_xcpc[remote_core]['vm'].vmdata.filename))
                self.assertTrue(
                    recv_core in summary[remote_core],
                    '{0} has {1}, but missing {3} in {1} position sync - {2}'.format(
                        all_xcpc[recv_core]['vm'].vmdata.filename,
                        remote_core,
                        all_xcpc[remote_core]['vm'].vmdata.filename,
                        recv_core
                    )
                )
        for core, sources in conn_strings.items():
            self.assertTrue(
                len(sources) <= 1,
                'Multiple connection strings for %s - %s across XCPositionSync. Please sync ' % (
                    core, ",".join(list(sources)))
            )

    def test_vm_conflict(self):
        """Ensure some specific vms are not cohosted on the same server"""
        conflicts = [
            ('mt_cside::applications::corestreamer::CoreStreamer', 'com.ewt.applications.latencymonitor.LatencyMonitor')
        ]
        for core in self.clusters:
            for case in conflicts:
                (class1, class2) = case
                vms1 = core.getVmsByCommandRegex(regex=class1)
                vms2 = core.getVmsByCommandRegex(regex=class2)
                for vm1 in vms1:
                    vm1_host = vm1.vmdata.host.split('.')[0]
                    other_vms = list(core.cluster_map[vm1_host].values())
                    self.assertFalse(
                        any(x in other_vms for x in vms2),
                        ("%s in %s has conflicting vms, %s VS %s" % (vm1_host, core.name, class1, class2))
                    )

    def test_feeds_have_no_duplicate_channels(self):
        """
        This test will ensure no quoteServer feeds have duplicate multicast channels set for replication
        for now, added for ItchFeed50, will test and add for all feeds
        """
        for core in self.clusters:
            vms = core.getVmsByCommandRegex(
                regex="mt_cside::quoteserver::feeds::itch::ItchFeed50"
            )
            for vm in vms:
                for app in vm.apps:
                    if app.classname in (
                            "mt_cside::applications::aoe::AoeAdmin",
                            "mt_cside::applications::mdbasedinjector::ItchInjector",
                    ):
                        continue

                    for key, feed in app.feeds.items():
                        for command in feed.commands:
                            channels_list = []
                            channels = re.match(
                                r"(.*?)channels=(.*?)\:(.*?)\,(.*?)\:(.*?)\&", command
                            )
                            # ipaddressRegex = "(^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$)"
                            if channels:
                                channels_list.append(channels.group(2))
                                channels_list.append(channels.group(4))

                            dupes = self.list_dupes(channels_list)
                            self.assertFalse(
                                dupes,
                                "Same multicast Channel value %s is used for replication in feed"
                                " %s in Config %s, please update to correct value"
                                % (dupes, feed.name, vm.vmdata.filename),
                            )

    def test_slobudp_multicast_unique_per_core(self):
        """ This test will ensure no quoteServer feeds have duplicate slobudp ip and ports in the same core"""
        for core in self.clusters:
            vms = core.getVmsByCommandRegex(regex="addServer slobudp destination")

            unique_ip_vm_dict = {}
            unique_vm_files = []
            for vm in vms:
                # don't count apps that have more than one slobudp in the commands files(since the other is a comment).
                if vm.vmdata.filename not in unique_vm_files:
                    unique_vm_files.append(vm.vmdata.filename)
                    for command in vm.vmdata.commands:
                        match = re.match(
                            r"(?!^#)(.*?)/addServer slobudp destination=(.*?)\:([0-9]+)",
                            command,
                        )
                        # Regex explanation from above:
                        # not match lines starting with #, match app name (it's not always QUOTES), then match IP, port
                        # this gives IP and port in groups 2 and 3 (and app name in group1 but we don't care)
                        if match:
                            ip, port = match.group(2), match.group(3)
                            self.assertNotIn(
                                (ip, port),
                                unique_ip_vm_dict.keys(),
                                msg="{app} slobudp IP={ip} and port={port} conflicts with {existing_app}".format(
                                    app=vm.vmdata.filename,
                                    ip=ip,
                                    port=port,
                                    existing_app=unique_ip_vm_dict.get((ip, port)),
                                ),
                            )
                            unique_ip_vm_dict[(ip, port)] = vm.vmdata.filename

    def test_microwave_feeds_have_gapRequestDelay_defined(self):
        """ This test ensures quoteServers using microwave data arb with gapRequestDelay defined"""
        for core in self.clusters:
            vms = core.getVmsByCommandRegex(
                regex="mt_cside::quoteserver::feeds::.*239.233"
            )
            for vm in vms:
                for app in vm.apps:
                    if app.classname in ['mt_cside::applications::aoe::AoeAdmin']:
                        continue
                    for key, feed in app.feeds.items():
                        for command in feed.commands:
                            url = re.match(r"(.*?)url=(.*)", command)
                            if url:
                                url_feed = url.group(2).split(" ")[0]

                            delay_check = "gapRequestDelay=" in url_feed
                            self.assertTrue(
                                delay_check,
                                "Microwave feed is missing gapRequestDelay arb setting for"
                                " %s in Config %s, please update feed url"
                                % (feed.name, vm.vmdata.filename),
                            )

    def test_wip_and_donottot_commands(self):
        """
        Test commands files for WIP and #DO NOT TOT comments and alerts to Sentry if past due date or bad format
        WIP comment format {#WIP YYYYMMDD username}
        DO NOT TOT comment format {#DO NOT TOT UNTIL YYYY-MM-DD }
        :return: alert to syslog is any issues
        """
        from scripts.headlessTipTop import notot_regex
        syslogger = syslogsender.SysLogger()
        current_date = datetime.now()
        wip_regex = r"^#WIP\s(20[12][0-9][01][0-9]{3})\s([a-zA-Z]*)"
        regex_wip = re.compile(wip_regex)
        regex_notot = re.compile(notot_regex)
        for cl in ALL_CLUSTERS:
            for vm in cl.vms:
                short_filename = vm.vmdata.filename.split("/")[-1]
                for regex in [regex_wip, regex_notot]:
                    for comment in vm.vmdata.comments:
                        m = regex.match(comment)
                        if "DO NOT TOT" in comment and regex == regex_notot:
                            self.assertFalse(vm.isCandidate(),
                                             f"Incompatible config - DO NOT TOT set for candidate {vm.vmdata.filename}, candidate VMs always get TOTed. Bartender Never Gets Killed ")
                            self.assertTrue(m.group("date"),
                                            f"Wrong format of comment {comment} file {vm.vmdata.filename}, needs to be #DO NOT TOT UNTIL YYYY-MM-DD")
                            self.assertTrue(datetime.strptime(m.group("date"), '%Y-%m-%d'),
                                            f"Wrong date format of comment {comment} file {vm.vmdata.filename}, needs to be #DO NOT TOT UNTIL YYYY-MM-DD")
                        if "#WIP" in comment and regex == regex_wip:
                            if m:
                                date = m.group(1)
                                wip_date = datetime.strptime(date, "%Y%m%d")
                                username = m.group(2)
                                if (wip_date < current_date) and (
                                        current_date.weekday() == 3
                                ):
                                    # alarm to Sentry on Thursdays only - it's our cleanup day
                                    syslogger.send_message(
                                        "COMMANDS_CHECK: This WIP is past expiration %s, please investigate, tell %s or Shanker"
                                        % (short_filename, username)
                                    )
                            else:
                                syslogger.send_message(
                                    "COMMANDS_CHECK: This WIP comment format wrong in %s, try #WIP YYYYMMDD username"
                                    % short_filename
                                )

    def test_vfx_fixport_commands_enableSymbol(self):
        """
        Test commands files for duplicate entries in enableSymbol commands
        """
        for cl in self.clusters:
            vms = cl.getVmsByCommandRegex(regex="vfx.*FixPort")
            for vm in vms:
                symbols = []
                duplicate = []
                for command in vm.vmdata.commands:
                    if "enableSymbol" in command:
                        symbol = command.split()[1]
                        if symbol not in symbols:
                            symbols.append(symbol)
                        else:
                            duplicate.append(symbol)
                self.assertEqual(
                    [],
                    duplicate,
                    "%s has duplicate symbols %s"
                    % (vm.vmdata.filename, ",".join(x for x in duplicate)),
                )

    def test_unique_gateway_name(self):
        """
        Test commands files for duplicate gateway names, client port names and also intersection
        between gateways and clientports
        For now, unique name only enforced within cluster, as still some duplicates to be cleaned up across clusters
        """
        classes_to_ignore = [
            'com.ewt.applications.matcher.MultiMatcher',
            'mt_cside::applications::matcher::MultiMatcher',
            'mt_cside::applications::gw::fix::equity::lastlook::matchit::MatchItConditionalGateway',
        ]
        from collections import defaultdict
        d_class = defaultdict(int)
        d_all = defaultdict(int)
        for cl in self.clusters:
            d_nm_cl = defaultdict(int)
            vms_gws = cl.getGateways()
            vms_ports = cl.getCounterPartyPorts()
            for vm in vms_gws + vms_ports:
                if vm.classname in classes_to_ignore:
                    continue
                else:
                    d_class[vm.classname + " " + vm.name] += 1
                    d_all[vm.name] += 1
                    d_nm_cl[vm.name] += 1
            for k, v in d_nm_cl.items():
                self.assertTrue(v <= 1, "Gateway+CP name %s been used %s times in %s" % (k, str(v), cl.core))
        for k, v in d_class.items():
            self.assertTrue(v <= 1, 'Duplicate Class + Gateway name -  %s been used %s' % (k, str(v)))
        for k, v in d_all.items():
            # TODO remove this if condition when COP-60419 is done
            if k not in [
                'CSEQ03',
                'CSEQ04',
                'RBCQ01',
                'RBCQ02',
                'MSEQ04',
                'INSE01',
                'MSEQ02',
                'MSEQ03',
                'MSEQ01',
                'MSEQ00',
                'UBSQ01',
                'VALQ01',
                'FSTM01',
                'XENN01',
                'FNCS03',
                'FNCS02',
                'SPTX01',
                'CSAS01',
                'CSAS02',
                'FSTM02',
                'IBKR01',
                'MSFX00',
                'FSTL03',
                'FSTL01',
                'EDGXC2',
                'EDGAC2',
                'BATSC1',
                'BATYC1',
                'EDGXC1',
                'EDGAC1',
                'BATSC2',
                'BATYC2',
                'VLQ100',
                'VLQ101',
                'VLQ300',
                'VLQ351',
                'VLQ600',
                'VLQ601',
                'VLQ651',
            ]:
                self.assertTrue(v <= 1,
                                'Duplicate Gateway+CP name %s been used %s times, choose different name' % (k, str(v)))
            else:
                if v >= 2:
                    print("Gateway+CP name %s been used %s times" % (k, str(v)))

    def test_unique_coreId_targetIp(self):
        """
        Test commands files for duplicate fix target between different missing
        """
        classes_to_ignore = [
            'com.ewt.applications.matcher.MultiMatcher',
            'mt_cside::applications::matcher::MultiMatcher',
            'mt_cside::applications::gw::fix::equity::lastlook::matchit::MatchItConditionalGateway',
        ]
        from collections import defaultdict
        from urllib.parse import urlparse
        d_url = defaultdict(list)
        regex_url = "^/(.*)/setURL apacfix://(.*:.*)\?(.*)"
        for cl in self.clusters:
            s_url_core = set()
            d_nm_cl = defaultdict(int)
            # TODO expand regex below to cover all fix gateway
            vms_gws = cl.getVmsByCommandRegex(
                regex="mt_cside::applications::gw::fix::apac"
            )
            for vm in vms_gws:
                for command in vm.vmdata.commands:
                    if re.match(regex_url, command):
                        url = re.match(regex_url, command)
                        if url.group(2) in s_url_core or "127.0.0.1" in url.group(2):
                            continue
                        else:
                            print(url.group(2))
                            s_url_core.add(url.group(2))
                            d_url[url.group(2)].append(url.group(3) + " " + vm.vmdata.core + " " + vm.vmdata.filename)
        print(d_url)
        for k, v in d_url.items():
            if len(d_url[k]) > 1:
                i = 1
                # tagret IP port in more than one core, checking if we've coreId in the URL
                for url in d_url[k]:
                    if "coreId" in str(url):
                        i += 1
                self.assertTrue(i >= len(d_url[k]),
                                ' Duplicate target IP %s between different cores %s but missing coreId VM' % (k, url))

    def test_single_core_gw_per_host(self):
        """
        Test commands files to make sure we don't run more than 1 core's gw per host based on COP-65043
        This should be a valid test to ensure no mixing of agency and prop gw's
        """

        def get_mold_url(app):
            for command in app.commands:
                matches = ["start", "mold"]
                if all(x in command for x in matches):
                    url = re.split('mold://|:', command)[1]
                else:
                    continue
                url = ".".join(url.split(".")[:-1])
                if url.startswith('239.'): return url

        exceptions = [
            'emu130.cus22.loc',  # https://jira.virtu.com/browse/COP-65043
        ]

        for cl in self.clusters:
            for k, host_vms in cl.cluster_map.items():
                gw_molds = set()
                for k, vm in host_vms.items():
                    if vm.vmdata.host in exceptions: continue
                    for app in vm.apps:
                        if any(x in app.classname for x in ['applications::gw']):
                            mold_url = get_mold_url(app)
                            if mold_url is not None: gw_molds.add(mold_url)
                self.assertTrue(len(gw_molds) <= 1, "Machine has gw's across many mold urls %s" % vm.vmdata.filename)
                # if len(gw_molds) >= 2:
                # print gw_molds
                # print vm.vmdata.filename

    def test_replicators_use_onload(self):
        """
        Test command files for UDPreplicators setup on core002 which has onload disabled
        """
        for core in self.clusters:
            vms = core.getVmsByCommandRegex(
                regex="mt_cside::applications::udpreplicator::UDPreplicator"
            )
            for vm in vms:
                vm_host = vm.vmdata.host.split('.')[0]
                # if vm_host == 'core002':
                #    print vm.vmdata.filename
                self.assertFalse(vm_host == 'core002',
                                 "Move off of core002, UDPreplicator running without onload %s" % vm.vmdata.filename)

    def test_thumpers_commands_ljs(self):
        """
        Test commands files for Thumpers and dumpers to have ljs output enabled
        """
        for cl in self.clusters:
            apps = cl.getAppsByName("DUMPER")
            apps += cl.getAppsByName("STMPR")
            apps += cl.getAppsByName("MTMPR")
            for app in apps:
                self.assertEqual("true", app.get_parameter("ljs"),
                                 "%s need to use ljs=true" % app.vm.vmdata.filename,
                                 )

    def test_boot_same_core_reader(self):
        """
        Test commands files for BootApps to contain same core reader url
        """

        def get_mold_url(app):
            for command in app.commands:
                if "mold://" in command:
                    url = command.split()[1]
                    return url

        for cl in self.clusters:
            vms = cl.getVmsByCommandRegex(regex="mt_cside::applications::misc::BootApp")
            for vm in vms:
                urls = set()
                for app in vm.apps:
                    boot_url = get_mold_url(app)
                    if boot_url is not None:
                        urls.add(boot_url)
                self.assertTrue(len(urls) <= 1, "BootApp has mold urls that are not identical %s" % vm.vmdata.filename)

    def test_unique_app_account(self):
        """
        Test commands files to make sure we don't have duplicat app account in the same core
        """
        self.skipTest("WIP COP-93399")
        ignore_vms = ['BULL01', 'BULLMD']
        ignore_classes = ['com.ewt.applications.relay.Relay', 'com.ewt.applications.relay.StreamerRelayContainer',
                          'mt_cside::applications::capturedemux::CaptureFilter', 'mt_cside::pcap::PcapProcessor',
                          'mt_cside::applications::capturedemux::CaptureDemux', 'mt_cside::applications::aoe::AoeAdmin',
                          'com.ewt.applications.stamper.Stamper', 'mt_cside::quoteserver::QuoteServer',
                          'mt_cside::applications::udpreplicator::UDPreplicator',
                          'mt_cside::applications::corepiper::CorePiper',
                          'com.ewt.tools.corewatcher.CoreWatcherMux',
                          'mt_cside::applications::cmdarbiter::EngineCommandArbiter',
                          'com.ewt.applications.monitor.CrossCorePositionVerifier2', 'com.ewt.dropcopy.fs.App',
                          'com.ewt.quoteserver.servers.glob.GlobRelay', 'com.ewt.quoteserver.QuoteServer',
                          'com.ewt.marketdata.MarketData', 'mt_cside::quoteserver::gap::GapProxy',
                          'mt_cside::applications::corestreamer::CoreStreamer',
                          'mt_cside::applications::orderpriority::cme::CmePriorityServer',
                          'com.ewt.applications.ioi.IOIServer',
                          'mt_cside::applications::timestamp::TimestampStreamManager']
        ignore_apps = ['DCHAND', 'GWDEMUX', 'POSTRACK', 'QUOTES', 'MTMPR', 'STMPR', 'LOADER', 'TOTTER', 'SSERVICE',
                       'USERVICE', 'CORESP', 'GLBPOS', 'METAQUOTE', 'DMHAND', 'MAINT', 'ORPHAN', 'ACKMON', 'GWMON',
                       'ORDERS', 'PRTMON', 'LATMON', 'GREWIND', 'GRELAY', 'STRTRACK', 'T7INJ', 'SLOADER', 'DUMPER',
                       'SGXORDPRIO', 'USERSERVICE', 'ICEPRIOSIF', 'AUTHSERVER', 'ICESYM', 'TUNNEL', 'IOCSTR', 'MOLDSP']
        from collections import defaultdict
        for cl in filtered_vms():
            d_app = defaultdict(int)
            for vm in cl.vms:
                if vm.vmdata.vmname in ignore_vms:
                    continue
                for app in vm.apps:
                    if app.name in ignore_apps or app.classname in ignore_classes:
                        continue
                    else:
                        d_app[app.name] += 1
            for k, v in d_app.items():
                if v > 1:
                    print("fix %s in %s " % (k, cl.core))
                # self.assertTrue(v <= 1, "App account %s been used %s times in %s" % (k, str(v), cl.core))

    def test_debug_enabled(self):
        """
        Test commands files for debug logging enabled
        debug_days defines how long we allow debug to be enabled
        """
        debug_days = 100
        for cl in self.clusters:
            vms = cl.getVmsByCommandRegex("^/INIT/setDebugNamespaceEnabled")
            for vm in vms:
                if "TEST" in vm.vmdata.vmname:
                    continue
                result = check_output(
                    "svn --username release --password %s --no-auth-cache blame %s"
                    % (b64decode("Ymh0cmFkZXI=").decode('ascii'), vm.vmdata.filename), shell=True
                ).decode("ascii").split("\n")
                for line in result:
                    if re.match(r".*\s/INIT/setDebugNamespaceEnabled.*", line):
                        rev = line.split()[0]
                        user = line.split()[1]
                        blame_res = check_output(
                            "svn --username release --password %s --no-auth-cache log -r %s %s"
                            % (b64decode("Ymh0cmFkZXI=").decode('ascii'), rev, vm.vmdata.filename), shell=True
                        ).decode("ascii").split("|")
                        """parsing date from line
                        i.e. 2020-03-11 19:24:11 -0500 (Wed, 11 Mar 2020)"""
                        commit_date = datetime.strptime(blame_res[2].split()[0], "%Y-%m-%d")
                        current_date = datetime.now()
                        diff = current_date - commit_date
                        self.assertFalse(
                            diff.days > debug_days,
                            "%s has been in debug for more than %s days, ask %s if still needed - %s"
                            % (
                                vm.vmdata.filename.split("..")[2],
                                str(diff.days),
                                user,
                                line,
                            ),
                        )

    def test_IGNORE_THIS_VM_age(self):
        """
        Test commands files for IGNORE_THIS_VM
        ignore_days defines how long we allow debug to be enabled
        """
        ignore_days = 30
        for cl in self.clusters:
            vms = cl.getVmsByCommandRegex(r"^#\s*IGNORE_THIS_VM")
            for vm in vms:
                if "TEST" in vm.vmdata.vmname:
                    continue
                result = check_output(
                    "svn --username release --password %s --no-auth-cache blame %s"
                    % (b64decode("Ymh0cmFkZXI=").decode('ascii'), vm.vmdata.filename), shell=True
                ).decode("ascii").split("\n")
                for line in result:
                    if re.search(r"#\s*IGNORE_THIS_VM", line):
                        rev = line.split()[0]
                        user = line.split()[1]
                        blame_res = check_output(
                            "svn --username release --password %s --no-auth-cache log -r %s %s"
                            % (b64decode("Ymh0cmFkZXI=").decode('ascii'), rev, vm.vmdata.filename), shell=True
                        ).decode("ascii").split("|")
                        """parsing date from line
                        i.e. 2020-03-11 19:24:11 -0500 (Wed, 11 Mar 2020)"""
                        commit_date = datetime.strptime(blame_res[2].split()[0], "%Y-%m-%d")
                        current_date = datetime.now()
                        diff = current_date - commit_date
                        self.assertFalse(
                            diff.days > ignore_days,
                            "%s has been in IGNORE_THIS_VM for more than %s days, ask %s if still needed - %s"
                            % (
                                vm.vmdata.filename.split("..")[2],
                                str(diff.days),
                                user,
                                line,
                            ),
                        )

    def test_cme_snapshot(self):
        """
        Test cme feeds to make sure they have snapshot configured
        """
        vms_to_skip = ["CMESPINDX", "CMEBLOCKSTR", "CMEMCEURT"]
        for cl in self.clusters:
            vms = cl.getVmsByCommandRegex(
                regex="mt_cside::quoteserver::feeds::cme::CmeMdpFeed"
            )
            for vm in vms:
                if any(vm.vmdata.vmname in x for x in vms_to_skip):
                    continue
                for app in vm.apps:
                    for key, feed in app.feeds.items():
                        for command in feed.commands:
                            if "/QUOTES/newFeed" in command:
                                self.assertTrue(
                                    "snapshot=" in command,
                                    "This feed %s is missing snapshot config %s"
                                    % (feed.name, vm.vmdata.filename),
                                )

    def my_filtered_quotes_vms(self):
        """

        :return:
        """
        for vms in self.clusters:
            for vm in vms.get_vms():
                if vm.getQuotes():
                    yield vm

    def test_QED_commands(self):
        """
        Test commands files QED symbols to be identical
        """
        qed_symbols = None
        symbols = None
        vms = list(self.my_filtered_quotes_vms())
        for vm in vms:
            if "CME" in vm.vmdata.filename:
                for command in vm.vmdata.commands:
                    if "includeSymbols" in command:
                        symbols = command.split()[1]
                        if qed_symbols is None:
                            qed_symbols = symbols
                    if "excludeSymbols" in command:
                        symbols = "".join(
                            x.split("=")[1]
                            for x in command.split()
                            if "excludeSymbols" in x
                        )
                        if qed_symbols is None:
                            qed_symbols = symbols
                self.assertEqual(
                    qed_symbols,
                    symbols,
                    "%s QED symbols are not correct" % vm.vmdata.filename,
                )

    def test_OSESIF_commands(self):
        """
        Test commands files OSE SIF symbols are valid
        """
        osesif_symbol = None
        ose_sif_symbol_regex = r"([A-Z]{2,3}:[A-Z0-9]{3})([A-Z])(\d{1})"
        osesif_valid_symbols = ['OSE:NM2', 'OSE:NK2', 'OSE:NM4', 'TF:TPX', 'TF:JGB']
        osesif_valid_months = ['H', 'M', 'U', 'Z']
        vms = list(self.my_filtered_quotes_vms())
        for vm in vms:
            if "OSESIF" in vm.vmdata.filename:
                for command in vm.vmdata.commands:
                    if "setSymbolConfig" in command:
                        osesif_symbol = re.search(ose_sif_symbol_regex, command.split()[1])
                        if osesif_symbol:
                            self.assertTrue((osesif_symbol.group(1) in osesif_valid_symbols),
                                            "%s not a valid OSE SIF symbol in %s" % (
                                                osesif_symbol.group(1), vm.vmdata.filename))
                            self.assertTrue((osesif_symbol.group(2) in osesif_valid_months),
                                            "%s not a valid OSE SIF symbol in %s" % (
                                                osesif_symbol.group(1), vm.vmdata.filename))

    def test_check_candidates_gws(self):
        """
        Test commands files if gateway classes have Candidate VMs setup
        use min_class_inst to define minimum instances for a class to have Candindate gw
        """
        min_class_inst = 2
        processed_classes = defaultdict(dict)
        for cl in self.clusters:
            for app in cl.getGateways():
                if any(x in app.__class__.__name__ for x in ["Gateway"]):
                    if app.classname in processed_classes.keys():
                        processed_classes[app.classname]["count"] += 1
                        processed_classes[app.classname]["core"].add(cl.core)
                        processed_classes[app.classname]["vms"].add(app.vm)
                    if (app.classname not in self.candi_classes) and (
                            app.classname not in processed_classes.keys()
                    ):
                        processed_classes[app.classname]["count"] = 1
                        processed_classes[app.classname]["core"] = set()
                        processed_classes[app.classname]["vms"] = set()
                        processed_classes[app.classname]["vms"].add(app.vm)
                        processed_classes[app.classname]["core"].add(cl.core)

        # filtering single-class vms
        for class_name, value in processed_classes.items():
            if value["count"] >= min_class_inst and len(value["vms"]) > 1:
                # print(class_name + " ! " + str(value["core"]) + " ! Apps:" + str(value["count"])+" ! VMs: " + str(len(value['vms'])))
                self.assertTrue(
                    class_name in self.candi_classes,
                    "Please add candidate gw for class %s in %s, App_count=%s, VM_count=%s"
                    % (class_name, str(value["core"]), str(value["count"]), str(len(value["vms"])))
                )

    def test_check_candidates_feeds(self):
        """
        Test commands files if feed classes have Candidate VMs setup
        use min_class_inst to define minimum instances for a class to have Candindate gw
        """
        min_class_inst = 2
        processed_classes = defaultdict(dict)
        for cl in self.clusters:
            for vm in cl.vms:
                for app in vm.apps:
                    if any(x in app.classname for x in ["QuoteServer"]):
                        for f, fval in app.feeds.items():
                            if fval.classname in processed_classes.keys():
                                processed_classes[fval.classname]["count"] += 1
                                processed_classes[fval.classname]["core"].add(cl.core)
                                processed_classes[fval.classname]["vms"].add(app.vm)
                            if (fval.classname not in self.candi_classes) and (
                                    fval.classname not in processed_classes.keys()
                            ):
                                processed_classes[fval.classname]["count"] = 1
                                processed_classes[fval.classname]["vms"] = set()
                                processed_classes[fval.classname]["vms"].add(app.vm)
                                processed_classes[fval.classname]["core"] = set()
                                processed_classes[fval.classname]["core"].add(cl.core)

        # filtering single-class vms
        for class_name, value in processed_classes.items():
            if value["count"] >= min_class_inst and len(value["vms"]) > 1:
                # print(class_name + " ! " + str(value["core"]) + " ! Apps:" + str(value["count"])+" ! VMs: " + str(len(value['vms'])))
                self.assertTrue(
                    class_name in self.candi_classes,
                    "Please add candidate feed for class %s in %s, app_count=%s, VM_count=%s"
                    % (class_name, str(value["core"]), str(value["count"]), str(len(value["vms"])))
                )

    def test_circular_mem_param(self):
        """
        Ensure useMemoryStore and memoryStoreSize are set on TimestampStreamManager apps
        """
        vms_to_skip = ["OIUPLOADER"]
        for cl in self.clusters:
            vms = cl.getVmsByCommandRegex(
                regex="mt_cside::applications::timestamp::TimestampStreamManager.*"
            )
            for vm in vms:
                if any(vm.vmdata.vmname in x for x in vms_to_skip):
                    continue
                for command in vm.vmdata.commands:
                    if "mt_cside::applications::timestamp::TimestampStreamManager" in command:
                        self.assertTrue(
                            "useMemoryStore=circular" in command,
                            "This app %s is missing useMemoryStore=circular config %s"
                            % (vm.vmdata.vmname, vm.vmdata.filename),
                        )
                        self.assertTrue(
                            "memoryStoreSize=" in command,
                            "This app %s is missing memoryStoreSize config %s"
                            % (vm.vmdata.vmname, vm.vmdata.filename),
                        )

    def test_purge_gw_hgcon(self):
        """
        Ensure purge gw's only use hgcon 0-7
        """
        self.skipTest("Need APAC to look into")
        from urllib.parse import urlparse
        for cl in self.clusters:
            gws = cl.getGateways()
            for gw in gws:
                for command in gw.commands:
                    if "supportsMassCancel=true" in command:
                        url = urlparse(gw.url)
                        if "hgcon" in command:
                            hgcon_num = int(command.split('hgcon=')[1].split('&')[0])
                            self.assertTrue(
                                hgcon_num in range(8),
                                "This gw %s is assigned an invalid hgcon %s, must be between 0-7"
                                % (gw, hgcon_num),
                            )
                        elif "hgcon" in url.query:
                            hgcon_num = int((url.query).split('hgcon=')[1].split('&')[0])
                            self.assertTrue(
                                hgcon_num in range(8),
                                "This gw %s is assigned an invalid hgcon %s, must be between 0-7"
                                % (gw, hgcon_num),
                            )

    def test_single_nlobrelay_per_host(self):
        """
        Test commands files to make sure we don't run more than 1 nlobrelay per host based on CORE-22533
        Also tests if we have nlob feed and nlob relay configured on the same numa node
        Also checks for nlobconfig, ie. we can run non-options feeds along with options nlobrelay, since it does not
        subscribe to these feeds
        """
        numa_calc = lambda x: x % 2
        for cl in self.clusters:
            for k, host_vms in cl.cluster_map.items():
                nlobrelay_count = 0
                used_numas_nlob = set()
                used_numas_qs = set()
                for k, vm in host_vms.items():

                    for app in vm.apps:
                        if any(x in app.classname for x in ['glob.GlobRelay']):
                            nlobrelay_count += 1
                            nlobconfig = app.get_parameter("globConfig")
                            used_numas_nlob.add((numa_calc(vm.vmdata.mux), nlobconfig))
                        if any(x in app.classname for x in ['QuoteServer']) \
                                and vm.vmdata.appGroup == "protected" \
                                and 'nlob' in app.publishers:
                            if app.nlobconfig:
                                used_numas_qs.add((numa_calc(vm.vmdata.mux), app.nlobconfig))
                            else:
                                used_numas_qs.add((numa_calc(vm.vmdata.mux), 'nlob'))

                self.assertTrue((nlobrelay_count <= 2),
                                "Too many NLOBRELAYs on %s, can have only 1 per NUMA" % vm.vmdata.host)
                if nlobrelay_count > 1 and len(used_numas_nlob) == 1:
                    test = set([x[0] for x in used_numas_nlob])
                    self.assertTrue(len(test) == 2,
                                    "NLOBRELAYs share same Numa on %s" % vm.vmdata.host)
                self.assertFalse((used_numas_nlob & used_numas_qs),
                                 "Feeds and NLOBRELAYs share same Numa on %s" % vm.vmdata.host)

    def test_check_protected_classes_have_catcha(self):
        """
        Test commands files if protected classes vms have catcha protected flag
        """
        protected_classes = [
            'mt_cside::quoteserver::feeds::nysearca::XdpIntegratedFeed',
            'mt_cside::quoteserver::feeds::itto::IttoFeed',
            'mt_cside::quoteserver::feeds::chix::ChicFeed',
            'mt_cside::quoteserver::feeds::iex::IexDeepFeed',
            'mt_cside::quoteserver::feeds::itch::ItchFeed50',
            'mt_cside::quoteserver::feeds::bats::PitchOptionsFeed',
            'mt_cside::quoteserver::feeds::mxpo::MxpoPlfFeed',
            'mt_cside::quoteserver::feeds::bats::PitchFeed',
            'mt_cside::quoteserver::feeds::opra::OpraFeed',
            'mt_cside::quoteserver::feeds::itto4::Itto4Feed',
            'com.ewt.quoteserver.feeds.tsx.TsxFeed2',
            'mt_cside::quoteserver::feeds::cqct::CqsFeed',
            'mt_cside::quoteserver::feeds::cqct::CtsFeed',
            'mt_cside::quoteserver::feeds::uqut::UtdfFeed',
            'mt_cside::quoteserver::feeds::uqut::UqdfFeed',
            'mt_cside::quoteserver::feeds::tsx::TsxQuantumFeed',
            'mt_cside::quoteserver::feeds::neo::NeoFeed',
            'mt_cside::quoteserver::feeds::omega::OmegaFeed',
            'mt_cside::quoteserver::feeds::pure::CseMultiFeed',
            'mt_cside::quoteserver::feeds::nysearca::options::XdpOptionsFeed'
        ]
        hosts_to_skip = ['vcap']
        vms_to_skip = ['TEST']
        for cl in self.clusters:
            vms = cl.getVmsByCommandRegex(regex="quoteserver")
            for vm in vms:
                host = vm.vmdata.host
                if any(x in host for x in hosts_to_skip):
                    continue
                if any(x in vm.vmdata.vmname for x in vms_to_skip):
                    continue
                for app in vm.apps:
                    if hasattr(app, 'feeds'):
                        for key, feed in app.feeds.items():
                            if feed.classname and any(x == feed.classname for x in protected_classes):
                                if vm.vmdata.appGroup != "protected":
                                    # print "VM is running protected class and missing protected catcha flag: %s" % vm.vmdata.filename
                                    self.assertEqual("protected", vm.vmdata.appGroup,
                                                     "VM is running protected class and missing protected catcha flag: %s" % vm.vmdata.filename)

    def test_catcha_core_match(self):
        ignore_cores = ['mum01']
        all_exceptions = list()
        for vm in self.my_filtered_vms():
            if vm.vmdata.catchaCore in ignore_cores:
                continue
            try:
                self.assertEqual(vm.core, vm.vmdata.catchaCore)
                self.assertEqual("catcha", vm.vmdata.catchaName)
            except AssertionError as e:
                all_exceptions.append(
                    ["catcha mis-match for %s %s" % (vm.vmdata.filename, str(e))]
                )
        if all_exceptions:
            for e in all_exceptions:
                print(e)
            raise AssertionError(all_exceptions)

    def test_catchamux_config(self):
        """ensure catchamux config is same for all instances"""

        def parse_line(line, result_dict):
            if 'addCore' in line:
                pieces = line.split()
                remote_core = pieces[1]
                address = pieces[2]
                result_dict[vm.vmdata.filename][remote_core] = address

        catcha_dict = defaultdict(dict)
        catcha_atlas_dict = defaultdict(dict)
        for vm in self.my_filtered_vms():
            vm_name = vm.vmdata.vmname
            if ('CATCHAMUX' in vm_name) \
                    and not ('ATLAS' in vm_name) \
                    and not ('UAT' in vm_name):
                for line in vm.vmdata.commands:
                    parse_line(line, catcha_dict)
            elif ('CATCHAMUX' in vm_name) \
                    and ('ATLAS' in vm_name) \
                    and not ('UAT' in vm_name):
                for line in vm.vmdata.commands:
                    parse_line(line, catcha_atlas_dict)

        for k, v in catcha_dict.items():
            for core, address in v.items():
                self.assertEqual(
                    {True}, set([address == catcha_dict[c][core] for c in catcha_dict.keys()]),
                    "Core %s %s is not configured identically for all CATCHAMUXes" % (core, address)
                )
        for k, v in catcha_atlas_dict.items():
            for core, address in v.items():
                self.assertEqual(
                    {True}, set([address == catcha_atlas_dict[c][core] for c in catcha_atlas_dict.keys()]),
                    "Core %s %s is not configured identically for all CATCHAMUXATLASes" % (core, address)
                )

    def test_time_threshold_configs(self):
        """
        Test threshold configs are setup as such and not using commands
        """
        feed_apps = ['QuoteServer']
        comms_to_look_for = ['setLagThreshold', 'setSilentThreshold', 'setLagPadding', 'setClockAheadThreshold',
                             'setLagCheck']
        ignore_vms = ['VMDRELAY2', 'VMDRELAY1', 'BULL01', 'BULLMD']
        for cl in filtered_vms():
            for vm in cl.vms:
                if vm.vmdata.vmname in ignore_vms:
                    continue
                for app in vm.apps:
                    if any(x in app.classname for x in feed_apps):
                        for command in app.commands:
                            if any(x in command for x in comms_to_look_for) and not command.startswith('#'):
                                self.assertEqual(vm.vmdata.vmname,
                                                 "Following feed has Threshold settings defined in commands: %s" % vm.vmdata.filename)

    def get_all_cores_with_break_check_comparision(self):
        """
        This function will get all cores that have drip reader / break check comparision set
        :return:
        """
        drop_copy_core = "nob14"
        all_cores_with_drip_reader = []
        cl = cluster.get_cluster_by_name(drop_copy_core, coreops_commands_path=COREOPS_COMMANDS_PATH)
        cl.initApps(logErrorsOnly=True)
        all_break_check_dropcopy_vms = cl.getAppsByClass("com.ewt.fs.reconciliation.realtime.RealtimeBreakCheck")
        for drop_copy_vm in all_break_check_dropcopy_vms:
            drip_reader_regex = r"^/{instance}/addDripReader\s+DRIP\s+(.*?)\s+".format(instance=drop_copy_vm.name)
            for line in drop_copy_vm.commands:
                match = re.match(drip_reader_regex, line)
                if match:
                    core = match.group(1)
                    all_cores_with_drip_reader.append(core)
        return all_cores_with_drip_reader

    def test_if_cores_with_Engine_have_break_check_comparision(self):
        """ This function will check if the cores with Engine, also have break check
        comparision / addDripReader set in nob14 i.e drop copy core"""

        all_cores_with_break_check_comparision = self.get_all_cores_with_break_check_comparision()
        exclude_list = [
            "cus99",
            "nob28",
            "teq21"  # WIP
        ]
        for cl in self.clusters:
            if cl.core in exclude_list or isAtlasCore(cl.core):
                continue
            try:
                primary_engine = cl.getUniqueVm("CENGINE").getUniqueAppByName('ENGINE')
            except CoreopsError as e:
                print("Cannot get ENGINE for {core}: {error}".format(core=cl.core, error=e))
                continue
            self.assertTrue(all_cores_with_break_check_comparision.count(primary_engine.core.upper()) > 0,
                            " Core {core} has Engine but no break check/drip reader set".format(
                                core=primary_engine.core))

    def test_engine_failover_multicastGroups(self):
        """
        Ensures that Engine and Failover have the same addMulticastGroup commands - COP-48413
        """
        for cl in filtered_vms():
            if isAtlasCore(cl.core):
                continue

            try:
                f_eng = cl.getUniqueVm("FAILOVER").getUniqueAppByName('FAILOVER')
                p_eng = cl.getUniqueVm("CENGINE").getUniqueAppByName('ENGINE')
            except CoreopsError as e:
                print('Cannot get FAILOVER and/or ENGINE for {0:s}'.format(cl.core))
                continue

            mcast_grp_com_regexp = r"addMulticastGroup\s+([0-9\.]+)"

            mcast_grp_primary = []
            for com in p_eng.commands:
                m = re.search(mcast_grp_com_regexp, com)
                if m:
                    mcast_grp_primary.append(m.group(1))

            mcast_grp_failover = []
            for com in f_eng.commands:
                m = re.search(mcast_grp_com_regexp, com)
                if m:
                    mcast_grp_failover.append(m.group(1))
            sym_diff = set(mcast_grp_primary).symmetric_difference(set(mcast_grp_failover))
            self.assertTrue(len(sym_diff) == 0,
                            'Engine and Failover in %s do not listen to the same multicast groups. Issue with %s' % (
                                cl.core, sym_diff))

    def test_init_servers(self):
        """
        COP-70269 - Ensures that all VMs have a text, http nd catcha port
        Exceptions: Engine should not have a catcha port
        """
        for cl in filtered_vms():
            for vm in cl.vms:

                if vm.vmdata.vmname != 'CENGINE':
                    self.assertTrue(vm.vmdata.catchaName,
                                    '{} in {} missing catcha'.format(vm.vmdata.vmname, vm.vmdata.host))

                self.assertTrue(vm.vmdata.hasHttp,
                                '{} in {} missing http port'.format(vm.vmdata.vmname, vm.vmdata.host))

                self.assertTrue(vm.vmdata.hasText,
                                '{} in {} missing text port'.format(vm.vmdata.vmname, vm.vmdata.host))

    def test_shortname_service(self):
        """
        COP-72223 - ShortnameService is required if gatewayTags or idTag is specified in the config.
        """
        regex_sservice = "/INIT/newCApp mt_cside::applications::common::ShortnameService SSERVICE"
        regex_gatewaTags = "^[^#].*gatewayTags="
        regex_idTag = "^[^#].*idTag="
        regex_xrefTag = "^[^#].*xrefTag="
        for cl in filtered_vms():
            for vm in cl.vms:
                has_sservice = False
                needs_sservice = False
                for line in vm.vmdata.commands:
                    if re.match(regex_sservice, line):
                        has_sservice = True
                    if re.match(regex_gatewaTags, line) or re.match(regex_idTag, line) or re.match(regex_xrefTag, line):
                        needs_sservice = True
                self.assertFalse(needs_sservice and not (has_sservice), "{} needs SSERVICE".format(vm.vmdata.vmname))

    def test_ndf(self):
        NDF_regex = re.compile('enableNDF=true')
        badvms = []
        is_ndf_port = [1, 1]
        for cl in filtered_vms():
            vms = cl.get_vms()
            NDF_vms = []
            for vm in vms:
                for command in vm.vmdata.commands:
                    if NDF_regex.search(command):
                        NDF_vms.append(vm)
                for vm in NDF_vms:
                    for command in vm.vmdata.commands:
                        if not NDF_regex.search(command) and 'VfxFixPort' in command:
                            is_ndf_port[0] = 0
                        if not NDF_regex.search(command) and 'vfxswapmd' in command:
                            is_ndf_port[1] = 0
                        if 0 in is_ndf_port:
                            badvms.append(vm)
            self.assertFalse(len(badvms),
                             "The following VMS have NDF enabled not in both gateway and the feed " + ", ".join(
                                 [v.vmdata.vmname for v in set(badvms)]))

    def test_blpapi(self):
        regex_blpapi = "/QUOTES/newFeed mt_cside::quoteserver::feeds::blpapi::BloombergFeed .* useBpipe=true"
        regex_blpapi_mux = "/QUOTES/newFeed mt_cside::quoteserver::feeds::blpapi::BloombergFeed .* pollerCpuSet=([a-z]*[0-9]* )(.*)"
        for cl in filtered_vms():
            for vm in cl.vms:
                for line in vm.vmdata.commands:
                    if re.match(regex_blpapi, line):
                        mux = re.match(regex_blpapi_mux, line)
                        if mux:
                            self.assertTrue(mux.group(1).startswith("other"),
                                            "Bad pollerCpuSet for {} ".format(vm.vmdata.vmname))
                        else:
                            self.assertFalse(True, "Missing pollerCpuSet for {} ".format(vm.vmdata.vmname))

    def test_clearing_ids(self):
        NDF_regex = re.compile('enableNDF=true')
        clearing_regex1 = re.compile(r'setClearingId [^Jb]')
        clearing_regex2 = re.compile(r'setClientClearingId \w* [Jb]')
        failing_vms = []
        for cl in filtered_vms():
            vms = cl.get_vms()
            NDF_enabled_vms = []
            for vm in vms:
                for command in vm.vmdata.commands:
                    if NDF_regex.search(command):
                        NDF_enabled_vms.append(vm)
            for vm in NDF_enabled_vms:
                for command in vm.vmdata.commands:
                    if clearing_regex1.search(command):
                        if not vm.vmdata.vmname in failing_vms:
                            failing_vms.append(vm)
            for vm in failing_vms:
                for command in vm.vmdata.commands:
                    if clearing_regex2.search(command):
                        failing_vms = [v for v in failing_vms if v != vm]
            self.assertFalse(len(failing_vms),
                             "The following VMS have NDF enabled, but do not have clearingId or clientClearingId set to J (SocGen) or b (BNP): " + ", ".join(
                                 [v.vmdata.vmname for v in set(failing_vms)]))


@pytest.mark.integtest
class TestQuoteConfigs(unittest.TestCase):
    """
    group quotes tests together
    """

    def setUp(self):

        # some cores to ignore - just during dev testing
        self.my_ignored_clusters = ["sto08"]

        self.gvms = list(self.my_filtered_vms())

        self.sbijfeed_class = "mt_cside::quoteserver::feeds::sbij::SbijItchFeed"

        self.sbij_group_venue_map = {'SBIJ': 'DAY',
                                     'SBIN': 'NGHT',
                                     'SBIX': 'DAYX',
                                     'SBIR': 'DAYX',
                                     'SBIU': 'DAYU'}

        self.sbij_group_glimpse_user_map = {'DAY': ('IBAR05', 'nTZTrXPKaZ'),
                                            'DAYX': ('IBARX2', 'kv5QnpTPch'),
                                            'DAYU': ('IBARU2', '5mBYReh96A'),
                                            'NGHT': ('IBARN2', 'fRjsuZaZpG')}

        self.sbij_group_glimpse_port_map = {'DAY': '11015',
                                            'DAYX': '11016',
                                            'DAYU': '11017',
                                            'NGHT': '11018'}

        self.sbij_group_glimpse_url = 'core002.tyo04.loc'

        self.blank_glimpse_config = 'url=mold64arbiting.*blankGlimpseSession=true'

        self.glimpse_simple_regexp = 'glimpseUrl'

        self.comment_regexp = r"^\s*#"

    def my_filtered_vms(self):
        """

        :return:
        """
        for vms in filtered_vms():
            for vm in vms.get_vms():
                if vm.vmdata.core in self.my_ignored_clusters:
                    continue
                if vm.getQuotes():
                    yield vm

    def get_sbij_feeds(self):

        for vm in self.gvms:
            for q in vm.getQuotes():
                for f in q.feeds.values():
                    if f.classname == self.sbijfeed_class:
                        yield f

    def get_group(self, cmds):
        groups = []
        group_regexp = 'group=([A-Z]*)'
        for c in cmds:
            m = re.search(group_regexp, c)
            if m:
                groups.append(m.group(1))
        return groups

    def find_in_commands(self, cmds, reg_exp_in):

        for c in cmds:
            m = re.search(reg_exp_in, c)
            if m and not re.match(self.comment_regexp, c):
                return True
        return False

    def get_glimpse(self, cmds):
        glimpse = {}
        glimpse_regexp = r'glimpseUrl=soupbin:\/\/([0-9A-Za-z]+):([0-9A-Za-z]+)@([a-z0-9\.]+):([0-9]+)'
        for c in cmds:
            m = re.search(glimpse_regexp, c)
            if m and len(m.groups()) == 4:
                glimpse['username'] = m.group(1)
                glimpse['password'] = m.group(2)
                glimpse['target'] = m.group(3)
                glimpse['port'] = m.group(4)
                break
        return glimpse

    def get_new_feed_cmds(self, cmds):
        newFeed_regex = r'newFeed.*'
        newfeeds_cmds = []
        for c in cmds:
            m = re.search(newFeed_regex, c)
            if m and not re.match(self.comment_regexp, c):
                newfeeds_cmds.append(c)
        return (newfeeds_cmds)

    def get_channelApp(self, cmd):
        channelApp_regexp = r'channelApp=(\S+)'
        m = re.search(channelApp_regexp, cmd)
        if m and not re.match(self.comment_regexp, cmd) and len(m.groups()) == 1:
            return (m.group(1))

    def get_instrumentApp(self, cmd):
        instrumentApp_regexp = r'instrumentApp=(\S+)'
        m = re.search(instrumentApp_regexp, cmd)
        if m and not re.match(self.comment_regexp, cmd) and len(m.groups()) == 1:
            return m.group(1)

    def is_relay(self, a):
        relay_class_regexp = "mt_cside::quoteserver::feeds::.*Slob"
        for c in a.commands:
            if re.search(relay_class_regexp, c) and not re.match(self.comment_regexp, c):
                return True
        return False

    def test_agency_feed_not_candidate(self):
        """
        COP-35669 / COP-130899
        :return: bool
        """
        for vm in self.gvms:
            if re.search("agency", vm.vmdata.appGroup):
                if 'TIER1' not in vm.vmdata.vmname:
                    self.assertFalse(
                        vm.vmdata.candidate,
                        "agency ({1:s}) VM {0:s} with feed cannot be candidate".format(
                            vm.vmdata.vmname, vm.vmdata.appGroup
                        ),
                    )

    def test_agency_tier1_feed_is_candidate(self):
        """
        COP-130899
        :return: bool
        """
        for vm in self.gvms:
            if re.search("agency", vm.vmdata.appGroup):
                if 'TIER1' in vm.vmdata.vmname:
                    self.assertTrue(
                        vm.vmdata.candidate,
                        "agency ({1:s}) Tier1 VM {0:s} with feed should be candidate".format(
                            vm.vmdata.vmname, vm.vmdata.appGroup
                        ),
                    )

    def test_sbijfeed_group(self):
        """
        Ensure group and venue match for sbij feed  - COP-51917
        Also verify there is a unique group and venue defined in sbijFeedd
        """
        for f in self.get_sbij_feeds():
            fname = os.path.basename(f.quotes.vm.vmdata.filename)
            grps = self.get_group(f.commands)
            vns = list(f.venues)

            self.assertTrue(len(vns) == 1,
                            "{0:d} venue(s) defined for sbij feed in {1:s}, should be 1".format(len(vns), fname))
            self.assertTrue(len(grps) == 1,
                            "{0:d} groups(s) defined for sbij feed in {1:s}, should be 1".format(len(grps), fname))
            self.assertTrue(grps[0] == self.sbij_group_venue_map[vns[0]],
                            'group ({0:s}) does not match venue ({1:s}) for sbijfeed in {2:s}, should be {3:s}'.format(
                                grps[0], vns[0], fname, self.sbij_group_venue_map[vns[0]]))

    def test_sbijfeed_glimpse(self):
        """
        Ensure the correct glimpse session for SbijItchFeed markets - COP-51917
        on SBI, feeds for J, X/R and U markets use different glimpse proxy/address
        """
        for f in self.get_sbij_feeds():
            fname = os.path.basename(f.quotes.vm.vmdata.filename)
            if 'UAT' in fname:
                continue

            self.assertTrue(self.find_in_commands(f.commands, self.glimpse_simple_regexp),
                            "SbiItchFeed in {0:s} does not have a glimpse - it should".format(fname))

            if self.find_in_commands(f.commands, self.glimpse_simple_regexp):
                glimpse = self.get_glimpse(f.commands)
                grp = self.get_group(f.commands)[0]

                self.assertTrue(glimpse, "Glimpse definition for SbijItchFeed in {0:s} is erroneous".format(fname))

                self.assertTrue(self.get_group(f.commands),
                                "SbijItchFeed in {0:s} is missing the group config".format(fname))

                self.assertTrue(self.find_in_commands(f.commands, self.blank_glimpse_config),
                                "SbijItchFeed in {0:s} has a glimpse but misses {1:s} config".format(fname,
                                                                                                     self.blank_glimpse_config))

                self.assertTrue(glimpse['username'] == self.sbij_group_glimpse_user_map[grp][0],
                                'Glimpse username ({0:s}) does not match the group ({1:s}) for {2:s},'
                                ' make sure you use the right proxy'.format(glimpse['username'], grp, fname))

                self.assertTrue(glimpse['password'] == self.sbij_group_glimpse_user_map[grp][1],
                                'Glimpse password ({0:s}) does not match the group ({1:s}) for {2:s},'
                                ' make sure you use the right proxy'.format(glimpse['password'], grp, fname))

                self.assertTrue(glimpse['port'] == self.sbij_group_glimpse_port_map[grp],
                                'Glimpse port ({0:s}) does not match the group ({1:s}) for {2:s},'
                                ' make sure you use the right proxy port'.format(glimpse['port'], grp, fname))

                self.assertTrue(glimpse['target'] == self.sbij_group_glimpse_url,
                                'Glimpse target url ({0:s}) is not ,'
                                ' make sure you use the right proxy port'.format(glimpse['port'], grp, fname))

    def test_nlobchannel_spin_cores_feed_config(self):
        """
        COP-61610
        :return: bool
        """
        add_nlob_regex = r"addServer\s+nlob"
        for vm in self.gvms:
            if is_nlob_spin_core(vm.vmdata.core):
                for ap in vm.apps:
                    if self.find_in_commands(ap.commands, add_nlob_regex):
                        for new_feed_cmd in self.get_new_feed_cmds(ap.commands):
                            inst_target = self.get_instrumentApp(new_feed_cmd)
                            chan_target = self.get_channelApp(new_feed_cmd)

                            expected_target = "instruments.venue.{0:s}.loc".format(vm.vmdata.core)
                            if chan_target:
                                self.assertTrue(re.search(expected_target, chan_target),
                                                'Expected channelApp={0:s} but got {1:s} for {2:s} in {3:s} ({4:s})'.format(
                                                    expected_target,
                                                    chan_target,
                                                    ap.name,
                                                    os.path.basename(
                                                        vm.vmdata.filename),
                                                    vm.vmdata.core))


                            elif inst_target:
                                self.assertTrue(re.search(expected_target, inst_target),
                                                'Expected instrumentApp={0:s} but got {1:s} for {2:s} in {3:s} ({4:s})'.format(
                                                    expected_target,
                                                    inst_target,
                                                    ap.name,
                                                    os.path.basename(
                                                        vm.vmdata.filename),
                                                    vm.vmdata.core))
                            else:
                                self.assertFalse(self.is_relay(ap),
                                                 "{0:s} in {1:s} ({2:s}) is a relay feed, but neither channelApp nor instrumentApp are specified".format(
                                                     ap.name, os.path.basename(vm.vmdata.filename), vm.vmdata.core))


class GatewayTestUtils():
    def set_common_constants(self):
        self.gw_class = "mt_cside::applications::gw::"
        self.gwdemux_class = "mt_cside::applications::gw::GatewayDemux"
        self.postrack_class = "mt_cside::applications::gw::PositionTracker"
        self.DMHandler_class = "mt_cside::applications::gw::DirectMessageHandler"
        self.order_delayer_class = "mt_cside::applications::gw::OrderDelayer"
        self.MultiDMHandler_class = (
            "mt_cside::applications::gw::MultiDirectMessageHandler"
        )

        self.OmBoltTunnelAdmin_class = (
            "mt_cside::applications::gw::om::lite::OmBoltTunnelAdmin"
        )

        self.SgxOuchObo_class = (
            "mt_cside::applications::gw::genium::sgx::SgxOuchOboGateway"
        )
        self.MlArrowObo_class = "mt_cside::applications::gw::tse::MlArrowheadOboGateway"
        self.ArrowObo_class = "mt_cside::applications::gw::tse::ArrowheadOboGateway"
        self.SbijOboOuch_class = (
            "mt_cside::applications::gw::sbij::MLSbijOboOuchGateway"
        )
        self.Sbij2OboToken_class = "mt_cside::applications::gw::sbij2::MLSbijOboTokenGateway"
        self.SbijOboToken_class = "mt_cside::applications::gw::sbij::MLSbijOboTokenGateway"
        self.JpxLiteObo_class = "mt_cside::applications::gw::om::lite::JpxLiteOboGateway"
        self.JpxOuchObo_class = "mt_cside::applications::gw::genium::jpx::JpxOuchOboGateway"

        self.JpxLite_class = "mt_cside::applications::gw::om::lite::JpxLiteGateway"

        self.XetraObo_class = "mt_cside::applications::gw::xetra::XetraEtiOboGateway"
        self.NiteFix_class = "mt_cside::applications::gw::fix::equity::NiteFixGateway"
        self.CrnxOuch_class = "mt_cside::applications::gw::crnx::CrnxOuchGateway"
        # TODO: remove NYSEUTP line below once all NYSE UTP GWs are gone
        self.NYSEUTPGW_class = "mt_cside::applications::gw::nyse::NyseUtpGateway"
        self.CmeGateway_class = "mt_cside::applications::gw::cme::CmeGateway"

        self.validation_regex_1 = re.compile(
            r"___/GWDEMUX/start mold.*___/POSTRACK/start gwdemux://\s*___"
        )
        _gwdemux_regex = r"/GWDEMUX/start.*(mold://\d{3}\.\d{3}.\d{1,3}\.\d{1,3}:|spice)"
        self.gwdemux_regex = re.compile(_gwdemux_regex)
        self.bootapp_regex = re.compile("/start bootApp=true.*mold://239")
        _postrack_regex_1 = "/POSTRACK/start"
        self.postrack_regex_2 = re.compile(_gwdemux_regex + ".*" + _postrack_regex_1)
        self.postrack_regex_3 = re.compile(_postrack_regex_1 + " gwdemux://")

        # some cores to ignore - just during dev testing
        self.my_ignored_clusters = []

        # Duplicated urls:
        #   - we use the same broker to connect to DCE and ZCE and they only provide us with one target url/port
        self.duplicated_urls = ['100109126:147359@172.31.39.69:44505']

        # ignore these classes
        # TODO: remove NYSEUTP variable below once all NYSE UTP GWs are gone
        self.my_ignored_classes = [
            self.OmBoltTunnelAdmin_class,
            self.DMHandler_class,
            self.MultiDMHandler_class,
            self.postrack_class,
            self.gwdemux_class,
            self.NYSEUTPGW_class,
            self.order_delayer_class,
        ]

        # No demux for OboGateways:
        self.obo_classes = [
            self.SgxOuchObo_class,
            self.MlArrowObo_class,
            self.ArrowObo_class,
            self.SbijOboOuch_class,
            self.JpxLiteObo_class,
            self.JpxOuchObo_class,
            self.XetraObo_class,
            self.SbijOboToken_class,
            self.Sbij2OboToken_class
        ]

        # No demux for NiteFixGateway:
        self.nite_classes = [self.NiteFix_class]

        # No demux for CrnxOuchGateway:
        self.crnx_ouch_classes = [self.CrnxOuch_class]

    def get_commands_text(self, vm):
        """returns commands as single text line separated by ___"""
        return "".join(
            [x.replace("\n", "___") for x in vm.vmdata.commands if x.startswith("/")]
        )

    def get_gateway_apps(self, vm):
        """
        our notion of a gateway for this check may differ from the system so it's nice to be
        able to filter out other app types
        :return: list containing 'app' class objects
        """
        return [a for a in vm.apps if self.gw_class in a.classname]

    def contains_obo_gateway(self, vm):
        """
        look if one of the apps in the vm uses Obo gateway(s)
        :return: bool indicating whether the Vm contains at least one obo gw
        """
        return (
                len(
                    [
                        a
                        for a in self.get_gateway_apps(vm)
                        if a.classname in self.obo_classes
                    ]
                )
                > 0
        )

    def is_bolt(self, vm):
        """
        :return: bool indicating whether the Vm contains at least one bolt gw
        """
        for a in vm.getGateways():
            if self.is_bolt_gw(a):
                return True
        return False

    def is_bolt_gw(self, gw):
        """
        if url has hgcon config, then this is a bolt gw
        """
        return gw.url and re.search('hgcon=[0-9]+', gw.url)

    def get_hgcon(self, gw):
        """
        return hgcon number if gw is bolt, -1 otherwise
        """
        m = re.search('hgcon=([0-9]+)', gw.url)
        if m:
            return m.group(0)
        else:
            return -1

    def get_bindIfc(self, gw):
        """
        return bindIfc
        """
        m = re.search('bindIfc=([A-Z0-9]+)', gw.url)
        if m:
            return m.group(0)
        else:
            return None

    def get_tunnelPorts(self, vm):
        """
        returns list of all non-commented tunnelPorts in that vm command file
        """
        all_tunnels = []
        for line in vm.vmdata.commands:
            m = re.search('^[^#].*tunnelPort=([A-Z0-9]+)', line)
            if m:
                all_tunnels.append(m.group(1))

        return (all_tunnels)

    def get_pure_gateway_apps(self, vm):
        """
        we're looking only venue facing GW apps.. so will filter out other things
        :param vm:
        :return: list containing 'app' class objects
        """
        return [
            a
            for a in self.get_gateway_apps(vm)
            if a.classname not in self.my_ignored_classes
        ]

    def get_gwdemux_app(self, vm):
        """
        looking for class 'app' to match the gwdemux classname string
        :param vm:
        :return:
        """
        return [
            a for a in self.get_gateway_apps(vm) if a.classname == self.gwdemux_class
        ]

    def get_postrack_app(self, vm):
        return [
            a for a in self.get_gateway_apps(vm) if a.classname == self.postrack_class
        ]

    def is_bootapp_configured(self, vm):
        """
        find all instances of string 'start bootApp=True mold://'
        :param vm:
        :return:
        """
        return self.bootapp_regex.findall(self.get_commands_text(vm))


@pytest.mark.integtest
class TestGatewayConfigs(unittest.TestCase, GatewayTestUtils):
    """
    group gateways tests together
    """

    def setUp(self):
        super(TestGatewayConfigs, self).set_common_constants()

        self.gvms = list(self.my_filtered_vms())

    def my_filtered_vms(self):
        """

        :return:
        """
        for vms in filtered_vms():
            for vm in vms.get_vms():
                if vm.vmdata.core in self.my_ignored_clusters:
                    continue
                if vm.getGateways():
                    yield vm

    def contains_nite_gateway(self, vm):
        """
        look if one of the apps in the vm uses Nite gateway(s)
        :return: bool indicating whether the Vm contains at least one nite gw
        """
        return (
                len(
                    [
                        a
                        for a in self.get_gateway_apps(vm)
                        if a.classname in self.nite_classes
                    ]
                )
                > 0
        )

    def contains_crnx_ouch_gateway(self, vm):
        """
        look if one of the apps in the vm uses CrnxOuchGateway gateway(s)
        :return: bool indicating whether the Vm contains at least one nite gw
        """
        return (
                len(
                    [
                        a
                        for a in self.get_gateway_apps(vm)
                        if a.classname in self.crnx_ouch_classes
                    ]
                )
                > 0
        )

    def test_gateway_app_gwdemux(self):
        """
        if we have more then 1 gateway in a VM, it's more efficient to leverage gwdemux app for
        message handling
        also for VM with 1 gateway and 1 POSTRACK
        We also insure that all gw app actually use the demux
        See  COP-31018 - COP-33075
        :return: bool
        """
        for vm in self.gvms:
            # ignore VM using spice instead of mold
            if re.match(".*spice.*", self.get_commands_text(vm)):
                continue

            # obo gateway should not use demux by design, see CORE-19991 and CORE-19993
            if self.contains_obo_gateway(vm):
                continue

            pure_gw_apps = self.get_pure_gateway_apps(vm)
            postrack_app = self.get_postrack_app(vm)

            if len(pure_gw_apps) + len(postrack_app) > 1:
                self.assertTrue(
                    self.get_gwdemux_app(vm),
                    "%s - missing gwdemux app" % vm.vmdata.filename,
                )

                for a in pure_gw_apps:
                    self.assertTrue(
                        a.usesGwdemux,
                        "VM %s has a gwdemux app but %s does not use it"
                        % (vm.vmdata.filename, a.name),
                    )

    def test_obo_gateway_no_demux(self):
        """
        By design, obo gw should not be used together with gwdemux
        See CORE-19991 and CORE-19993
        :return: bool
        """
        for vm in self.gvms:
            if self.contains_obo_gateway(vm):
                self.assertTrue(
                    len(self.get_gwdemux_app(vm)) == 0,
                    "%s - uses gwdemux app with Obo gateways (and it shouldn't)"
                    % vm.vmdata.filename,
                )

    def test_gateway_app_postrack_demux(self):
        """
        rule:
        1. '/POSTRACK/start gwdemux://' should be the line
        2. POSTRACK line appear after the '/GWDEMUX/start' line
        :return:
        """
        for vm in self.gvms:
            if not self.get_gwdemux_app(vm):
                continue

            for pt in self.get_postrack_app(vm):
                self.assertTrue(
                    self.postrack_regex_2.search(self.get_commands_text(vm)),
                    "%s - postrack app should start AFTER gwdemux" % vm.vmdata.filename,
                )
                self.assertTrue(
                    self.postrack_regex_3.findall(pt.commands[1]),
                    "%s - postrack app should leverage gwdemux" % vm.vmdata.filename,
                )

    def test_cus08_clearing_ids(self):
        """
        Ensures that all cus08 gateways have clearing ID set to 'D', as requested in COP-30018
        note we have cus08 gateways that run in other clusters (e.g. Carteret and Mahwah) so we check all prod cores
        Also added clearing ID 'C' for BVSP gateways per COP-47285.
        :return: alert to syslog if any issues
        """
        invalid_gws = {}
        for vm in self.gvms:
            for gw in self.get_pure_gateway_apps(vm):
                # note that gw.core is the *logical* core
                if gw.core == "cus08":
                    if gw.vm.core == "bra01":
                        continue
                    if gw.clearing_id not in ["D", "C"]:
                        invalid_gws[gw.name] = {
                            "clearing_id": gw.clearing_id,
                            "vm_core": gw.vm.core,
                        }

        self.assertEqual(0, len(invalid_gws),
                         "COP-30018: The following cus08 gateways do not have clearing ID set to D or C:\n" +
                         "\n".join(["    name: {gw}, running_core: {core}, clearing_id: {id}".format(
                             gw=gw,
                             core=invalid_gws[gw]["vm_core"],
                             id=invalid_gws[gw]["clearing_id"],
                         ) for gw in invalid_gws]))

    def test_unique_gw_urls(self):
        """
        COP-28939 No two gateways should have the same URL since each is a distinct order handling session
        :return: fail if two gateways' URLs match exactly
        """
        gw_urls = {}
        unique_fields = (
        "targetCompId", "senderCompId", "targetSubId", "senderSubId", "sessionId", "virtualServer", "userName",
        "sessionSubId")
        URL = namedtuple("URL", "base_url " + " ".join(unique_fields))
        field_regex = {}
        for field in unique_fields:
            field_regex[field] = re.compile(r"[&?]{}=([^ ^&]+)".format(field), re.IGNORECASE)
        for vm in self.gvms:
            for gw in self.get_pure_gateway_apps(vm):

                if gw.get_parameter_lower("isStatusApp") == "true":
                    continue
                if gw.url:
                    base_url = gw.url.split("?")[0].split("://")
                    base_url = None if len(base_url) < 2 else base_url[1]
                    fields = {}
                    for field in unique_fields:
                        fields[field] = get_re_result_by_group_num(field_regex[field].search(gw.url), 1)
                    this_url = URL(base_url=base_url, **fields)
                    if (base_url not in self.duplicated_urls) and (this_url in gw_urls):
                        self.assertFalse(True, "Identical URL found in more than one gateway:\n" +
                                         "    {gw1} in {core1}/{vm1} and {gw2} in {core2}/{vm2} both have the same URL:\n".format(
                                             gw1=gw.name,
                                             core1=gw.core,
                                             vm1=vm.vmdata.vmname,
                                             gw2=gw_urls[this_url]["name"],
                                             core2=gw_urls[this_url]["core"],
                                             vm2=gw_urls[this_url]["vmname"],
                                         ) +
                                         "    URL={}".format(this_url)
                                         )
                    gw_urls[this_url] = {"name": gw.name, "core": gw.core, "vmname": vm.vmdata.vmname}

    def test_bolt_hgcon(self):
        """
        Ensure that hgcon are unique within each BOLT vm
        """
        for cl in filtered_vms():
            for vm in cl.get_vms():
                if self.is_bolt(vm):
                    hgcons = []
                    for gw in vm.getGateways():
                        if self.is_bolt_gw(gw):
                            hgcons.append(self.get_hgcon(gw))
                    self.assertTrue(len(hgcons) == len(set(hgcons)),
                                    'hgcon must be unique within Bolt vm, issue with {0:s}'.format(vm.vmdata.vmname))

    def test_bolt_unique_ifc(self):
        """
        Ensures that all bolt gw within one vm use the same interface - COP-47867
        """
        for cl in filtered_vms():
            for vm in cl.get_vms():
                if self.is_bolt(vm):
                    bind_ifc = []
                    for gw in vm.getGateways():
                        if self.is_bolt_gw(gw):
                            bind_ifc.append(self.get_bindIfc(gw))
                    self.assertTrue(len(set(filter(None, bind_ifc))) <= 1,
                                    'all bolt gw must have the same bindIfc within a vm, issue with {0:s}, len={1:d}'.format(
                                        vm.vmdata.vmname, len(set(bind_ifc))))

    def test_unique_tunnelPort(self):
        """
        tunnelPort config should be unique per box - COP-65821
        alos test port range
        """
        all_tunnelPorts = defaultdict(list)
        for cl in filtered_vms():
            for vm in cl.get_vms():
                tunnelPort = self.get_tunnelPorts(vm)
                if tunnelPort:
                    all_tunnelPorts[vm.vmdata.host].extend(tunnelPort)
        for host, ports in all_tunnelPorts.items():
            # uniqueness
            self.assertTrue(len(ports) == len(set(ports)), "tunnelPort not unique in {}".format(host))
            # range
            for port in ports:
                self.assertTrue((int(port) < 65535) & (int(port) > 0),
                                'tunnelPort {} in {} out of range [0, 65535]'.format(port, host))

    def test_cme_subids(self):
        """
        COP-62596 Check CME gateways' target and sender subIDs match market segment
        :return: fail if target or sender subID does not match market segment
        """
        from coputils.app import isNewAppLine
        subID_fields = ("targetSubId", "senderSubId")
        field_regex = {}
        for field in subID_fields:
            field_regex[field] = re.compile(r"[&?]{}=([^ ^&]+)".format(field), re.IGNORECASE)
        for vm in self.gvms:
            for gw in self.get_pure_gateway_apps(vm):
                if gw.get_parameter_lower("isStatusApp") == "true":
                    continue
                if self.CmeGateway_class not in gw.classname:
                    continue

                for line in vm.vmdata.commands:
                    if (isNewAppLine(line)) and (gw.name in line):
                        market_segment_regex = re.compile(r"^/INIT/(newApp|newCApp).* marketSegmentID=(\d+)")
                        market_segment_id = get_re_result_by_group_num(market_segment_regex.search(line), 2)

                if gw.url:
                    fields = {}
                    for field in subID_fields:
                        fields[field] = get_re_result_by_group_num(field_regex[field].search(gw.url), 1)

                        if market_segment_id is None:  # VCMM cores
                            if field is 'targetSubId':
                                self.assertTrue(fields[field] == 'G',
                                                '{} is not G for {} (CmeGateway)'.format(field, gw.name))

                        else:  # VPMM cores
                            self.assertTrue(fields[field] == market_segment_id,
                                            '{} does not match market segment ID for {} (CmeGateway)'.format(field,
                                                                                                             gw.name))

    def test_cme_login_ids(self):
        """
        COP-62598 Check CME gateways' login IDs are unique per ip address (login_id@ipaddress)
        :return: fail if duplicate login IDs are detected
        """
        cme_gateways_logins = {}
        from coputils.app import isNewAppLine
        for vm in self.gvms:
            for gw in self.get_pure_gateway_apps(vm):
                if gw.get_parameter_lower("isStatusApp") == "true":
                    continue
                if self.CmeGateway_class not in gw.classname:
                    continue

                for line in vm.vmdata.commands:
                    if (isNewAppLine(line)) and (gw.name in line):
                        market_segment_regex = re.compile(r"^/INIT/(newApp|newCApp).* marketSegmentID=(\d+)")
                        market_segment_id = get_re_result_by_group_num(market_segment_regex.search(line), 2)

                if gw.url:
                    base_url = gw.url.split("?")[0].split("://")
                    base_url = None if len(base_url) < 2 else base_url[1]
                    if ':' in base_url:
                        base_url = base_url.split(':')[0]
                    if base_url in cme_gateways_logins.keys():
                        cme_gateways_logins[base_url].append(gw.name)
                    else:
                        cme_gateways_logins[base_url] = [gw.name]

        for gateway_login, gwnames in cme_gateways_logins.items():
            if len(gwnames) > 1:
                print(gwnames)
                self.assertFalse(True, 'Multiple gateways detected for CME login {}'.format(gateway_login))

    def test_cme_market_ips(self):
        """
        COP-62618 Check CME gateways' have same target and backup IPs for the same market segment
        :return: fail if there are multiple target or sender IPs for the same market segment
        """
        from coputils.app import isNewAppLine
        gw_urls = {}

        backup_address_regex = re.compile(r"[&?]backupAddress=([^ ^&^:]+)", re.IGNORECASE)
        for vm in self.gvms:
            for gw in self.get_pure_gateway_apps(vm):
                if gw.get_parameter_lower("isStatusApp") == "true":
                    continue
                if self.CmeGateway_class not in gw.classname:
                    continue

                for line in vm.vmdata.commands:
                    if (isNewAppLine(line)) and (gw.name in line):
                        market_segment_regex = re.compile(r"^/INIT/(newApp|newCApp).* marketSegmentID=(\d+)")
                        market_segment_id = get_re_result_by_group_num(market_segment_regex.search(line), 2)
                if market_segment_id is None:
                    continue
                if gw.url:
                    base_url = gw.url.split("?")[0].split("://")
                    base_url = None if len(base_url) < 2 else base_url[1]
                    if '@' in base_url:
                        base_url = base_url.split('@')[1]
                    if ':' in base_url:
                        base_url = base_url.split(':')[0]
                    if base_url is not None:
                        backup_url = get_re_result_by_group_num(backup_address_regex.search(gw.url), 1)
                        two_urls = (base_url, backup_url)

                        if market_segment_id not in gw_urls.keys():
                            gw_urls[market_segment_id] = set()
                        gw_urls[market_segment_id].add(two_urls)

        for market_segment_id in gw_urls.keys():
            if len(gw_urls[market_segment_id]) > 1:
                print(gw_urls[market_segment_id])
                self.assertFalse(True, 'Multiple IPs detected for CME gateways with market segment ID {}'.format(
                    market_segment_id))

    def test_mit_gateways_replayPort(self):
        from urllib.parse import urlparse
        """
        COP-107052
        MitGateway, MitAutoRfqGateway, MitQuoteGateway should use replayPort
        depending on the venue, there is some logic to determine replayPort from "main" port"
        - LSE and Turquoise: replayPort = mainPort + 200
        - MTAH: replayPort = mainPort + 201
        - MTA and ETFP: replayPort = mainPort + 1
        """
        mit_family = ["MitGateway", "MitAutoRfqGateway", "MitQuoteGateway"]
        lse_turq_venues = ['LSE', 'LSER', 'TURQ', 'TRQD', 'TRQA', 'TQEX', 'TQED', 'TQEA', 'TRQD']
        mta_etfp_venues = ['MTA', 'ETFP', 'ETFR', 'MTAH', 'MTAI']
        mtah_venues = ['MTAH']
        replayPort_regexp = r"replayPort=([0-9]*)"
        for cl in filtered_vms():
            for vm in cl.get_vms():
                for gw in self.get_pure_gateway_apps(vm):
                    if gw.classname.split('::')[-1] in mit_family:
                        m = re.search(replayPort_regexp, gw.url)
                        self.assertTrue(m, "{} (in {}) is missing a replayPort".format(gw.name, vm.vmdata.vmname))
                        if m:
                            regular_port = int(urlparse(gw.url).port)
                            replay_port = int(m.group(1))
                            if any(v in gw.venues for v in lse_turq_venues):
                                self.assertEqual(replay_port, regular_port + 200,
                                                 "{} (in {}) seem to be using the wrong replayPort: using {}, expecting {}".format(
                                                     gw.name, vm.vmdata.vmname, replay_port, regular_port + 200))
                                # if replay_port != regular_port + 200:
                                #     print("gsed -i \'/{}:{}/s/replayPort={}/replayPort={}/\' {}".format(
                                #         urlparse(gw.url).hostname, urlparse(gw.url).port, replay_port,
                                #         regular_port + 200, vm.vmdata.filename))
                            elif any(v in gw.venues for v in mtah_venues):
                                self.assertEqual(replay_port, regular_port + 201,
                                                 "{} (in {}) seem to be using the wrong replayPort: using {}, expecting {}".format(
                                                     gw.name, vm.vmdata.vmname, replay_port, regular_port + 201))
                            elif any(v in gw.venues for v in mta_etfp_venues):
                                self.assertEqual(replay_port, regular_port + 1,
                                                 "{} (in {}) seem to be using the wrong replayPort: using {}, expecting {}".format(
                                                     gw.name, vm.vmdata.vmname, replay_port, regular_port + 1))
                                # if replay_port != regular_port + 1:
                                #     print("gsed -i \'/{}:{}/s/replayPort={}/replayPort={}/\' {}".format(
                                #         urlparse(gw.url).hostname, urlparse(gw.url).port, replay_port, regular_port + 1,
                                #         vm.vmdata.filename))MTAOR18
                            else:
                                self.assertTrue(False,
                                                "replayPort rule not defined for venue(s) {} for {} (in {}) - please check and update test".format(
                                                    ' '.join(gw.venues), gw.name, vm.vmdata.vmname))

    def test_mit_gateways_backup(self):
        """
        COP-82362
        Ensure MTA and MTAH gateways specify the right backup target
        https://www.borsaitaliana.it/borsaitaliana/gestione-mercati/migrazionemillenniumit-mit/mit702-bit-connectivityspecification-bitmainmarket.pdf
        https://www.borsaitaliana.it/borsaitaliana/gestione-mercati/migrazionemillenniumit-mit/mit701-bit-connectivityspecification-bit-v20.en.pdf
        """
        mta_target_to_backup_map = {'194.169.10.48': '194.169.12.48',
                                    '194.169.10.49': '194.169.12.49',
                                    '194.169.10.50': '194.169.12.50',
                                    '194.169.10.56': '194.169.12.56',
                                    '194.169.10.57': '194.169.12.57'}
        for cl in filtered_vms():
            for mta_gw in cl.getAppsByClass('MitQuoteGateway') + cl.getAppsByClass(
                    'MitAutoRfqGateway') + cl.getAppsByClass('MitGateway'):

                m_target = re.search(r'@([0-9\.]+):([0-9]+)', mta_gw.url)
                if not m_target:
                    raise AttributeError('ip not found for {} in {}'.format(mta_gw.name, cl.name))

                target_ip = m_target.group(1)
                target_port = int(m_target.group(2))

                if target_ip in mta_target_to_backup_map:
                    backup_ip = mta_target_to_backup_map[target_ip]
                    backup_port = target_port
                    print(mta_gw.venues)

                    m_reg = re.search('backupAddress=([0-9\.]+):([0-9]+)', mta_gw.url)

                    if m_reg:
                        if not (backup_ip == m_reg.group(1) and backup_port == int(m_reg.group(2))):
                            raise AttributeError(
                                'Wrong backup target for {} in {}: expected {}:{}, got {}:{}'.format(mta_gw.name,
                                                                                                     cl.name,
                                                                                                     backup_ip,
                                                                                                     backup_port,
                                                                                                     m_reg.group(1),
                                                                                                     m_reg.group(2)))
                    else:
                        raise AttributeError('Missing backup target for {} in {}'.format(mta_gw.name, cl.name))


@pytest.mark.integtest
class TestAgencyConfigs(unittest.TestCase, GatewayTestUtils):
    """
    Test Agency Configs
    """

    def setUp(self):
        super(TestAgencyConfigs, self).set_common_constants()
        """
        BEFORE YOU ADD TO self.allowed_brokers, PLEASE CHECK THAT OPS HAS ADDED TO AIMS ACCOUNTS IN FS!

        https://fsgui.virtu.com:8443/fsgui/app/aimsAccounts?skipInit=Y&submitScreen=Y&action=Search&pageSize=500&dataSize=2&accountIdSearch=&aimsClientIdSearch=228506&aimsClientInstName=&_aimsClientIdArrSearch=1&shortnameSearch=&accountNumber=%5E....%24&accountName=&nonRetiredOnly=true&_nonRetiredOnly=on&_alertErrorsOnly=on&alertAcronym=&accessCode=&dtcClearingNumber=&orderBy1=&orderBy1Asc=ASC&orderBy2=&orderBy2Asc=ASC&orderBy3=&orderBy3Asc=ASC&orderBy4=&orderBy4Asc=ASC
        """
        self.allowed_brokers = ['CSCO', 'CTVT', 'JGSF', 'JCTP', 'JDAC', 'JDAI', 'JGSC', 'JKAI', 'JNOM', 'JPVX', 'NIKO',
                                'JBNP', 'JCLV', 'JLQV', 'JHBV',
                                'AUCX', 'AVTD', 'AVTM', 'CXVD', 'CXVM', 'PNWV', 'JPDX', 'NCRD', 'NCRV', 'AUVX', 'ACLV',
                                'ALQV', 'AGSV', 'AHBV', 'IRES',
                                'TYVD', 'TKVD', 'TCVD', 'WHBV', 'HHBV', 'HBCV',
                                'HKVD', 'HCVF', 'CCHV', 'HKVX', 'HICV', 'CCIV', 'HCTP', 'HCTV', 'HCLV', 'HLQV',
                                'KVCT', 'KVDA', 'KVHB', 'KHBV', 'KVKI', 'KSHV', 'KVSM', 'INCV',
                                'IIVT', 'TVCT',
                                'SCIV', 'SDBV', 'SHBV', 'MCIV', 'MHBV', 'TDBV', 'THCV', 'IDBV', 'IDCV', 'IHBV', 'RSAV',
                                'SOCG', 'PTVD', 'PHBV', 'INKV', 'HGSV', 'GSAV', 'GSCV']

    def agency_apac_core(self):
        """
        :return: generator object containing 'cluster' agency apac objects
        """
        for cl in ALL_CLUSTERS:
            if cl.core in getAttrs('AGENCYCORE') and cl.core in getAttrs('APAC'):
                yield cl

    def test_agency_fixport_core_order(self):
        """
        COP-106632
        Unittest to ensure ports in full-core-order cores use the right config
        :return:
        """
        # TODO: update this list as coreOrder roll out goes on:
        non_fully_migrated_cores = ['wee03']

        core_regexp = "^/INIT/newApp.*{}.* useCoreOrderWorkflow=true"
        exception_regexp = "^/INIT/newApp.*{}.* crossCorePessimisticPing=true"
        missing_core_order_config = []
        for cl in filtered_vms():
            if cl.name in non_fully_migrated_cores:
                print('SKIPPING {} for useCoreOrderWorkflow check - update if core was migrated'.format(cl.name))
                continue
            cl.initApps()
            for fix_port in cl.getAppsByPythonClass(AgencyFixPort):
                for line in fix_port.vm.vmdata.commands:
                    if re.match(exception_regexp.format(fix_port.name), line):
                        break
                    elif re.match(core_regexp.format(fix_port.name), line):
                        break
                else:
                    missing_core_order_config.append('{} in {}'.format(fix_port.name, cl.name))

        self.assertEqual(len(missing_core_order_config), 0,
                         'FixPort without coreOrderWorkflow: \n' + ';\n '.join(missing_core_order_config))

    def test_agency_fixport_duplicate_port(self):
        """
        COP-113101
        Ensure Agency port don't use the same port if in same host
        :return:
        """
        core_ports = defaultdict(list)
        duplicate_ports = defaultdict(list)
        for cl in filtered_vms():
            cl.initApps()
            for fix_port in cl.getAppsByPythonClass(AgencyFixPort):
                if fix_port.clientPort in core_ports[fix_port.vm.vmdata.host]:
                    duplicate_ports[fix_port.vm.vmdata.host].append(fix_port.clientPort)
                else:
                    core_ports[fix_port.vm.vmdata.host].append(fix_port.clientPort)

        if len(duplicate_ports) > 0:
            err_msg = "Duplicated port(s) in the following host(s): "
            for host, ports in duplicate_ports.items():
                err_msg += '\n {}: {}'.format(host, ' '.join(ports))
            self.assertTrue(False, err_msg)

    def test_agency_fixport_has_realbcp(self):
        """
        COP-75496 Test every GlobalAgencyFixPort has a breaks check i.e. addComparison in REALBCP
        """
        fixport_regex = re.compile("^/INIT/newApp com.ewt.applications.vfx.GlobalAgencyFixPort .*")
        comparison_regex = re.compile(r"^/(REALBCPA?)/addComparison\s(.*?)\s")
        exclude_list = ["wee03", "cus26"]
        cores_with_fixports = []
        realbcp_comparisons = []
        for cl in filtered_vms():
            if cl.core in exclude_list:
                continue
            vms = cl.get_vms()
            for vm in vms:
                if cl.core in cores_with_fixports:
                    break
                for command in vm.vmdata.commands:
                    if fixport_regex.match(command) and ("caprona=true" in command):
                        cores_with_fixports.append(cl.core)
                        break
            realbcp_vms = [vm for vm in vms if ((vm.vmdata.vmname == 'REALBCP') or (vm.vmdata.vmname == 'REALBCPA'))]
            for v in realbcp_vms:
                realbcp_comparisons.extend([c for c in v.vmdata.commands if comparison_regex.match(c)])

        self.assertNotEqual([], realbcp_comparisons, "Can't find any REALBCP comparisons!")
        self.assertNotEqual([], cores_with_fixports, "No cores with GlobalAgencyFixPorts detected!")
        comparison_phrases = " ".join(realbcp_comparisons).replace("/REALBCP/addComparison", "").replace(
            "/REALBCPA/addComparison", "")
        # comparison_phrases = re.sub("/(REALBCPA?)/addComparison", "", " ".join(realbcp_comparisons))
        core_regex = re.compile(r"([A-Za-z]+)(\d+)")
        for core in cores_with_fixports:
            self.assertTrue(core_regex.match(core), "Invalid core name %s" % core)
            [core_site, core_num] = core_regex.match(core).groups()
            match_phrase = "%s_%s" % (core_site.upper(), core_num)
            match_phrase = "CAP_" + match_phrase
            self.assertTrue(match_phrase in comparison_phrases,
                            "No CAP_%s_%s comparison in REALBCP - please add!" % (core_site.upper(), core_num))

    def test_broker_apac_agency(self):
        """
        COP-78139 / COP-78069
        broker field is required for APAC agency gws, as it is needed for clearing in Gate
        Only certain values are allowed.
        If you set-up a new gateways (especially with a new broker/venue), you should make sure FS and GATE's MBO are in sync
        """
        broker_regex = r"^/INIT/.*broker=([A-Za-z0-9]+)"
        for cl in self.agency_apac_core():
            cl.get_vms()
            gws = cl.getGateways()
            for gw in gws:
                broker = ""
                for command in gw.commands:
                    m = re.match(broker_regex, command)
                    if m and m.groups():
                        broker = m.groups()[0]
                        break
                self.assertFalse(broker == "", "{} does not have any broker field".format(gw.name))
                self.assertTrue(broker in self.allowed_brokers,
                                "{} broker field {} is not (yet?) defined as valid".format(gw.name, broker))


@pytest.mark.integtest
class TestApacCommands(unittest.TestCase, GatewayTestUtils):
    """
    Test APAC-specific commands cases
    """

    def setUp(self):
        super(TestApacCommands, self).set_common_constants()

        self.asx_ouch_regex = ".*venues?=ASX.*geniumouch://([A-Z0-9]{6}):.*"
        self.sgx_ouch_regex = ".*venues?=SGX.*geniumouch://([A-Z0-9]{6}):.*"
        self.sgx_password_regex = r".*(omex|geniumouch)://([A-Z0-9]{6}):(\S*)@.*"
        self.ose_spc_regex = r".*omex://(\d{5})\S{5}:.*"
        self.ose_om_regex = r".*omex://(\d{5}\S{5}):.*"
        self.tse_vs_regex = r".*virtualServer=([A-Z0-9]{6})&.*"
        self.hkfe_om_regex = r".*omex://([A-Z]{5}[0-9]{4}):.*"
        self.ose_broadcast_a1 = r"mold://239.192.42.104:65271\?requestHost=core012.core.tyo06.loc&requestPort=64221"
        self.ose_broadcast_a2 = r"mold://239.192.42.105:65272\?requestHost=core007.core.tyo06.loc&requestPort=64222"
        self.ose_broadcast_b1 = r"mold://239.192.42.106:65273\?requestHost=core012.core.tyo06.loc&requestPort=64223"
        self.ose_broadcast_b2 = r"mold://239.192.42.107:65274\?requestHost=core007.core.tyo06.loc&requestPort=64224"
        self.ose_broadcast_s1 = r"mold://239.192.42.108:65275\?requestHost=core081.core.tyo06.loc&requestPort=64225"
        self.ose_broadcast_s2 = r"mold://239.192.42.109:65276\?requestHost=core081-1.core.tyo06.loc&requestPort=64226"
        self.ose_broadcast_c1 = r"mold://239.192.42.110:65280\?requestHost=core029.core.tyo06.loc&requestPort=64230"
        self.ose_broadcast_c2 = r"mold://239.192.42.111:65281\?requestHost=core081.core.tyo06.loc&requestPort=64231"
        self.ose_broadcast_regex1 = r"^/.*mt_cside::applications::broadcast::om::lite::JpxBroadcaster OSEPC1 url=omex://11104[A-Z0-9]{5}:.*@(\d+.\d+.\d+.\d+):(\d{4}?).*"
        self.ose_broadcast_regex2 = r"^/.*mt_cside::applications::broadcast::om::lite::JpxBroadcaster OSEPC2 url=omex://11104[A-Z0-9]{5}:.*@(\d+.\d+.\d+.\d+):(\d{4}?).*"
        self.asx_feed_regex = (
            r".*mt_cside::quoteserver::feeds::jpx::AsxItchFeed.*venues?=ASX.*"
        )
        self.asx_glimpse_regex = r"^[^#].*glimpseUrl(s)?=soupbin://236G01:ZbI6NqGG@core008.syd03.loc:1101(\d)\?sequence=1.*"
        self.mckay_receiver_regex = ".*mt_cside::applications::mckay::Receiver MKTSRECV.*"
        self.ose_feed_regex = (
            r".*mt_cside::quoteserver::feeds::jpx::JpxItchFeed.*venues?=OSE.*"
        )
        self.ose_glimpse_regex = (
            r".*glimpseUrl=soupbin://GLMP(\d):\S{8}@core020.tyo06.loc:1101(\d).*"
        )
        self.sgx_feed_regex = (
            r".*mt_cside::quoteserver::feeds::jpx::SgxItchFeed.*venues?=SGX.*"
        )
        self.sgx_glimpse_regex = r".*glimpseUrl=soupbin://MLVT[XZ]A:vfcd1d@core009.sin01.loc:1101(\d)\?sequence=1.*"
        self.tocm_feed_regex = (
            r".*mt_cside::quoteserver::feeds::jpx::JpxItchFeed.*venues?=TOCM.*"
        )
        self.tocm_glimpse_regex = (
            r".*glimpseUrl=soupbin://GLMP(\d):ea763xr9@core019.tyo07.loc:1101(\d).*"
        )
        self.tse_feed_regex = r"^/.*mt_cside::quoteserver::feeds::tse::FlexFeed.*"
        self.tse_snapshot_regex = (
            r"^/.*channels=239.194.2[1-4].(\d+):(\d{5})\,239.194.2[1-4].(\d+):(\d{5}).*channelId=(\d+)"
            r".*snapshotUrl=flexgap://core017.tyo06.loc:11011\?mainsUserCode=189887f01"
            r".*&channelOffset=(\d+)&diff=(\d+).*"
        )
        self.sbij_ouch_regex = r".*url=tokenouch://[A-Z0-9]{6}:\S{10}@(\d+.\d+.\d+.\d+):\d{5}\?sequence=(\d+).*"
        self.sbij_expressway_ips = ["10.65.2.14", "10.65.2.27", "10.65.2.29", "10.65.2.155", "10.65.2.157"]

        self.unique_talker_mux_exempted = ['SGXOUCHPASSWORD', 'OSESG1']
        self.nse_feed_regex = r"^\/.*mt_cside::quoteserver::feeds::nseindiamc::NseIndiaMCFeed.*"
        self.bse_feed_regex = r"^\/QUOTES\/newFeed mt_cside::quoteserver::feeds::eobi::EobiFeed.*venues?=BSEQ.*"

    def is_super_gateway(self, vm):
        """
        detect super gateway (OSE, TOCOM, SGX OM, HKFE, ASX OM)
        :return: True/False
        """
        session_regex = r"^\/.*addSession"
        count_session = 0
        for app in vm.apps:
            for cmd in app.commands:
                if re.match(session_regex, cmd):
                    count_session = count_session + 1
        return (count_session > 1)

    def get_session_talker_muxes(self, vm):
        talker_mux_regex = r"^\/.*addSession.*talkerCpuSet=mux([0-9]+)"
        talker_muxes = []
        for app in vm.apps:
            for cmd in app.commands:
                regexp = re.match(talker_mux_regex, cmd)
                if regexp:
                    talker_muxes.append(int(regexp.group(1)))
        return talker_muxes

    def check_unique_sessions(self, venue, session_regex, ignore_string=""):
        """
        Ensure that venue gateway session logins are unique
        """
        regex = re.compile(session_regex)
        session_list = []
        for cl in filtered_vms():
            for app in cl.getGatewaysByVenue(venue):
                for command in app.commands:
                    if ignore_string and ignore_string in command:
                        continue
                    else:
                        m = regex.match(command)
                        if m:
                            session = m.group(1)
                            self.assertFalse(
                                session in session_list,
                                "Venue %s session %s is a duplicate" % (venue, session),
                            )
                            session_list.append(session)

    def test_unique_sessions(self):
        self.check_unique_sessions("ASX", self.asx_ouch_regex)
        self.check_unique_sessions("HKFE", self.hkfe_om_regex)
        self.check_unique_sessions("OSE", self.ose_om_regex)
        self.check_unique_sessions("SGX", self.sgx_ouch_regex, "isStatusApp=true")
        self.check_unique_sessions("TSE", self.tse_vs_regex)

    def test_sgx_passwords_match(self):
        """
        Ensure SGX password in prod OUCH gateway matches the OM password app
        """
        sgx_passwords = {}
        regex = re.compile(self.sgx_password_regex)
        for cl in filtered_vms():
            gws = cl.getGatewaysByVenue("SGX")
            for gw in gws:
                for command in gw.commands:
                    m = regex.match(command)
                    if m:
                        if m.group(2) in sgx_passwords:
                            self.assertTrue(
                                sgx_passwords[m.group(2)] == m.group(3),
                                "SGX password does not match for OUCH and OM for user %s"
                                % m.group(2),
                            )
                        else:
                            sgx_passwords[m.group(2)] = m.group(3)

    def test_sgx_ouch_in_passwd(self):
        """
        Ensure all SGX ouch gw have a line in SGXOUCHPASSWD PASSWD app
        """
        import updateSGXpasswords

        cl = cluster.get_cluster_by_name('sin01', coreops_commands_path=COREOPS_COMMANDS_PATH)
        sessions, duplicate_sessions = updateSGXpasswords.getSessionsData(cl, 'SGX')
        ompass_app = cl.getUniqueApp('PASSWD')
        for session_data in list(sessions.values()) + list(duplicate_sessions.values()):
            is_in_passwd = False
            for line in ompass_app.vm.vmdata.commands:
                if re.match('#?/PASSWD/addLogin {}'.format(session_data['user_id']), line):
                    is_in_passwd = True
                    break
            self.assertTrue(is_in_passwd,
                            '{} password is not in SGXOUCHPASSWD PASSWD app'.format(session_data["user_id"]))

    def test_ose_gateway_spc(self):
        """
        Ensure OSE gateways only have one SPC user
        """
        regex = re.compile(self.ose_spc_regex)
        for cl in filtered_vms():
            cl.get_vms()
            gws = cl.getGatewaysByVenue("OSE")
            for gw in gws:
                if "DmaFixGateway" in gw.classname or "BamlTtGateway" in gw.classname:
                    continue
                if gw.vm.vmdata.vmname == 'OSEBOLT09' or gw.vm.vmdata.vmname == 'OSEN01' \
                        or gw.vm.vmdata.vmname == 'OSEOUCHTEST21':
                    continue  # new OSEBOLT in construction or shared TAPs with Nissan
                gw_spc = []
                for command in gw.commands:
                    m = regex.match(command)
                    if m:
                        gw_spc.append(m.group(1))
                spcs = list(set(gw_spc))
                self.assertTrue(
                    len(spcs) <= 1,
                    "OSE gateway %s (in %s) has multiple SPC sessions %s"
                    % (gw.name, gw.vm.vmdata.vmname, spcs),
                )

    # def test_ose_VM_spc(self):
    #    """
    #    Ensure that all gateways in one OSEBOLT vm use the same participant code
    #    """
    #    regex = re.compile(self.ose_spc_regex)
    #    for cl in filtered_vms():
    #        for vm in cl.get_vms():
    #            if 'OSEBOLT' in vm.vmdata.vmname:
    #                continue  # new OSEBOLT setup requires 2 pp codes
    #            if self.is_bolt(vm) and re.search('OSE', vm.vmdata.vmname):
    #                vm_spc = []
    #                for gw in vm.getGateways():
    #                    for command in gw.commands:
    #                        m = regex.match(command)
    #                        if m:
    #                            vm_spc.append(m.group(1))
    #                spcs = list(set(vm_spc))
    #                self.assertTrue(
    #                    len(spcs) == 1,
    #                    "OSE VM %s has multiple SPC sessions: %s"
    #                    % (vm.vmdata.filename, spcs),
    #                )

    def test_commonrock_ap3_tyo06_tyo07(self):
        """
        COP-77447 Check tyo06 OIs with ethType 34915 and 34917 (intended for tyo07)
        Check that the tyo06 commonrock oiPort and oiWriter config matches with tyo07 addOiSrc config
        i.e. ensure that the COMMONROCK is sending OIs from tyo06 -> tyo07
        """
        self.skipTest("COP-120349")
        ethtypes_to_track = [34915, 34917]

        rock_tyo06, rock_tyo07 = None, None
        for cl in filtered_vms():
            if cl.core in ('tyo06', 'tyo07'):
                ap = [a for a in cl.getAppsByName('COMMONROCK') if (a.vm.vmdata.host.split('.')[0] == 'emu130')]
                self.assertTrue(len(ap) == 1, "%s has %d COMMONROCK apps! Expecting only 1 here."
                                % (cl.core, len(ap)))
                if cl.core == 'tyo06':
                    rock_tyo06 = ap[0]
                elif cl.core == 'tyo07':
                    rock_tyo07 = ap[0]
                if (rock_tyo06 is not None) and (rock_tyo07 is not None):
                    break

        ethtypes_config = {}
        for etype in ethtypes_to_track:
            ethtypes_config[etype] = set()

        writer_socket_line = re.compile("^/COMMONROCK/COMMON_ROCK/setOiWriterSocket")
        oi_src_line = re.compile("^/COMMONROCK/COMMON_ROCK/addOiSrc")

        dstmac_regex = re.compile(r"dstMac=(\S+)")
        oisrcethtype_regex = re.compile(r"oiSrcEthType=(\d+)")
        oisrcdstmac_regex = re.compile(r"oiSrcDstMac=(\S+)")

        for commandline in rock_tyo06.commands:
            if not writer_socket_line.match(commandline):
                continue
            for etype in ethtypes_to_track:
                ethtype_line = "ethType=%d" % etype
                if ethtype_line in commandline:
                    mmatch = dstmac_regex.search(commandline)
                    if mmatch:
                        mac = mmatch.group(1)
                        ethtypes_config[etype].add(mac)

        for etype, macs in ethtypes_config.items():
            self.assertFalse(len(macs) == 0, "Can't find sending of ethType %d" % etype)

        # for commandline in rock_tyo07.commands:
        #    if not oi_src_line.match(commandline):
        #        continue
        #    if oisrcethtype_regex.search(commandline):
        #        etype = int(oisrcethtype_regex.search(commandline).group(1))
        #        if etype not in ethtypes_to_track:
        #            continue
        #        mmatch = oisrcdstmac_regex.search(commandline)
        #        if mmatch:
        #            mac = mmatch.group(1)
        #            ethtypes_config[etype].remove(mac)

        for etype, macs in ethtypes_config.items():
            if len(macs) != 0:
                print(macs)
                self.assertTrue(len(macs) == 0, "Sending MACs without receiver for ethType %d" % etype)

    def test_mckay_nln_sin01(self):
        """
        Test commands files in sin01 and tyo07 to make sure McKay is the primary wireless , we can add a comment if
        we failover to prevent the alert / build failure , comment format {#MCKAY_DOWN YYYYMMDD username}
        :return: alert to syslog is any issues
        """
        syslogger = syslogsender.SysLogger()
        current_date = datetime.now()
        maintenance_regex = r"^#MCKAY_DOWN\s(20[12][0-9][01][0-9]{3})\s([a-zA-Z]*)"
        regex = re.compile(maintenance_regex)
        senders_regex = r".*/(addDirectSignalSender|addOrderInjectionSender|setCoreAddress) .*"
        re_senders_regex = re.compile(senders_regex)
        vm_regex = re.compile(self.mckay_receiver_regex)
        for cl in filtered_vms():
            for vm in cl.get_vms():
                maintenance = maintenance_date = False
                missing_command = []
                if vm.vmdata.vmname == 'MKTSRECV':
                    short_filename = vm.vmdata.filename.split("/")[-1]
                    for comment in vm.vmdata.comments:
                        if "#MCKAY_DOWN" in comment:
                            m = regex.match(comment)
                            if m:
                                date = m.group(1)
                                maintenance_date = datetime.strptime(date, "%Y%m%d")
                                username = m.group(2)
                                if (maintenance_date < current_date):
                                    maintenance = False
                                else:
                                    maintenance = True
                        elif re_senders_regex.match(comment):
                            missing_command.append(comment)
                            # Some commands to inject signal or orders are commented out so we'll alert
                    if not maintenance_date:
                        syslogger.send_message(
                            "COMMANDS_CHECK: This commands file %s, is missing MCKAY_DOWN comment"
                            % short_filename
                        )
                    self.assertFalse(
                        missing_command and not maintenance,
                        "McKay sin01<->tyo07 is still disabled %s passed %s" % (vm.vmdata.filename, maintenance_date),
                    )

    # Todo: follow up on  CORE-22297 and complete/uncomment that test
    # def test_japan_obo_gateway_config(self):
    #     """
    #     JpxLite and JpxLiteObo Bolt gateways require rerouteCancel=true config
    #     See CORE-22297
    #     :return: bool
    #     """
    #     for vm in self.gvms:
    #         if self.is_bolt(vm):
    #             for a in self.get_gateway_apps(vm):
    #                 if a.classname in [self.JpxLite_class, self.JpxLiteObo_class]:
    #                     # self.assertTrue('rerouteCancel=true' in a.commands,
    #                     #                 'JpxLit(obo) gateway {app:s} in vm {vm:s} misses \'rerouteCancel=True\' command'.format(app=a, vm=vm.vmdata.vmname))
    #                     print a.commands

    # def test_ose_broadcast_setup(self, ignore_vms=["OSESTATUS", "OSEN01", "OSEMDTESTOM"]):
    #    """
    #    Ensure OSE broadcast proxy is on the first connection in a VM and matches SPC code
    #    """
    #    regex_spc = re.compile(self.ose_spc_regex)
    #    regex_a1 = re.compile(self.ose_broadcast_a1)
    #    regex_a2 = re.compile(self.ose_broadcast_a2)
    #    regex_b1 = re.compile(self.ose_broadcast_b1)
    #    regex_b2 = re.compile(self.ose_broadcast_b2)
    #    regex_c1 = re.compile(self.ose_broadcast_c1)
    #    regex_c2 = re.compile(self.ose_broadcast_c2)
    #    regex_s1 = re.compile(self.ose_broadcast_s1)
    #    regex_s2 = re.compile(self.ose_broadcast_s2)
    #
    #    def regex_check(spc):
    #        if spc == "11804":
    #            p1 = regex_a1.findall(command)
    #            p2 = regex_a2.findall(command)
    #        elif spc == "11819":
    #            p1 = regex_b1.findall(command)
    #            p2 = regex_b2.findall(command)
    #        elif spc == "22550":
    #            p1 = regex_s1.findall(command)
    #            p2 = regex_s2.findall(command)
    #        elif spc == "11104":
    #            p1 = regex_c1.findall(command)
    #            p2 = regex_c2.findall(command)
    #        return p1, p2
    #
    #    for cl in filtered_vms():
    #        cl.get_vms()
    #        gws = cl.getGatewaysByVenue("OSE")
    #        for gw in gws:
    #            if ignore_vms and gw.vm.vmdata.vmname in ignore_vms:
    #                continue
    #            else:
    #                gw_spc = []
    #                for command in gw.commands:
    #                    m = regex_spc.match(command)
    #                    if m:
    #                        gw_spc.append(m.group(1))
    #                        if len(gw_spc) == 1:
    #                            p1, p2 = regex_check(gw_spc[0])
    #                            self.assertTrue(
    #                                p1,
    #                                "OSE gateway %s (in %s) missing primary broadcast proxy"
    #                                % (gw.name, gw.vm.vmdata.vmname),
    #                            )
    #                            self.assertTrue(
    #                                p2,
    #                                "OSE gateway %s (in %s) missing secondary broadcast proxy"
    #                                % (gw.name, gw.vm.vmdata.vmname),
    #                            )
    #                        else:
    #                            p1, p2 = regex_check(gw_spc[0])
    #                            self.assertFalse(
    #                                p1,
    #                                "OSE gateway %s (in %s) has broadcast proxy not on first session"
    #                                % (gw.name, gw.vm.vmdata.vmname),
    #                            )
    #                            self.assertFalse(
    #                                p2,
    #                                "OSE gateway %s (in %s) has broadcast proxy not on first session"
    #                                % (gw.name, gw.vm.vmdata.vmname),
    #                            )
    #
    # def test_ose_broadcast_proxy_tap(self):
    #    """
    #    Ensure OSE broadcast proxy 1 and 2 use different TAPs
    #    """
    #    broadcast_proxy_regex_1 = re.compile(self.ose_broadcast_regex1)
    #    broadcast_proxy_regex_2 = re.compile(self.ose_broadcast_regex2)
    #
    #    for cl in filtered_vms():
    #        cl.get_vms()
    #        vms = cl.getVmsByCommandRegex("JpxBroadcaster")
    #        for vm in vms:
    #            for command in vm.vmdata.commands:
    #                if broadcast_proxy_regex_1.match(command):
    #                    b1 = broadcast_proxy_regex_1.match(command)
    #                    vm1 = vm.vmdata.vmname
    #                if broadcast_proxy_regex_2.match(command):
    #                    b2 = broadcast_proxy_regex_2.match(command)
    #                    vm2 = vm.vmdata.vmname
    #    if b1 and b2:
    #        self.assertFalse(
    #            b1.group(1) + ":" + b1.group(2) == b2.group(1) + ":" + b2.group(2),
    #            "%s and %s are connecting to the same OSE TAP"
    #            % (vm1, vm2),
    #        )
    #
    def check_snapshot_proxy_setup(
            self, feed_regex, snapshot_regex, snapshot_format, ignore_vms=[]
    ):
        """
        Ensure snapshot URL uses the correct snapshot proxy
        """
        regex1 = re.compile(feed_regex)
        regex2 = re.compile(snapshot_regex)
        for cl in filtered_vms():
            vms = cl.getVmsByCommandRegex(snapshot_format)
            for vm in vms:
                if ignore_vms and vm.vmdata.vmname in ignore_vms:
                    continue
                else:
                    for line in vm.vmdata.commands:
                        command = line.split("#")[0]
                        m = regex1.match(command)
                        if m:
                            n = regex2.match(command)
                            self.assertTrue(
                                n,
                                "%s has the incorrect snapshot proxy setup"
                                % vm.vmdata.filename,
                            )

    def test_snapshot_proxy_setup(self):
        self.skipTest("Needs to be fixed first. Been failing for days")
        self.check_snapshot_proxy_setup(
            self.asx_feed_regex, self.asx_glimpse_regex, "glimpseUrl=", ["MDCAPTUREASX", "ASXMDTEST"]
        )
        self.check_snapshot_proxy_setup(
            self.asx_ouch_regex, self.asx_glimpse_regex, "glimpseUrl="
        )
        self.check_snapshot_proxy_setup(
            self.ose_feed_regex, self.ose_glimpse_regex, "glimpseUrl=",
            ["OSEITCHUDPPICO", "OSEITCHUDP", "OSEITCHUDPJGATE3"]
        )
        self.check_snapshot_proxy_setup(
            self.sgx_feed_regex, self.sgx_glimpse_regex, "glimpseUrl="
        )
        self.check_snapshot_proxy_setup(
            self.sgx_ouch_regex, self.sgx_glimpse_regex, "glimpseUrl="
        )
        self.check_snapshot_proxy_setup(
            self.tocm_feed_regex,
            self.tocm_glimpse_regex,
            "glimpseUrl=",
            ["TOCMITCHUAT"],
        )
        self.check_snapshot_proxy_setup(
            self.tse_feed_regex,
            self.tse_snapshot_regex,
            "snapshotUrl=",
            [
                "TSEMCSLOB4",
                "TSEMCTOS",
                "TSEMCTEST1",
                "TSEMCGLOB4",
                "TSEMCUDP4",
                "TSEMD1",
                "TSEMD2",
                "TSEMCAGCY4",
            ],
        )
        # TODO: clean up TSE exceptions

    def check_jpx_snapshot_url(self, glimpse_regex, ignore_vms=[]):
        """
        Ensure JPX snapshot URL has matching user, port
        """
        regex = re.compile(glimpse_regex)
        for cl in filtered_vms():
            vms = cl.getVmsByCommandRegex("JpxItchFeed")
            for vm in vms:
                if ignore_vms and vm.vmdata.vmname in ignore_vms:
                    continue
                else:
                    for command in vm.vmdata.commands:
                        m = regex.match(command)
                        if m:
                            self.assertTrue(
                                len(set(m.groups())) == 1,
                                "JPX feed %s has mismatched snapshot user and "
                                "port" % vm.vmdata.filename,
                            )

    def test_jpx_snapshot_url(self):
        self.check_jpx_snapshot_url(self.ose_glimpse_regex)
        self.check_jpx_snapshot_url(self.tocm_glimpse_regex, ["TOCMITCHUAT"])
        # TODO can we combine this test with the snapshot_proxy_setup?

    def test_tse_snapshot_url(
            self, ignore_vms=["TSEMCTOS", "TSEMCBASE", "TSEMCBASETIER1", "TSEMCUATTEST", "TSECMCPICO1", "TSECMCPICO2"]
    ):
        """
        Ensure TSE feed is using snapshot proxy with channelId=X and has unique diff=X values per VM and that channelId
        match with the mutlicast groups and offset
        """
        regex = re.compile(self.tse_snapshot_regex)
        for cl in filtered_vms():
            cl.get_vms()
            vms = cl.getVmsByCommandRegex("FlexFeed")
            for vm in vms:
                if ignore_vms and vm.vmdata.vmname in ignore_vms:
                    continue
                else:
                    feed_diffs = []
                    for command in vm.vmdata.commands:
                        m = regex.match(command)
                        if m and command not in vm.vmdata.comments:
                            feed_diffs.append(m.group(5))
                            self.assertTrue(
                                int(m.group(5)) + int(m.group(6)) == int(m.group(1)) == int(m.group(3)),
                                "TSE feed %s Offset %s is wrong "
                                % (vm.vmdata.filename, m.group(3)),
                            )
                    diffs = list(set(feed_diffs))
                    self.assertFalse(
                        len(diffs) == 0,
                        "TSE feed %s is not using snapshot proxy setup"
                        % vm.vmdata.filename,
                    )
                    self.assertTrue(
                        len(diffs) == len(feed_diffs),
                        "TSE feed %s has common diff IDs" % vm.vmdata.filename,
                    )

    # def test_password_formats(self):
    #     """
    #     Ensure passwords have required format
    #     """
    # TODO
    # self.skipTest("write test")

    def test_sbij_expressway_setup(self):
        """
        Check all Expressway sessions use postOnly=true config
        """
        regex = re.compile(self.sbij_ouch_regex)
        liquidity_str = "postOnly=true"
        for cl in filtered_vms():
            cl.get_vms()
            vms = cl.getVmsByCommandRegex(JAPAN_HST_CONSTS["SBIJ_BARCLAYS"][1])
            for vm in vms:
                for command in vm.vmdata.commands:
                    m = regex.match(command)
                    if m:
                        if m.group(1) in self.sbij_expressway_ips:
                            self.assertTrue(
                                liquidity_str in command,
                                "SBIJ Expressway session in %s not configured to only add liquidity" % vm.vmdata.filename
                            )
                        self.assertTrue(
                            int(m.group(2)) == 0,
                            "SBIJ Expressway gateway %s not using sequence=0 to prevent rewind see CORE-30339" % vm.vmdata.filename
                        )
                        if liquidity_str in command:
                            self.assertTrue(
                                m.group(1) in self.sbij_expressway_ips,
                                "Non-Expressway SBIJ gateway in %s configured to only add liquidity" % vm.vmdata.filename
                            )

    def test_super_gw_unique_mux(self):
        """
        COP-58500
        - If it is an OM super gateway (OSE, TOCOM, SGX OM, HKFE, ASX OM), sessions should have unique muxes for each talker
        - If it is using "SPLIT_SERVER=true", the muxes used for the talkers and pollers should be on the same numa node as the gateway
        COP-64690
        - EDIT: the case where talkerCpuSet=other is also fine for wire gateways
        """
        for cl in filtered_vms():
            for vm in cl.get_vms():
                if vm.vmdata.vmname in self.unique_talker_mux_exempted:
                    continue

                if self.is_super_gateway(vm):
                    vm_muxes = self.get_session_talker_muxes(vm)

                    if vm_muxes:
                        self.assertTrue(len(set(vm_muxes)) == len(vm_muxes),
                                        'talker mux not unique for each session in {0:s}'.format(vm.vmdata.vmname))

                        if vm.vmdata.splitServer:
                            for mux_num in vm_muxes:
                                self.assertTrue(mux_num % 2 == vm_muxes[0] % 2,
                                                'at least one talker mux is not on the right numa node  in {0:s}'.format(
                                                    vm.vmdata.vmname))
                            self.assertTrue(int(vm.vmdata.instance) % 2 == vm_muxes[0] % 2,
                                            'talker mux are not on the right numa node  in {0:s}'.format(
                                                vm.vmdata.vmname))

    def test_super_gw_unique_mux2(self):
        """
        COP-58500 (part 2)
        Ensure that within a core talker muxes don't collide among each other
        """
        for cl in filtered_vms():
            talker_mux_per_host = {}
            for vm in cl.get_vms():
                vm_muxes = self.get_session_talker_muxes(vm)
                if vm_muxes:
                    if vm.vmdata.host not in talker_mux_per_host:
                        talker_mux_per_host[vm.vmdata.host] = []

                    if vm.vmdata.vmname in self.unique_talker_mux_exempted:
                        talker_mux_per_host[vm.vmdata.host].extend(list(set(vm_muxes)))
                    else:
                        talker_mux_per_host[vm.vmdata.host].extend(vm_muxes)

            for host, all_muxes in talker_mux_per_host.items():
                self.assertTrue(len(all_muxes) == len(set(all_muxes)), 'Conflicting talker muxes on {0:s}'.format(host))

    def test_nse_feed_setup(self):
        """
        COP-69058
        Ensure we have a maximum of 1 NSE feed per VM unless in snapshot mode
        Ensure NSE snapshot feeds are on a strewind host
        """
        regex = re.compile(self.nse_feed_regex)
        for cl in filtered_vms():
            for vm in cl.get_vms():
                count = 0
                for command in vm.vmdata.commands:
                    m = regex.match(command)
                    if m:
                        if "snapshotServer=true" not in command:
                            count += 1
                            self.assertFalse(
                                count > 1,
                                "More than 1 NSE feed in a single VM: %s" % vm.vmdata.filename
                            )
                        else:
                            self.assertTrue(
                                "strewind" in vm.vmdata.host,
                                "NSE feed %s running in snapshot mode must be on strewind host" % vm.vmdata.filename
                            )

    def test_india_feed_setup(self):
        """
        COP-87097
        Ensure we have a maximum of 1 India feed VM per numa node, as it's really memory-hungry
        Applies to NseIndiaMc feed and BSEI/BSEQ feeds
        """
        nsefeed_regex = re.compile(self.nse_feed_regex)
        bsefeed_regex = re.compile(self.bse_feed_regex)
        mux_regex = re.compile(r"^\/INIT\/setInstanceNumber *(\d+)")
        india_feed_count = {}
        for cl in filtered_vms():
            if 'mum' not in cl.core:  # skip checking non-mum cores
                continue
            for vm in cl.get_vms():
                numanode = None
                if vm.vmdata.vmname in ['NSEMCUAT', "NSEMCCDTEST", "NSEQMC1TEST"]:  # exception for CORE-26495 testing
                    continue
                for command in vm.vmdata.commands:
                    mux = mux_regex.match(command)
                    if mux:
                        numanode = int(mux.groups()[0]) % 2
                    if nsefeed_regex.match(command) or bsefeed_regex.match(command):
                        hostname = vm.vmdata.host.split('.')[0] + '.' + cl.core
                        if numanode is not None:
                            hostnode = hostname + '-' + str(numanode)
                            if hostnode in india_feed_count.keys():
                                india_feed_count[hostnode] = india_feed_count[hostnode] + 1
                            else:
                                india_feed_count[hostnode] = 1
                            break
                        else:
                            self.assertFalse(True, 'Could not detect VM instance number')
                            break
        # exceptions - nodes allowed to have more than 1 feed
        exceptions = {
            'strewind01.mum04-0': 2,
            'strewind01.mum04-1': 3,
            'strewind02.mum04-1': 3,  # added to silence unittests AAA
            'strewind02.mum04-0': 3,  # added to silence unittests AW
            'core101.mum04-1': 2,  # NSEG feed is pretty small
            'core015.mum04-0': 2  # added to silence unittests AAA
        }

        for hostnode, count in india_feed_count.items():
            if hostnode in exceptions.keys():
                maxcount = exceptions[hostnode]
            else:
                maxcount = 1
            self.assertFalse(count > maxcount, 'Numa node %s has too many India feeds' % hostnode)

    def test_syd02_ttl10(self):
        """
            COP-70922
            Ensure all syd02 apps have &ttl=10 in the start line
            Strictly speaking should use ansible repo,
            but for now we use the fact that all core and fab hosts in syd02 start with '1'
            (fab1xx, core1xx)
        """
        syd02_regex = '(core1|fab1)[0-9]{2}'
        ttl_regex = 'ttl=10'
        cl = cluster.get_cluster_by_name('syd03', coreops_commands_path=COREOPS_COMMANDS_PATH)
        for vm in cl.get_vms():
            if re.match(syd02_regex, vm.vmdata.host):
                all_molds = [a.startMoldOptions for a in vm.apps if a.startMoldOptions]
                for mld in all_molds:
                    self.assertTrue(re.search(ttl_regex, mld),
                                    '{} misses ttl=10 in the mold start line'.format(vm.vmdata.vmname))

    def test_india_feeds_for_segments(self):
        regex = re.compile(self.nse_feed_regex)
        feeds = []
        for cl in filtered_vms():
            if "mum" not in cl.core:
                continue
            for vm in cl.get_vms():
                for command in vm.vmdata.commands:
                    if regex.match(command):
                        feeds.append(vm)
                        break

        failing = []
        for vm in feeds:
            segments = []
            for command in vm.vmdata.commands:
                seg = re.search(r"segment=.*?\s", command)
                if seg and not "#" == command[0]:
                    segments.append(seg.group().split("=")[1][:-1])
            if len(set(segments)) > 1: failing.append(vm.vmdata.vmname)

        self.assertTrue(len(failing) == 0,
                        "NSE/NSEQ feed VM(s): {} do not have a unique segment code".format(", ".join(failing)))

    def test_passwords_regexes(self):
        venueCore = {"SGXQ": "sin01"}

        # No duplicate characters
        def SGXQ(p):
            return len(set(p)) == len(p)

        failing = []
        for venue in venueCore:
            for cl in filtered_vms():
                if cl.core == venueCore[venue]:
                    for gw in cl.getGatewaysByVenue(venue):
                        p = re.search(r"newPassword=.*?&", gw.url).group().split("=")[1][:-1]
                        if not locals()[venue](p):
                            failing.append(gw.vm.vmdata.vmname)

        self.assertTrue(len(failing) == 0, "VMs: {} do not meet password requirements".format(", ".join(failing)))

    def test_broker_guis_for_commands_file(self):
        guiDir = COREOPS_SCRIPTS_PATH + "/brokerlimits/websites/flask_erms_gui/erms/config/gui"
        guis = [i for i in os.listdir(guiDir) if not i in ["__init__.py", "default.py"]]
        missing = []
        for g in guis:
            bot = get_output("grep self.BOT {}/{} | grep -v '{}'".format(guiDir, g, ("\|").join(IGNORE_CLUSTERS)))
            if bot == '': continue
            host, port, app = eval(re.search(r'\((.*?)\)', bot).group(1))
            server, core = host.split(".")[0:2]
            cmdFileRegex = ("/").join([COREOPS_COMMANDS_PATH, core, "apps", server + "*.commands"])
            botClass = "com\.ewt\.applications\.bot\.limits?\.LimitBot"
            res = get_output("grep {} {} | egrep {}".format(app, cmdFileRegex, botClass))
            if not len(res): missing.append(g)

        self.assertTrue(len(missing) == 0,
                        "Broker GUI(s): {} are missing corresponding command(s) file".format((", ").join(missing)))

    def test_broker_guis_for_instance(self):
        guiDir = COREOPS_SCRIPTS_PATH + "/brokerlimits/websites/flask_erms_gui/erms/config/gui"
        guis = [i for i in os.listdir(guiDir) if not i in ["__init__.py", "default.py"]]
        failing = []
        for g in guis:
            bot = get_output("grep self.BOT {}/{} | grep -v '{}'".format(guiDir, g, ("\|").join(IGNORE_CLUSTERS)))
            if bot == '': continue
            host, port, app = eval(re.search(r'\((.*?)\)', bot).group(1))
            server, core = host.split(".")[0:2]
            cmdFileRegex = ("/").join([COREOPS_COMMANDS_PATH, core, "apps", server + "*.commands"])
            botCmdFile = get_output("grep -l {} {}".format(app, cmdFileRegex))
            vm = VM.fromCommandsFile(botCmdFile)
            if not all([vm.vmdata.hasText, port == 1500 + vm.vmdata.instance]): failing.append(g)
        self.assertTrue(len(failing) == 0,
                        "Broker GUI(s): {} text port does not match command file".format(", ".join(failing)))

    def test_woori_gateway_for_order_range(self):
        regex = re.compile(r"^\/.*mt_cside::applications::gw::woori::WooriGatewayHold.*")
        gateways = []
        for cl in filtered_vms():
            if "bus01" not in cl.core:
                continue
            for vm in cl.get_vms():
                for command in vm.vmdata.commands:
                    if regex.match(command):
                        gateways.append(vm)
                        break

        order_ranges = []
        for command in gateways[0].vmdata.commands:
            order_range = re.search(r"orderNumRange=.*?\s", command)
            if order_range and not "#" == command[0]:
                order_ranges.append([int(i) for i in order_range.group().split("=")[1][:-1].split("-")])

        order_ranges = sorted(order_ranges)
        for i in range(1, len(order_ranges)):
            self.assertFalse(order_ranges[i - 1][0] <= order_ranges[i][0] <= order_ranges[i - 1][1],
                             "KRXF Woori orderNumRanges must be unique across sessions")

    def test_nse_snapshot_for_streamID(self):
        regex = re.compile(self.nse_feed_regex)
        feeds = []
        for cl in filtered_vms():
            if "mum" not in cl.core:
                continue
        for vm in cl.get_vms():
            for command in vm.vmdata.commands:
                if regex.match(command):
                    feeds.append(vm)
                    break

        failing = []
        for vm in feeds:
            if ("UAT" in vm.vmdata.vmname) or "TEST" in vm.vmdata.vmname: continue
            for command in vm.vmdata.commands:
                if regex.match(command):
                    if not "snapshot=solace://" in command: continue
                    streamID = int(re.search(r"streamId=.*?\s", command).group().split("=")[1][:-1])
                    snapshot = re.search(r"snapshot=solace.*?\s", command).group()
                    queue = [i for i in snapshot.split("&") if i.startswith("queue")][0]
                    queueID = int(queue.split(".")[4])
                    if not streamID == queueID:
                        failing.append(vm.vmdata.vmname)

        self.assertTrue(len(failing) == 0,
                        "NSE feed VM(s): {} do(es) not have matching stream and queue IDs".format(", ".join(failing)))


@pytest.mark.integtest
class TestMoldHubConfig(unittest.TestCase):
    def setUp(self):
        from scripts.coputils.apps import MoldHub

        # these apps use moldhub address in their configuration without unique
        # identifier that would allow us to know if intention is moldhub address
        # or corestream (mold/cengine) addr
        self.mold_hub = MoldHub
        self.moldhub_apps = ["MTMPR", "MOLDSP", "MEWIND"]
        self.moldhub_addrs = self.mold_hub.MoldHub.get_moldhub_config_addrs_dict()
        self.vm = None
        self.cmd_line = None
        self.cmd_line_addr = None
        self.cmd_line_port = None

        # some cores to ignore - just during dev testing
        self.my_ignored_clusters = ["slo08"]

        # ignore these classes
        self.my_ignored_classes = ["com.ewt.quoteserver.feeds.collar.CollarFeed"]

        # ignore these commands for now while we figure out how to deal with them
        self.my_ignored_commands = [
            "setPriceCollarReader",
            "addPriceCollarReader",
            "addServer collar",
            "addServerPort collar",
            "addPriceCollarReader",
        ]

    @property
    def core_name(self):
        return self.vm.vmdata.core

    @property
    def vm_name(self):
        return self.vm.vmdata.vmname

    @property
    def host_name(self):
        return self.vm.vmdata.host.split(".")[0]

    @property
    def moldhub_addr(self):
        try:
            result = self.moldhub_addrs[self.core_name.upper()]["address"]
        except KeyError:
            raise KeyError("Missing such core %s in moldhub_config_data.py" % self.core_name.upper())
        return result

    @property
    def moldhub_port(self):
        return self.moldhub_addrs[self.core_name.upper()]["port"]

    def my_filtered_vms(self):
        """

        :return:
        """
        for vms in filtered_vms():
            for self.vm in vms.get_vms():
                if self.vm.vmdata.core in self.my_ignored_clusters:
                    continue
                yield self.vm

    def _set_addr_port(self, regex):
        """

        :param regex:
        :return:
        """
        m = re.match(regex, self.cmd_line)
        try:
            self.cmd_line_addr = m.group(1)
            self.cmd_line_port = m.group(2)
        except AttributeError:
            raise AttributeError(
                "cmd: %s :: %s" % (self.cmd_line, self.vm.apps[0].classname)
            )

    def _handle_class_exclusions(self):
        """

        :return:
        """
        for excluded_class in self.my_ignored_classes:
            if excluded_class in self.cmd_line:
                raise ValueError

    def _handle_cmd_exclusions(self):
        """

        :return:
        """
        for excluded_app in self.my_ignored_commands:
            if excluded_app in self.cmd_line:
                raise ValueError

    def _set_vm_data(self):
        """

        :return:
        """
        if "mold://" in self.cmd_line:
            if "/addWriter" in self.cmd_line:
                regex = r".*mold://0\.0\.0\.0:\d{5}\@(.*?):(\d{5}).*"
            else:
                regex = r".*mold://(.*?):(\d{5}).*"
            self._set_addr_port(regex)

    def _normalize_vm_data(self):
        """
        will check moldhub configs for VM to ensure they match what's in moldhub.py
        :return:
        """
        for self.vm in self.my_filtered_vms():
            for self.cmd_line in self.vm.vmdata.commands:
                try:
                    self._handle_class_exclusions()
                    self._handle_cmd_exclusions()
                except ValueError:
                    continue
                else:
                    self._set_vm_data()
                    yield 1

    def _test_assert_addr(self):
        self.assertTrue(
            self.moldhub_addr == self.cmd_line_addr,
            "MoldHub addr mis-match: %s-%s.%s :: %s != %s %s"
            % (
                self.host_name,
                self.vm_name,
                self.core_name.lower(),
                self.moldhub_addr,
                self.cmd_line_addr,
                self.cmd_line,
            ),
        )

    def _test_assert_port(self):
        self.assertTrue(
            self.moldhub_port == self.cmd_line_port,
            "MoldHub port mis-match: %s-%s.%s :: %s != %s"
            % (
                self.host_name,
                self.vm_name,
                self.core_name.lower(),
                self.moldhub_port,
                self.cmd_line_port,
            ),
        )

    def test_corestream_doppelganger(self):
        """these tests are for apps where the config syntax is like how corestreams
        are configured"""
        for c in self._normalize_vm_data():
            if self.vm_name in self.moldhub_apps and "start mold://" in self.cmd_line:
                self._test_assert_addr()
                self._test_assert_port()

    def test_moldhub_config_lines(self):
        for c in self._normalize_vm_data():
            if "hubUrl=mold://" in self.cmd_line:
                self._test_assert_addr()
                self._test_assert_port()


@pytest.mark.integtest
class TestJapanHstCount(unittest.TestCase):
    """
    test commands files to ensure the native Japan connections matches our HST registration
    https://theloop.virtu.com/display/COM/HST+Key+Information
    """

    def setUp(self):
        pass

    def hst_count_eq(self, hst_venue):
        """
        Counts the number of apps with a specific commands regex, alerts if it is not equal to the HST count
        """
        count = 0
        for cl in filtered_vms(IGNORE_CLUSTERS_HST):
            cl.get_vms()
            cl.getGateways()
            count += getAppCountByCommandRegex(cl, JAPAN_HST_CONSTS[hst_venue][1])
            self.assertLessEqual(
                count,
                JAPAN_HST_CONSTS[hst_venue][0],
                "HST venue %s has more connections than our registration! Please contact apac-compliance@virtu.com"
                % hst_venue,
            )
        self.assertEqual(
            count,
            JAPAN_HST_CONSTS[hst_venue][0],
            "HST venue %s has fewer connections than our registration! Please contact apac-compliance@virtu.com"
            % hst_venue,
        )

    def test_hst_count_ose(self):
        """
        Counts the number of target IPs we have for OSE TAP count, alerts if it is not equal to the HST count
        """
        # self.skipTest("Been broken for days.COP-120349")
        tap_ip_regex = r"^\/.*addSession omex:\/\/[0-9A-Z]{10}:\S*@(\d{0,3}.\d{0,3}.\d{0,3}.\d{0,3}:.\d{0,5}).*tunnelPort.*"
        regex = re.compile(tap_ip_regex)
        for OSE_BROKER in ["OSE_ALL_OM"]:
            ip_set = set()
            for cl in filtered_vms(IGNORE_CLUSTERS_HST):
                vms = cl.getVmsByCommandRegex(JAPAN_HST_CONSTS[OSE_BROKER][1])
                for vm in vms:
                    for command in vm.vmdata.commands:
                        m = regex.match(command)
                        if m:
                            ip = m.group(1)
                            ip_set.add(ip)
                            self.assertLessEqual(len(ip_set), JAPAN_HST_CONSTS[OSE_BROKER][0])
            self.assertEqual(len(ip_set), JAPAN_HST_CONSTS[OSE_BROKER][0])

    def test_hst_count(self):
        for hst_venue in JAPAN_HST_CONSTS:
            if hst_venue not in ["OSE_BARCLAYS_OM", "OSE_ALL_OM"]:
                self.hst_count_eq(hst_venue)

