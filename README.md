Bogon ASN Filter Policy Configuration Examples
----------------------------------------------

Contact: Job Snijders <job@ntt.net>

Background:

    https://ripe72.ripe.net/wp-content/uploads/presentations/151-RIPE72_bogon_ASNs_JobSnijders.pdf
    https://ripe72.ripe.net/archives/video/193/
    http://mailman.nlnog.net/pipermail/nlnog/2016-May/002584.html
    http://mailman.nanog.org/pipermail/nanog/2016-June/086078.html

Juniper:
========

    policy-options {
        as-path-group bogon-asns {
            /* RFC7607 */
            as-path zero ".* 0 .*";
            /* RFC 4893 AS_TRANS */
            as-path as_trans ".* 23456 .*";
            /* RFC 5398 and documentation/example ASNs */
            as-path examples1 ".* [64496-64511] .*";
            as-path examples2 ".* [65536-65551] .*";
            /* RFC 6996 Private ASNs*/
            as-path reserved1 ".* [64512-65534] .*";
            as-path reserved2 ".* [4200000000-4294967294] .*";
            /* RFC 6996 Last 16 and 32 bit ASNs */
            as-path last16 ".* 65535 .*";
            as-path last32 ".* 4294967295 .*";
            /* RFC IANA reserved ASNs*/
            as-path iana-reserved ".* [65552-131071] .*";
        }
        policy-statement import_from_ebgp {
            term bogon-asns {
                from as-path-group bogon-asns;
                then reject;
            }
            term .....
        }
    }

Cisco IOS XR:
=============

    as-path-set bogon-asns
      # RFC7607
      ios-regex '_0_',
      # 2 to 4 byte ASN migrations
      passes-through '23456',
      # RFC5398
      passes-through '[64496..64511]',
      passes-through '[65536..65551]',
      # RFC6996
      passes-through '[64512..65534]',
      passes-through '[4200000000..4294967294]',
      # RFC7300
      passes-through '65535',
      passes-through '4294967295',
      # IANA reserved
      passes-through '[65552..131071]'
    end-set

    route-policy import_from_ebgp
      if as-path in bogon-asns then
        drop
      else
        ......
      endif
    end-policy

BIRD:
=====

    define BOGON_ASNS = [ 0,                      # RFC 7607
                          23456,                  # RFC 4893 AS_TRANS
                          64496..64511,           # RFC 5398 and documentation/example ASNs
                          64512..65534,           # RFC 6996 Private ASNs
                          65535,                  # RFC 6996 Last 16 bit ASN
                          65536..65551,           # RFC 5398 and documentation/example ASNs
                          65552..131071,          # RFC IANA reserved ASNs
                          4200000000..4294967294, # RFC 6996 Private ASNs
                          4294967295 ];           # RFC 6996 Last 32 bit ASN
    
    function ebgp_import()
    int set bogon_asns;
    {
        # ignore bogon AS_PATHs
        bogon_asns = BOGON_ASNS;
        if ( bgp_path ~ bogon_asns ) then {
            print "Reject: bogon AS_PATH: ", net, " ", bgp_path;
            reject;
        }
        .......
    }


Nokia SR OS:
============

    bgp
        error-handling
            # RFC 7607 AS 0
            update-fault-tolerance
        exit
    exit

    policy-options
        begin
        as-path-group "bogon-asns"
            # RFC 4893 AS_TRANS
            entry 10 expression ".* 23456 .*"
            # RFC 5398 and documentation/example ASNs
            entry 15 expression ".* [64496-64511] .*"
            entry 20 expression ".* [65536-65551] .*"
            # RFC 6996 private ASNs
            entry 25 expression ".* [64512-65534] .*"
            entry 30 expression ".* [4200000000-4294967294] .*"
            RFC 6996 last 16-bit and 32-bit ASNs
            entry 35 expression ".* 65535 .*"
            entry 40 expression ".* 4294967295 .*"
            # IANA reserved ASNs
            entry 45 expression ".* [65552-131071] .*"
        exit
        policy-statement "import_from_ebgp"
            entry 10
                from
                    as-path-group "bogon-asns"
                exit
                action reject
            exit
        exit
        commit
    exit


Cisco IOS & IOS XE:
===================

    ! Thanks to James Bensley, Antonio Prado, Nick Hilliard, Tim Osburn
    ! Warning: Some IOS platforms might have too little CPU power
    ! to deal with these filters.
    ! Warning: this is a complex set of regular expressions, deploy
    ! and maintain at your own risk. 
    
    ip as-path access-list 99 permit _0_
    ip as-path access-list 99 permit _23456_
    ip as-path access-list 99 permit _(6449[6-9])_|_(6450[0-9])_|_(6451[0-1])_|_(6553[6-9])_|_(6554[0-9])_|_(6555[0-1])_
    ip as-path access-list 99 permit _6(4(5(1[2-9]|[2-9][0-9])|[6-9][0-9][0-9])|5([0-4][0-9][0-9]|5([0-2][0-9]|3[0-5])))_
    ip as-path access-list 99 permit _6555[2-9]_|_655[6-9][0-9]_|_65[6-9][0-9][0-9]_|_6[6-9][0-9][0-9][0-9]_
    ip as-path access-list 99 permit _[7-9][0-9][0-9][0-9][0-9]_|_1[0-2][0-9][0-9][0-9][0-9]_|_130[0-9][0-9][0-9]_
    ip as-path access-list 99 permit _1310[0-6][0-9]_|_13107[0-1]_
    ip as-path access-list 99 permit _42[0-8][0-9][0-9][0-9][0-9][0-9][0-9][0-9]_
    ip as-path access-list 99 permit _(429[0-3][0-9][0-9][0-9][0-9][0-9][0-9])_|_(4294[0-8][0-9][0-9][0-9][0-9][0-9])_
    ip as-path access-list 99 permit _(42949[0-5][0-9][0-9][0-9][0-9])_|_(429496[0-6][0-9][0-9][0-9])_
    ip as-path access-list 99 permit _(4294967[0-1][0-9][0-9])_|_(42949672[0-8][0-9])_|_(429496729[0-4])_
   
    route-map ebgp-in deny 1
      match as-path 99
