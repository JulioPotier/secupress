<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );

/*------------------------------------------------------------------------------------------------*/
/* ON MODULE SETTINGS SAVE ====================================================================== */
/*------------------------------------------------------------------------------------------------*/

/**
 * Callback to filter, sanitize and de/activate submodules
 *
 * @since 1.0
 * @return array $settings
 */
function __secupress_firewall_settings_callback( $settings ) {
	$modulenow = 'firewall';
	$settings = $settings ? $settings : array();

	if ( isset( $settings['bbq-headers_user-agents-header'] ) ) {
		secupress_activate_submodule( $modulenow, 'user-agents-header' );
	} else {
		secupress_deactivate_submodule( $modulenow, 'user-agents-header' );
	}

	if ( isset( $settings['bbq-headers_request-methods-header'] ) ) {
		secupress_activate_submodule( $modulenow, 'request-methods-header' );
	} else {
		secupress_deactivate_submodule( $modulenow, 'request-methods-header' );
	}

	if ( isset( $settings['bbq-url-content_bad-contents'] ) ) {
		secupress_activate_submodule( $modulenow, 'bad-url-contents' );
	} else {
		secupress_deactivate_submodule( $modulenow, 'bad-url-contents' );
	}

	if ( isset( $settings['bbq-url-content_bad-url-length'] ) ) {
		secupress_activate_submodule( $modulenow, 'bad-url-length' );
	} else {
		secupress_deactivate_submodule( $modulenow, 'bad-url-length' );
	}

	if ( isset( $settings['bbq-url-content_bad-sqli-scan'] ) ) {
		secupress_activate_submodule( $modulenow, 'bad-sqli-scan' );
	} else {
		secupress_deactivate_submodule( $modulenow, 'bad-sqli-scan' );
	}

	return $settings;
}


/*------------------------------------------------------------------------------------------------*/
/* INSTALL ====================================================================================== */
/*------------------------------------------------------------------------------------------------*/

// Create default option on install.

add_action( 'wp_secupress_first_install', '__secupress_install_firewall_module' );

function __secupress_install_firewall_module( $module = 'all' ) {
	if ( 'all' === $module || 'firewall' === $module ) {
		update_site_option( 'secupress_firewall_settings', array(
			'bbq-headers_user-agents-header'      => '1',
			'bbq-headers_user-agents-list'        => secupress_firewall_bbq_headers_user_agents_list_default(),
			'bbq-headers_request-methods-header'  => '1',
			'bbq-url-content_bad-contents'        => '1',
			'bbq-url-content_bad-contents-list'   => secupress_firewall_bbq_url_content_bad_contents_list_default(),
			'bbq-url-content_bad-url-length'      => '1',
		) );
	}
}


/*------------------------------------------------------------------------------------------------*/
/* MAKE SURE OUR LISTS ARE NOT EMPTY: FILTER OUTPUT ============================================= */
/*------------------------------------------------------------------------------------------------*/

// Bad User Agents.

add_filter( 'secupress_get_module_option_bbq-headers_user-agents-list', '__secupress_firewall_bbq_headers_user_agents_list_default_if_empty', PHP_INT_MAX, 3 );

function __secupress_firewall_bbq_headers_user_agents_list_default_if_empty( $value, $default, $module ) {
	if ( 'firewall' === $module && ! trim( $value ) ) {
		return secupress_firewall_bbq_headers_user_agents_list_default();
	}
	return $value;
}


add_filter( 'pre_secupress_get_module_option_bbq-headers_user-agents-list', '__secupress_firewall_pre_bbq_headers_user_agents_list_default_if_empty', PHP_INT_MAX, 3 );

function __secupress_firewall_pre_bbq_headers_user_agents_list_default_if_empty( $value, $default, $module ) {
	if ( 'firewall' === $module && isset( $value ) && ! trim( $value ) ) {
		return secupress_firewall_bbq_headers_user_agents_list_default();
	}
	return $value;
}


function secupress_firewall_bbq_headers_user_agents_list_default() {
	return 'ADSARobot, ah-ha, almaden, aktuelles, Anarchie, amzn_assoc, ASPSeek, ASSORT, ATHENS, Atomz, attach, attache, autoemailspider, BackWeb, Bandit, BatchFTP, bdfetch, big.brother, BlackWidow, bmclient, Boston Project, BravoBrian SpiderEngine MarcoPolo, Bot mailto:craftbot@yahoo.com, Buddy, Bullseye, bumblebee, capture, CherryPicker, ChinaClaw, CICC, clipping, Collector, Copier, Crescent, Crescent Internet ToolPak, Custo, cyberalert, DA$, Deweb, diagem, Digger, Digimarc, DIIbot, DISCo, DISCo Pump, DISCoFinder, Download Demon, Download Wonder, Downloader, Drip, DSurf15a, DTS.Agent, EasyDL, eCatch, ecollector, efp@gmx.net, Email Extractor, EirGrabber, email, EmailCollector, EmailSiphon, EmailWolf, Express WebPictures, ExtractorPro, EyeNetIE, FavOrg, fastlwspider, Favorites Sweeper, Fetch, FEZhead, FileHound, FlashGet WebWasher, FlickBot, fluffy, FrontPage, GalaxyBot, Generic, Getleft, GetRight, GetSmart, GetWeb!, GetWebPage, gigabaz, Girafabot, Go!Zilla, Go!Zilla, Go-Ahead-Got-It, GornKer, gotit, Grabber, GrabNet, Grafula, Green Research, grub-client, Harvest, hhjhj@yahoo, hloader, HMView, HomePageSearch, http generic, HTTrack, httpdown, httrack, ia_archiver, IBM_Planetwide, Image Stripper, Image Sucker, imagefetch, IncyWincy, Indy*Library, Indy Library, informant, Ingelin, InterGET, Internet Ninja, InternetLinkagent, Internet Ninja, InternetSeer.com, Iria, Irvine, JBH*agent, JetCar, JOC, JOC Web Spider, JustView, KWebGet, Lachesis, larbin, LeechFTP, LexiBot, lftp, libwww, likse, Link, Link*Sleuth, LINKS ARoMATIZED, LinkWalker, LWP, lwp-trivial, Mag-Net, Magnet, Mac Finder, Mag-Net, Mass Downloader, MCspider, Memo, Microsoft.URL, MIDown tool, Mirror, Missigua Locator, Mister PiX, MMMtoCrawl/UrlDispatcherLLL, ^Mozilla$, Mozilla.*Indy, Mozilla.*NEWT, Mozilla*MSIECrawler, MS FrontPage*, MSFrontPage, MSIECrawler, MSProxy, multithreaddb, nationaldirectory, Navroad, NearSite, NetAnts, NetCarta, NetMechanic, netprospector, NetResearchServer, NetSpider, Net Vampire, NetZIP, NetZip Downloader, NetZippy, NEWT, NICErsPRO, Ninja, NPBot, Octopus, Offline Explorer, Offline Navigator, OpaL, Openfind, OpenTextSiteCrawler, OrangeBot, PageGrabber, Papa Foto, PackRat, pavuk, pcBrowser, PersonaPilot, Ping, PingALink, Pockey, Proxy, psbot, PSurf, puf, Pump, PushSite, QRVA, RealDownload, Reaper, Recorder, ReGet, replacer, RepoMonkey, Robozilla, Rover, RPT-HTTPClient, Rsync, Scooter, SearchExpress, searchhippo, searchterms.it, Second Street Research, Seeker, Shai, Siphon, sitecheck, sitecheck.internetseer.com, SiteSnagger, SlySearch, SmartDownload, snagger, Snake, SpaceBison, Spegla, SpiderBot, sproose, SqWorm, Stripper, Sucker, SuperBot, SuperHTTP, Surfbot, SurfWalker, Szukacz, tAkeOut, tarspider, Teleport Pro, Templeton, TrueRobot, TV33_Mercator, UIowaCrawler, UtilMind, URLSpiderPro, URL_Spider_Pro, Vacuum, vagabondo, vayala, visibilitygap, VoidEYE, vspider, Web Downloader, w3mir, Web Data Extractor, Web Image Collector, Web Sucker, Wweb, WebAuto, WebBandit, web.by.mail, Webclipping, webcollage, webcollector, WebCopier, webcraft@bea, webdevil, webdownloader, Webdup, WebEMailExtrac, WebFetch, WebGo IS, WebHook, Webinator, WebLeacher, WEBMASTERS, WebMiner, WebMirror, webmole, WebReaper, WebSauger, Website, Website eXtractor, Website Quester, WebSnake, Webster, WebStripper, websucker, webvac, webwalk, webweasel, WebWhacker, WebZIP, Wget, Whacker, whizbang, WhosTalking, Widow, WISEbot, WWWOFFLE, x-Tractor, ^Xaldon WebSpider, WUMPUS, Xenu, XGET, Zeus.*Webster, Zeus';
}


// Bad URL contents.

add_filter( 'secupress_get_module_option_bbq-url-content_bad-contents-list', '__secupress_firewall_bbq_url_content_bad_contents_list_default_if_empty', PHP_INT_MAX, 3 );

function __secupress_firewall_bbq_url_content_bad_contents_list_default_if_empty( $value, $default, $module ) {
	if ( 'firewall' === $module && ! trim( $value ) ) {
		return secupress_firewall_bbq_url_content_bad_contents_list_default();
	}
	return $value;
}


add_filter( 'pre_secupress_get_module_option_bbq-url-content_bad-contents-list', '__secupress_firewall_pre_bbq_url_content_bad_contents_list_default_if_empty', PHP_INT_MAX, 3 );

function __secupress_firewall_pre_bbq_url_content_bad_contents_list_default_if_empty( $value, $default, $module ) {
	if ( 'firewall' === $module && isset( $value ) && ! trim( $value ) ) {
		return secupress_firewall_bbq_url_content_bad_contents_list_default();
	}
	return $value;
}


function secupress_firewall_bbq_url_content_bad_contents_list_default() {
	return 'AND 1=, AND+1=, AND%201=, information_schema, UNI'.'ON SEL'.'ECT, UNI'.'ON+SEL'.'ECT, UNI'.'ON%20SEL'.'ECT,  UNI'.'ON ALL SEL'.'ECT, UNI'.'ON+ALL+SEL'.'ECT, UNI'.'ON%20ALL%20SEL'.'ECT, ev'.'al(, wp-config.php, %'.'00, %%'.'30%'.'30, GLOBALS[, .ini, REQUEST[, et'.'c/pas'.'swd, ba'.'se'.'64'.'_en'.'co'.'de, ba'.'se'.'64'.'_de'.'co'.'de, javascript:, ../, 127.0.0.1, inp'.'ut_fi'.'le';
}
