<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );

/** --------------------------------------------------------------------------------------------- */
/** MAKE SURE OUR LISTS ARE NOT EMPTY: FILTER OUTPUT ============================================ */
/** --------------------------------------------------------------------------------------------- */

/**
 * Bad User Agents.
 */
add_filter( 'pre_secupress_get_module_option_bbq-headers_user-agents-list', 'secupress_firewall_pre_bbq_headers_user_agents_list_default_if_empty', PHP_INT_MAX, 3 );
/**
 * Filter the option to not return an empty list of forbidden user-agents.
 *
 * @since 1.0
 *
 * @param (mixed)  $value   The filtered value. Should be `null` by default.
 * @param (string) $default The default value.
 * @param (string) $module  The module.
 *
 * @return (string)
 */
function secupress_firewall_pre_bbq_headers_user_agents_list_default_if_empty( $value, $default, $module ) {
	if ( 'firewall' === $module && isset( $value ) && ! trim( $value ) ) {
		return secupress_firewall_bbq_headers_user_agents_list_default();
	}
	return $value;
}


add_filter( 'secupress_get_module_option_bbq-headers_user-agents-list', 'secupress_firewall_bbq_headers_user_agents_list_default_if_empty', PHP_INT_MAX, 3 );
/**
 * Filter the option to not return an empty list of forbidden user-agents.
 *
 * @since 1.0
 *
 * @param (mixed)  $value   The option value.
 * @param (string) $default The default value.
 * @param (string) $module  The module.
 *
 * @return (string)
 */
function secupress_firewall_bbq_headers_user_agents_list_default_if_empty( $value, $default, $module ) {
	if ( 'firewall' === $module && ! trim( $value ) ) {
		return secupress_firewall_bbq_headers_user_agents_list_default();
	}
	return $value;
}


/**
 * Get user-agents forbidden by default.
 *
 * @since 1.0
 *
 * @return (string) A comma-separated list.
 */
function secupress_firewall_bbq_headers_user_agents_list_default() {
	return 'Gecko/2009032609 Firefox, ADSARobot, ah-ha, almaden, aktuelles, Anarchie, amzn_assoc, ASPSeek, ASSORT, ATHENS, Atomz, attach, autoemailspider, BackWeb, Bandit, BatchFTP, bdfetch, big.brother, BlackWidow, bmclient, Boston Project, BravoBrian SpiderEngine MarcoPolo, Bot mailto:craftbot@yahoo.com, Buddy, Bullseye, bumblebee, capture, CherryPicker, ChinaClaw, CICC, clipping, Collector, Copier, Crescent, Crescent Internet ToolPak, Custo, cyberalert, DA$, Deweb, diagem, Digger, Digimarc, DIIbot, DISCo, DISCo Pump, DISCoFinder, Download Demon, Download Wonder, Downloader, Drip, DSurf15a, DTS.Agent, EasyDL, eCatch, ecollector, efp@gmx.net, Email Extractor, EirGrabber, EmailCollector, EmailSiphon, EmailWolf, Express WebPictures, ExtractorPro, EyeNetIE, FavOrg, fastlwspider, Favorites Sweeper, FEZhead, FileHound, FlashGet WebWasher, FlickBot, fluffy, FrontPage, GalaxyBot, Generic, Getleft, GetRight, GetSmart, GetWeb!, GetWebPage, gigabaz, Girafabot, Go!Zilla, Go!Zilla, Go-Ahead-Got-It, GornKer, gotit, Grabber, GrabNet, Grafula, Green Research, grub-client, Harvest, hhjhj@yahoo, hloader, HMView, HomePageSearch, http generic, HTTrack, httpdown, httrack, ia_archiver, IBM_Planetwide, Image Stripper, Image Sucker, imagefetch, IncyWincy, Indy*Library, Indy Library, informant, Ingelin, InterGET, Internet Ninja, InternetLinkagent, Internet Ninja, InternetSeer.com, Iria, Irvine, JBH*agent, JetCar, JOC, JOC Web Spider, JustView, KWebGet, Lachesis, larbin, LeechFTP, LexiBot, lftp, libwww, likse, Link*Sleuth, LINKS ARoMATIZED, LinkWalker, LWP, lwp-trivial, Mag-Net, Magnet, Mac Finder, Mag-Net, Mass Downloader, MCspider, Memo, Microsoft.URL, MIDown tool, Mirror, Missigua Locator, Mister PiX, MMMtoCrawl/UrlDispatcherLLL, ^Mozilla$, Mozilla.*Indy, Mozilla.*NEWT, Mozilla*MSIECrawler, MS FrontPage*, MSFrontPage, MSIECrawler, MSProxy, multithreaddb, nationaldirectory, Navroad, NearSite, NetAnts, NetCarta, NetMechanic, netprospector, NetResearchServer, NetSpider, Net Vampire, NetZIP, NetZip Downloader, NetZippy, NEWT, NICErsPRO, Ninja, NPBot, Octopus, Offline Explorer, Offline Navigator, OpaL, Openfind, OpenTextSiteCrawler, PageGrabber, Papa Foto, PackRat, pavuk, pcBrowser, PersonaPilot, PingALink, Pockey, psbot, PSurf, puf, Pump, PushSite, QRVA, RealDownload, Reaper, Recorder, ReGet, replacer, RepoMonkey, Robozilla, Rover, RPT-HTTPClient, Rsync, Scooter, SearchExpress, searchhippo, searchterms.it, Second Street Research, Seeker, Shai, Siphon, sitecheck, sitecheck.internetseer.com, SiteSnagger, SlySearch, SmartDownload, snagger, Snake, SpaceBison, Spegla, SpiderBot, sproose, SqWorm, Stripper, Sucker, SuperBot, SuperHTTP, Surfbot, SurfWalker, Szukacz, tAkeOut, tarspider, Teleport Pro, Templeton, TrueRobot, TV33_Mercator, UIowaCrawler, UtilMind, URLSpiderPro, URL_Spider_Pro, Vacuum, vagabondo, vayala, visibilitygap, VoidEYE, vspider, Web Downloader, w3mir, Web Data Extractor, Web Image Collector, Web Sucker, Wweb, WebAuto, WebBandit, web.by.mail, Webclipping, webcollage, webcollector, WebCopier, webcraft@bea, webdevil, webdownloader, Webdup, WebEMailExtrac, WebFetch, WebGo IS, WebHook, Webinator, WebLeacher, WEBMASTERS, WebMiner, WebMirror, webmole, WebReaper, WebSauger, Website, Website eXtractor, Website Quester, WebSnake, Webster, WebStripper, websucker, webvac, webwalk, webweasel, WebWhacker, WebZIP, Wget, Whacker, whizbang, WhosTalking, Widow, WISEbot, WWWOFFLE, x-Tractor, ^Xaldon WebSpider, WUMPUS, Xenu, XGET, Zeus.*Webster, Zeus';
}


/**
 * Bad URL contents.
 */
add_filter( 'pre_secupress_get_module_option_bbq-url-content_bad-contents-list', 'secupress_firewall_pre_bbq_url_content_bad_contents_list_default_if_empty', PHP_INT_MAX, 3 );
/**
 * Filter the option to not return an empty list of forbidden contents.
 *
 * @since 1.0
 *
 * @param (mixed)  $value   The filtered value. Should be `null` by default.
 * @param (string) $default The default value.
 * @param (string) $module  The module.
 *
 * @return (string)
 */
function secupress_firewall_pre_bbq_url_content_bad_contents_list_default_if_empty( $value, $default, $module ) {
	if ( 'firewall' === $module && isset( $value ) && ! trim( $value ) ) {
		return secupress_firewall_bbq_url_content_bad_contents_list_default();
	}
	return $value;
}


add_filter( 'secupress_get_module_option_bbq-url-content_bad-contents-list', 'secupress_firewall_bbq_url_content_bad_contents_list_default_if_empty', PHP_INT_MAX, 3 );
/**
 * Filter the option to not return an empty list of forbidden contents.
 *
 * @since 1.0
 *
 * @param (mixed)  $value   The option value.
 * @param (string) $default The default value.
 * @param (string) $module  The module.
 *
 * @return (string)
 */
function secupress_firewall_bbq_url_content_bad_contents_list_default_if_empty( $value, $default, $module ) {
	if ( 'firewall' === $module && ! trim( $value ) ) {
		return secupress_firewall_bbq_url_content_bad_contents_list_default();
	}
	return $value;
}


/**
 * Get contents forbidden in URL by default.
 *
 * @since 1.0
 *
 * @return (string) A comma-separated list.
 */
function secupress_firewall_bbq_url_content_bad_contents_list_default() {
	return 'AND 1=, AND+1=, AND%201=, information_schema, UNI' . 'ON SEL' . 'ECT, UNI' . 'ON+SEL' . 'ECT, UNI' . 'ON%20SEL' . 'ECT, UNI' . 'ON ALL SEL' . 'ECT, UNI' . 'ON+ALL+SEL' . 'ECT, UNI' . 'ON%20ALL%20SEL' . 'ECT, ev' . 'al(, wp-config.php, %' . '00, %%' . '30%' . '30, GLOBALS[, .ini, REQUEST[, et' . 'c/pas' . 'swd, ba' . 'se' . '64' . '_en' . 'co' . 'de, ba' . 'se' . '64' . '_de' . 'co' . 'de, javascript:, ../, 127.0.0.1, inp' . 'ut_fi' . 'le';
}


/** --------------------------------------------------------------------------------------------- */
/** OTHER ======================================================================================= */
/** --------------------------------------------------------------------------------------------- */

add_filter( 'secupress_block_id', 'secupress_firewall_block_id' );
/**
 * Translate block IDs into understandable things.
 *
 * @since 1.1.4
 * @author Grégory Viguier
 *
 * @param (string) $module The related module.
 *
 * @return (string) The block ID.
 */
function secupress_firewall_block_id( $module ) {
	$block_ids = array(
		// Antispam.
		'AAU'  => __( 'Antispam, Anti-Usurpation', 'secupress' ),
		// URL Contents.
		'BUC'  => __( 'Bad URL Contents', 'secupress' ),
		// GeoIP.
		'GIP'  => __( 'GeoIP', 'secupress' ),
		// Request Method.
		'RMHM' => __( 'Bad Request Method', 'secupress' ),
		// User-Agent.
		'UAHT' => __( 'User-Agent With HTML Tags', 'secupress' ),
		'UAHB' => __( 'User-Agent Blacklisted', 'secupress' ),
	);

	return isset( $block_ids[ $module ] ) ? $block_ids[ $module ] : $module;
}
