<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );

/*------------------------------------------------------------------------------------------------*/
/* ON MODULE SETTINGS SAVE ====================================================================== */
/*------------------------------------------------------------------------------------------------*/

/**
 * Callback to filter, sanitize and de/activate submodules
 *
 * @since 1.0
 *
 * @param (array) $settings The module settings.
 *
 * @return (array) The sanitized and validated settings.
 */
function secupress_firewall_settings_callback( $settings ) {
	$modulenow = 'firewall';
	$activate  = secupress_get_submodule_activations( $modulenow );
	$settings  = $settings ? $settings : array();

	if ( isset( $settings['sanitized'] ) ) {
		return $settings;
	}
	$settings['sanitized'] = 1;

	/*
	 * Each submodule has its own sanitization function.
	 * The `$settings` parameter is passed by reference.
	 */

	// Bad headers.
	secupress_bad_headers_settings_callback( $modulenow, $settings, $activate );

	// Bad contents.
	secupress_bad_contents_settings_callback( $modulenow, $settings, $activate );

	// Anti Bruteforce Management.
	secupress_bruteforce_settings_callback( $modulenow, $settings, $activate );

	// Country Management.
	secupress_geoip_settings_callback( $modulenow, $settings, $activate );

	return $settings;
}


/**
 * Bad Headers plugins.
 *
 * @since 1.0
 *
 * @param (string)     $modulenow Current module.
 * @param (array)      $settings  The module settings, passed by reference.
 * @param (bool|array) $activate  Used to (de)activate plugins.
 */
function secupress_bad_headers_settings_callback( $modulenow, &$settings, $activate ) {
	// (De)Activation.
	if ( false !== $activate ) {
		secupress_manage_submodule( $modulenow, 'user-agents-header', ! empty( $activate['bbq-headers_user-agents-header'] ) );
		secupress_manage_submodule( $modulenow, 'request-methods-header', ! empty( $activate['bbq-headers_request-methods-header'] ) );
	}

	// Settings.
	if ( ! empty( $settings['bbq-headers_user-agents-list'] ) ) {
		$settings['bbq-headers_user-agents-list'] = sanitize_text_field( $settings['bbq-headers_user-agents-list'] );
		$settings['bbq-headers_user-agents-list'] = secupress_sanitize_list( $settings['bbq-headers_user-agents-list'] );
		$settings['bbq-headers_user-agents-list'] = secupress_unique_sorted_list( $settings['bbq-headers_user-agents-list'], ', ' );
	}

	if ( empty( $settings['bbq-headers_user-agents-list'] ) ) {
		$settings['bbq-headers_user-agents-list'] = secupress_firewall_bbq_headers_user_agents_list_default();
	}
}


/**
 * Bad Contents plugins.
 *
 * @since 1.0
 *
 * @param (string)     $modulenow Current module.
 * @param (array)      $settings  The module settings, passed by reference.
 * @param (bool|array) $activate  Used to (de)activate plugins.
 */
function secupress_bad_contents_settings_callback( $modulenow, &$settings, $activate ) {
	// (De)Activation.
	if ( false !== $activate ) {
		secupress_manage_submodule( $modulenow, 'bad-url-contents', ! empty( $activate['bbq-url-content_bad-contents'] ) );
		secupress_manage_submodule( $modulenow, 'bad-url-length', ! empty( $activate['bbq-url-content_bad-url-length'] ) );
		secupress_manage_submodule( $modulenow, 'bad-sqli-scan', ! empty( $activate['bbq-url-content_bad-sqli-scan'] ) );
	}

	// Settings.
	if ( ! empty( $settings['bbq-url-content_bad-contents-list'] ) ) {
		// Do not sanitize the value or the sky will fall.
		$settings['bbq-url-content_bad-contents-list'] = secupress_sanitize_list( $settings['bbq-url-content_bad-contents-list'] );
		$settings['bbq-url-content_bad-contents-list'] = secupress_unique_sorted_list( $settings['bbq-url-content_bad-contents-list'], ', ' );
	}

	if ( empty( $settings['bbq-url-content_bad-contents-list'] ) ) {
		$settings['bbq-url-content_bad-contents-list'] = secupress_firewall_bbq_url_content_bad_contents_list_default();
	}
}


/**
 * Anti Bruteforce Management plugin.
 *
 * @since 1.0
 *
 * @param (string)     $modulenow Current module.
 * @param (array)      $settings  The module settings, passed by reference.
 * @param (bool|array) $activate  Used to (de)activate plugins.
 */
function secupress_bruteforce_settings_callback( $modulenow, &$settings, $activate ) {
	// (De)Activation.
	if ( false !== $activate ) {
		secupress_manage_submodule( $modulenow, 'bruteforce', ! empty( $activate['bruteforce_activated'] ) );
	}

	// Settings.
	$settings['bruteforce_request_number'] = ! empty( $settings['bruteforce_request_number'] ) ? (int) secupress_validate_range( $settings['bruteforce_request_number'], 3, 1000, 9 ) : 9;
	$settings['bruteforce_time_ban']       = ! empty( $settings['bruteforce_time_ban'] )       ? (int) secupress_validate_range( $settings['bruteforce_time_ban'], 1, 60, 5 )         : 5;
}


/**
 * Country Management plugin.
 *
 * @since 1.0
 *
 * @param (string)     $modulenow Current module.
 * @param (array)      $settings  The module settings, passed by reference.
 * @param (bool|array) $activate  Used to (de)activate plugins.
 */
function secupress_geoip_settings_callback( $modulenow, &$settings, $activate ) {
	// Settings.
	$geoip_values = array( '-1' => 1, 'blacklist' => 1, 'whitelist' => 1 );

	$settings['geoip-system_countries'] = ! empty( $settings['geoip-system_countries'] ) && is_array( $settings['geoip-system_countries'] ) ? array_map( 'sanitize_text_field', $settings['geoip-system_countries'] ) : array();

	if ( ! $settings['geoip-system_countries'] || empty( $settings['geoip-system_type'] ) || ! isset( $geoip_values[ $settings['geoip-system_type'] ] ) ) {
		$settings['geoip-system_type'] = '-1';
	}

	// (De)Activation.
	if ( false !== $activate ) {
		secupress_manage_submodule( $modulenow, 'geoip-system', ( '-1' !== $settings['geoip-system_type'] ) );
	}

	// Make sure to not block the user.
	if ( '-1' !== $settings['geoip-system_type'] && function_exists( 'secupress_geoip2country' ) ) {

		$country_code = secupress_geoip2country( secupress_get_ip() );

		if ( $country_code ) {
			$is_whitelist = 'whitelist' === $settings['geoip-system_type'];
			$countries    = array_flip( $settings['geoip-system_countries'] );

			if ( isset( $countries[ $country_code ] ) && ! $is_whitelist ) {
				// Unblacklist the user country.
				unset( $countries[ $country_code ] );
				$settings['geoip-system_countries'] = array_flip( $countries );

			} elseif ( ! isset( $countries[ $country_code ] ) && $is_whitelist ) {
				// Whitelist the user country.
				$countries   = array_flip( $countries );
				$countries[] = $country_code;
				$settings['geoip-system_countries'] = $countries;
			}
		}
	}
}


/*------------------------------------------------------------------------------------------------*/
/* INSTALL/RESET ================================================================================ */
/*------------------------------------------------------------------------------------------------*/

add_action( 'secupress.first_install', 'secupress_install_firewall_module' );
/**
 * Create default option on install and reset.
 *
 * @since 1.0
 *
 * @param (string) $module The module(s) that will be reset to default. `all` means "all modules".
 */
function secupress_install_firewall_module( $module ) {
	if ( 'all' === $module || 'firewall' === $module ) {
		update_site_option( 'secupress_firewall_settings', array(
			// Bad headers.
			'bbq-headers_user-agents-list'      => secupress_firewall_bbq_headers_user_agents_list_default(),
			// Bad contents.
			'bbq-url-content_bad-contents-list' => secupress_firewall_bbq_url_content_bad_contents_list_default(),
		) );
	}
}


/*------------------------------------------------------------------------------------------------*/
/* MAKE SURE OUR LISTS ARE NOT EMPTY: FILTER OUTPUT ============================================= */
/*------------------------------------------------------------------------------------------------*/

// Bad User Agents.

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
	return 'ADSARobot, ah-ha, almaden, aktuelles, Anarchie, amzn_assoc, ASPSeek, ASSORT, ATHENS, Atomz, attach, attache, autoemailspider, BackWeb, Bandit, BatchFTP, bdfetch, big.brother, BlackWidow, bmclient, Boston Project, BravoBrian SpiderEngine MarcoPolo, Bot mailto:craftbot@yahoo.com, Buddy, Bullseye, bumblebee, capture, CherryPicker, ChinaClaw, CICC, clipping, Collector, Copier, Crescent, Crescent Internet ToolPak, Custo, cyberalert, DA$, Deweb, diagem, Digger, Digimarc, DIIbot, DISCo, DISCo Pump, DISCoFinder, Download Demon, Download Wonder, Downloader, Drip, DSurf15a, DTS.Agent, EasyDL, eCatch, ecollector, efp@gmx.net, Email Extractor, EirGrabber, email, EmailCollector, EmailSiphon, EmailWolf, Express WebPictures, ExtractorPro, EyeNetIE, FavOrg, fastlwspider, Favorites Sweeper, Fetch, FEZhead, FileHound, FlashGet WebWasher, FlickBot, fluffy, FrontPage, GalaxyBot, Generic, Getleft, GetRight, GetSmart, GetWeb!, GetWebPage, gigabaz, Girafabot, Go!Zilla, Go!Zilla, Go-Ahead-Got-It, GornKer, gotit, Grabber, GrabNet, Grafula, Green Research, grub-client, Harvest, hhjhj@yahoo, hloader, HMView, HomePageSearch, http generic, HTTrack, httpdown, httrack, ia_archiver, IBM_Planetwide, Image Stripper, Image Sucker, imagefetch, IncyWincy, Indy*Library, Indy Library, informant, Ingelin, InterGET, Internet Ninja, InternetLinkagent, Internet Ninja, InternetSeer.com, Iria, Irvine, JBH*agent, JetCar, JOC, JOC Web Spider, JustView, KWebGet, Lachesis, larbin, LeechFTP, LexiBot, lftp, libwww, likse, Link, Link*Sleuth, LINKS ARoMATIZED, LinkWalker, LWP, lwp-trivial, Mag-Net, Magnet, Mac Finder, Mag-Net, Mass Downloader, MCspider, Memo, Microsoft.URL, MIDown tool, Mirror, Missigua Locator, Mister PiX, MMMtoCrawl/UrlDispatcherLLL, ^Mozilla$, Mozilla.*Indy, Mozilla.*NEWT, Mozilla*MSIECrawler, MS FrontPage*, MSFrontPage, MSIECrawler, MSProxy, multithreaddb, nationaldirectory, Navroad, NearSite, NetAnts, NetCarta, NetMechanic, netprospector, NetResearchServer, NetSpider, Net Vampire, NetZIP, NetZip Downloader, NetZippy, NEWT, NICErsPRO, Ninja, NPBot, Octopus, Offline Explorer, Offline Navigator, OpaL, Openfind, OpenTextSiteCrawler, OrangeBot, PageGrabber, Papa Foto, PackRat, pavuk, pcBrowser, PersonaPilot, Ping, PingALink, Pockey, Proxy, psbot, PSurf, puf, Pump, PushSite, QRVA, RealDownload, Reaper, Recorder, ReGet, replacer, RepoMonkey, Robozilla, Rover, RPT-HTTPClient, Rsync, Scooter, SearchExpress, searchhippo, searchterms.it, Second Street Research, Seeker, Shai, Siphon, sitecheck, sitecheck.internetseer.com, SiteSnagger, SlySearch, SmartDownload, snagger, Snake, SpaceBison, Spegla, SpiderBot, sproose, SqWorm, Stripper, Sucker, SuperBot, SuperHTTP, Surfbot, SurfWalker, Szukacz, tAkeOut, tarspider, Teleport Pro, Templeton, TrueRobot, TV33_Mercator, UIowaCrawler, UtilMind, URLSpiderPro, URL_Spider_Pro, Vacuum, vagabondo, vayala, visibilitygap, VoidEYE, vspider, Web Downloader, w3mir, Web Data Extractor, Web Image Collector, Web Sucker, Wweb, WebAuto, WebBandit, web.by.mail, Webclipping, webcollage, webcollector, WebCopier, webcraft@bea, webdevil, webdownloader, Webdup, WebEMailExtrac, WebFetch, WebGo IS, WebHook, Webinator, WebLeacher, WEBMASTERS, WebMiner, WebMirror, webmole, WebReaper, WebSauger, Website, Website eXtractor, Website Quester, WebSnake, Webster, WebStripper, websucker, webvac, webwalk, webweasel, WebWhacker, WebZIP, Wget, Whacker, whizbang, WhosTalking, Widow, WISEbot, WWWOFFLE, x-Tractor, ^Xaldon WebSpider, WUMPUS, Xenu, XGET, Zeus.*Webster, Zeus';
}


// Bad URL contents.

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
