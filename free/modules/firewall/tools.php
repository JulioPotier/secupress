<?php
defined( 'ABSPATH' ) or die( 'Something went wrong.' );

/** --------------------------------------------------------------------------------------------- */
/** MAKE SURE OUR LISTS ARE NOT EMPTY: FILTER OUTPUT ============================================ */
/** --------------------------------------------------------------------------------------------- */
/**
 * Get user-agents forbidden by default.
 *
 * @since 1.0
 * @since 1.4.9 update list
 * @since 1.4.11 Rollback list
 *
 * @return (string) A comma-separated list.
 */
function secupress_firewall_bbq_headers_user_agents_list_default() {
	return  apply_filters( 'secupress.bad_user_agents.list',
			'Gecko/2009032609 Firefox, ADSARobot, ah-ha, almaden, aktuelles, Anarchie, amzn_assoc, ASPSeek, ASSORT, ATHENS, Atomz, attach, autoemailspider, BackWeb, Bandit, BatchFTP, bdfetch, big.brother, BlackWidow, bmclient, Boston Project, BravoBrian SpiderEngine MarcoPolo, Bot mailto:craftbot@yahoo.com, Buddy, Bullseye, bumblebee, capture, CherryPicker, ChinaClaw, CICC, clipping, Collector, Copier, Crescent, Crescent Internet ToolPak, Custo, cyberalert, DA$, Deweb, diagem, Digger, Digimarc, DIIbot, DISCo, DISCo Pump, DISCoFinder, Download Demon, Download Wonder, Downloader, Drip, DSurf15a, DTS.Agent, EasyDL, eCatch, ecollector, efp@gmx.net, Email Extractor, EirGrabber, EmailCollector, EmailSiphon, EmailWolf, Express WebPictures, ExtractorPro, EyeNetIE, FavOrg, fastlwspider, Favorites Sweeper, FEZhead, FileHound, FlashGet WebWasher, FlickBot, fluffy, FrontPage, GalaxyBot, Generic, Getleft, GetRight, GetSmart, GetWeb!, GetWebPage, gigabaz, Girafabot, Go!Zilla, Go!Zilla, Go-Ahead-Got-It, GornKer, gotit, Grabber, GrabNet, Grafula, Green Research, grub-client, Harvest, hhjhj@yahoo, hloader, HMView, HomePageSearch, http generic, HTTrack, httpdown, httrack, ia_archiver, IBM_Planetwide, Image Stripper, Image Sucker, imagefetch, IncyWincy, Indy*Library, Indy Library, informant, Ingelin, InterGET, Internet Ninja, InternetLinkagent, Internet Ninja, InternetSeer.com, Iria, Irvine, JBH*agent, JetCar, JOC, JOC Web Spider, JustView, KWebGet, Lachesis, larbin, LeechFTP, LexiBot, lftp, libwww, likse, Link*Sleuth, LINKS ARoMATIZED, LinkWalker, LWP, lwp-trivial, Mag-Net, Magnet, Mac Finder, Mag-Net, Mass Downloader, MCspider, Memo, Microsoft.URL, MIDown tool, Mirror, Missigua Locator, Mister PiX, MMMtoCrawl/UrlDispatcherLLL, ^Mozilla$, Mozilla.*Indy, Mozilla.*NEWT, Mozilla*MSIECrawler, MS FrontPage*, MSFrontPage, MSIECrawler, MSProxy, multithreaddb, nationaldirectory, Navroad, NearSite, NetAnts, NetCarta, NetMechanic, netprospector, NetResearchServer, NetSpider, Net Vampire, NetZIP, NetZip Downloader, NetZippy, NEWT, NICErsPRO, Ninja, NPBot, Octopus, Offline Explorer, Offline Navigator, OpaL, Openfind, OpenTextSiteCrawler, PageGrabber, Papa Foto, PackRat, pavuk, pcBrowser, PersonaPilot, PingALink, Pockey, psbot, PSurf, puf, Pump, PushSite, QRVA, RealDownload, Reaper, Recorder, ReGet, replacer, RepoMonkey, Robozilla, Rover, RPT-HTTPClient, Rsync, Scooter, SearchExpress, searchhippo, searchterms.it, Second Street Research, Seeker, Shai, Siphon, sitecheck, sitecheck.internetseer.com, SiteSnagger, SlySearch, SmartDownload, snagger, Snake, SpaceBison, Spegla, SpiderBot, sproose, SqWorm, Stripper, Sucker, SuperBot, SuperHTTP, Surfbot, SurfWalker, Szukacz, tAkeOut, tarspider, Teleport Pro, Templeton, TrueRobot, TV33_Mercator, UIowaCrawler, UtilMind, URLSpiderPro, URL_Spider_Pro, Vacuum, vagabondo, vayala, visibilitygap, VoidEYE, vspider, Web Downloader, w3mir, Web Data Extractor, Web Image Collector, Web Sucker, Wweb, WebAuto, WebBandit, web.by.mail, Webclipping, webcollage, webcollector, WebCopier, webcraft@bea, webdevil, webdownloader, Webdup, WebEMailExtrac, WebFetch, WebGo IS, WebHook, Webinator, WebLeacher, WEBMASTERS, WebMiner, WebMirror, webmole, WebReaper, WebSauger, Website, Website eXtractor, Website Quester, WebSnake, Webster, WebStripper, websucker, webvac, webwalk, webweasel, WebWhacker, WebZIP, Whacker, whizbang, WhosTalking, Widow, WISEbot, WWWOFFLE, x-Tractor, ^Xaldon WebSpider, WUMPUS, Xenu, XGET, Zeus.*Webster, Zeus' // 1.0
			// 'Gecko/2009032609 Firefox, ADSARobot, ah-ha, almaden, aktuelles, Anarchie, amzn_assoc, ASPSeek, ASSORT, ATHENS, Atomz, autoemailspider, BackWeb, Bandit, BatchFTP, bdfetch, big.brother, BlackWidow, bmclient, Boston Project, BravoBrian SpiderEngine MarcoPolo, Bot mailto:craftbot@yahoo.com, Buddy, Bullseye, bumblebee, CherryPicker, ChinaClaw, CICC, clipping, Collector, Copier, Crescent, Crescent Internet ToolPak, Custo, cyberalert, DA$, Deweb, diagem, Digger, Digimarc, DIIbot, DISCo, DISCo Pump, DISCoFinder, Download Demon, Download Wonder, Downloader, Drip, DSurf15a, DTS.Agent, EasyDL, eCatch, ecollector, efp@gmx.net, Email Extractor, EirGrabber, EmailCollector, EmailSiphon, EmailWolf, Express WebPictures, ExtractorPro, EyeNetIE, FavOrg, fastlwspider, Favorites Sweeper, FEZhead, FileHound, FlashGet WebWasher, FlickBot, fluffy, FrontPage, GalaxyBot, Generic, Getleft, GetRight, GetSmart, GetWeb!, GetWebPage, gigabaz, Girafabot, Go!Zilla, Go-Ahead-Got-It, GornKer, gotit, Grabber, GrabNet, Grafula, Green Research, grub-client, Harvest, hhjhj@yahoo, hloader, HMView, HomePageSearch, http generic, HTTrack, httpdown, httrack, ia_archiver, IBM_Planetwide, Image Stripper, Image Sucker, imagefetch, IncyWincy, Indy*Library, Indy Library, informant, Ingelin, InterGET, Internet Ninja, InternetLinkagent, InternetSeer.com, Iria, Irvine, JBH*agent, JetCar, JOC, JOC Web Spider, JustView, KWebGet, Lachesis, larbin, LeechFTP, LexiBot, lftp, libwww, likse, Link*Sleuth, LINKS ARoMATIZED, LinkWalker, LWP, lwp-trivial, Mag-Net, Magnet, Mac Finder, Mass Downloader, MCspider, Memo, Microsoft.URL, MIDown tool, Mirror, Missigua Locator, Mister PiX, MMMtoCrawl/UrlDispatcherLLL, ^Mozilla$, Mozilla.*Indy, Mozilla.*NEWT, Mozilla*MSIECrawler, MS FrontPage*, MSFrontPage, MSIECrawler, MSProxy, multithreaddb, nationaldirectory, Navroad, NearSite, NetAnts, NetCarta, NetMechanic, netprospector, NetResearchServer, NetSpider, Net Vampire, NetZIP, NetZip Downloader, NetZippy, NEWT, NICErsPRO, Ninja, NPBot, Octopus, Offline Explorer, Offline Navigator, OpaL, Openfind, OpenTextSiteCrawler, PageGrabber, Papa Foto, PackRat, pavuk, pcBrowser, PersonaPilot, PingALink, Pockey, psbot, PSurf, puf, Pump, PushSite, QRVA, RealDownload, Reaper, Recorder, ReGet, replacer, RepoMonkey, Robozilla, Rover, RPT-HTTPClient, Rsync, Scooter, SearchExpress, searchhippo, searchterms.it, Second Street Research, Seeker, Shai, Siphon, sitecheck, sitecheck.internetseer.com, SiteSnagger, SlySearch, SmartDownload, snagger, Snake, SpaceBison, Spegla, SpiderBot, sproose, SqWorm, Stripper, Sucker, SuperBot, SuperHTTP, Surfbot, SurfWalker, Szukacz, tAkeOut, tarspider, Teleport Pro, Templeton, TrueRobot, TV33_Mercator, UIowaCrawler, UtilMind, URLSpiderPro, URL_Spider_Pro, Vacuum, vagabondo, vayala, visibilitygap, VoidEYE, vspider, Web Downloader, w3mir, Web Data Extractor, Web Image Collector, Web Sucker, Wweb, WebAuto, WebBandit, web.by.mail, Webclipping, webcollage, webcollector, WebCopier, webcraft@bea, webdevil, webdownloader, Webdup, WebEMailExtrac, WebFetch, WebGo IS, WebHook, Webinator, WebLeacher, WEBMASTERS, WebMiner, WebMirror, webmole, WebReaper, WebSauger, Website, Website eXtractor, Website Quester, WebSnake, Webster, WebStripper, websucker, webvac, webwalk, webweasel, WebWhacker, WebZIP, Whacker, whizbang, WhosTalking, Widow, WISEbot, WWWOFFLE, x-Tractor, ^Xaldon WebSpider, WUMPUS, Xenu, XGET, Zeus.*Webster, Zeus, shell, remoteview, base64_, bin/bash, disconnect, eval, lwp-download, unserialize, 360Spider, acapbot, acoonbot, alexibot, asterias, attackbot, backdorbot, becomebot, binlar, blackwidow, blekkobot, blexbot, blowfish, bullseye, bunnys, butterfly, careerbot, casper, checkpriv, cheesebot, cherrypick, chinaclaw, choppy, clshttp, cmsworld, copernic, copyrightcheck, cosmos, crescent, cy_cho, datacha, demon, diavol, discobot, dittospyder, dotbot, dotnetdotcom, dumbot, emailcollector, emailsiphon, emailwolf, extract, eyenetie, feedfinder, flaming, flashget, flicky, foobot, g00g1e, getright, gigabot, go-ahead-got, gozilla, grabnet, grafula, harvest, heritrix, icarus6j, jetbot, jetcar, jikespider, kmccrew, leechftp, libweb, linkextractor, linkscan, linkwalker, loader, miner, majestic, mechanize, morfeus, moveoverbot, netmechanic, netspider, nicerspro, nikto, ninja, nutch, octopus, pagegrabber, planetwork, postrank, proximic, purebot, pycurl, python, queryn, queryseeker, radian6, radiation, realdownload, rogerbot, scooter, seekerspider, semalt, siclab, sindice, sistrix, sitebot, siteexplorer, sitesnagger, skygrid, smartdownload, snoopy, sosospider, spankbot, spbot, sqlmap, stackrambler, stripper, sucker, surftbot, sux0r, suzukacz, suzuran, takeout, teleport, telesoft, true_robots, turingos, turnit, vampire, vikspider, voideye, webleacher, webreaper, webstripper, webviewer, webwhacker, winhttp, wwwoffle, woxbot, xaldon, xxxyy, yamanalab, yioopbot, youda, zeus, zmeu, zune, zyborg'
			);
}

/**
 * Get contents forbidden in URL by default.
 *
 * @since 1.0
 * @since 1.4.9 update list
 * @since 1.4.11 Rollback list
 *
 * @return (string) A comma-separated list.
 */
function secupress_firewall_bbq_url_content_bad_contents_list_default() {
	// We cut some words to prevent being tagged as "bad" file from scanners.
	return  apply_filters( 'secupress.bad_url_contents.list',
			'AND%201=, information_schema, UNI'.'ON%20SEL'.'ECT, UNI'.'ON%20ALL%20SEL'.'ECT, ev'./**/'al(, wp-config.php, %%30%30, GLOBALS[, .ini, REQUEST[, et'.'c/pas'.'swd, ba'.'se'.'64_, javascript:, ../, 127.0.0.1, inpu'.'t_file' // v1.0
			// . 'temp00, 70bex, configbak, dom'.'pdf, filene'.'tworks, ja'.'hat, kc'.'rew, keywor'.'dspy, mob'.'iquo, nes'.'sus, rac'.'rew, loc'.'us7, bi'.'trix, msoffice, child'.'_terminate, con'.'cat, allow_'.'url_f'.'open, allow_'.'url_in'.'clude, auto_pre'.'pend_file, blex'.'bot, browser'.'sploit, c9'.'9, disab'.'le_function, docume'.'nt_root, ela'.'stix, encode'.'uricom, fclose, fgets, fputs, fread, fsbuff, fsockopen, gethostbyname, gra'.'blogin, hme'.'i7, open_basedir, passthru, popen, proc_open, quick'.'brute, safe'.'_mode, shell_exec, su'.'x0r, xer'.'tive, <script, fopen, .php.inc, mos'.'config, mkdir, rmdir, chdir, ckf'.'inder, full'.'click, fcke'.'ditor, timt'.'humb, abso'.'lute_dir, abso'.'lute_path, ro'.'ot_dir, ro'.'ot_path, base'.'dir, base'.'path, loop'.'back, %00, 0x00, %0d%0a' // v1.4.9
			);
}

/**
 * Get contents forbidden in REMOTE_HOST by default.
 *
 * @since 1.4.9
 *
 * @return (string) A comma-separated list.
 */
function secupress_firewall_bbq_host_content_bad_contents_list_default() {
	return  apply_filters( 'secupress.bad_host_contents.list',
			'163data, amazonaws, colocrossing, crimea, g00g1e, justhost, kanagawa, loopia, masterhost, onlinehome, poneytel, sprintdatacenter, reverse.softlayer, safenet, ttnet, woodpecker, wowrack'
			);
}

/**
 * Get contents forbidden in HTTP_REFERER by default.
 *
 * @since 1.4.9
 *
 * @return (string) A comma-separated list.
 */
function secupress_firewall_bbq_referer_content_bad_contents_list_default() {
	return  apply_filters( 'secupress.bad_referer_contents.list',
			'semalt.com, todaperfeita, ambien, blue spill, cocaine, ejaculat, erectile, erections, hoodia, huronriveracres, impotence, levitra, libido, lipitor, phentermin, sandyauer, tramadol, troyhamby, ultram, unicauca, valium, viagra, vicodin, xanax, ypxaieo'
			);
}


/** --------------------------------------------------------------------------------------------- */
/** OTHER ======================================================================================= */
/** --------------------------------------------------------------------------------------------- */

/**
 * See secupress_block_bad_url_contents
 *
 * @since 1.4.9
 * @author Julio Potier
 * @param (string) $function Short string to be concat to form the callback
 * @param (string) $server The index in $_SERVER to be checked
 * @param (string) $block_id Which code use if we block
 * @return (void)
 **/
function secupress_block_bad_content_but_what( $function, $server, $block_id ) {
	if ( ! isset( $_SERVER[ $server ] ) ) {
		return;
	}

	// don't block if our own domain name contains a bad word and is present in the URL (with redirect for example).
	$check_value = isset( $_SERVER['HTTP_HOST'] ) ? str_replace( $_SERVER['HTTP_HOST'], '', $_SERVER[ $server ] ) : $_SERVER[ $server ];
	$check_value = explode( '?', $check_value, 2 );
	// Nothing like a request uri? It's ok, don't look into the URLs paths
	if ( 'QUERY_STRING' !== $server && ! isset( $check_value[1] ) ) {
		return;
	}
	$check_value  = end( $check_value );
	$bad_contents = "secupress_firewall_bbq_{$function}_content_bad_contents_list_default";
	if ( ! function_exists( $bad_contents ) ) {
		wp_die( __FUNCTION__ ); // Should not happen in live.
	}
	$bad_contents = $bad_contents();

	if ( ! empty( $bad_contents ) ) {
		$bad_contents = preg_replace( '/\s*,\s*/', '|', preg_quote( $bad_contents, '/' ) );
		$bad_contents = trim( $bad_contents, '| ' );

		while ( false !== strpos( $bad_contents, '||' ) ) {
			$bad_contents = str_replace( '||', '|', $bad_contents );
		}
	}

	preg_match( '/' . $bad_contents . '/i', $check_value, $matches );
	if ( ! empty( $check_value ) && $bad_contents && ! empty( $matches ) ) {
		secupress_block( $block_id, [ 'code' => 503, 'b64' => [ 'data' => $matches ] ] );
	}

}

add_filter( 'secupress_block_id', 'secupress_firewall_block_id' );
/**
 * Translate block IDs into understandable things.
 *
 * @since 2.3   ATS
 * @since 2.1   NOUSER
 * @since 2.0   BRU
 * @since 1.4.9 BHC, BRC
 * @author Julio Potier
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
		'ATS'  => __( 'Antispam, Too soon', 'secupress' ),
		// Firewall.
		'BRU'  => __( 'Bad Referer URL', 'secupress' ),
		// URL Contents.
		'BHC'  => __( 'Bad Host Contents', 'secupress' ),
		'BRC'  => __( 'Bad Referer Contents', 'secupress' ),
		// GeoIP.
		'GIP'  => __( 'Bad GeoIP', 'secupress' ),
		// Request Method.
		'RMHM' => __( 'Bad Request Method', 'secupress' ),
		// User-Agent.
		'UAHT' => __( 'User-Agent With HTML Tags', 'secupress' ),
		'UAHB' => __( 'User-Agent Disallowed', 'secupress' ),
		// Users
		'NOUSER' => __( 'Unknown user', 'secupress' ),
	);

	return isset( $block_ids[ $module ] ) ? $block_ids[ $module ] : $module;
}
