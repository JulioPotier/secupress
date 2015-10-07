<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );

/*
 * Tell WP what to do when admin is loaded aka upgrader
 *
 * @since 1.0
 */
add_action( 'admin_init', 'secupress_upgrader' );

function secupress_upgrader() {
	// Grab some infos
	$actual_version = secupress_get_option( 'version' );
	// You can hook the upgrader to trigger any action when WP secupress is upgraded
	// first install
	if ( ! $actual_version ){
		do_action( 'wp_secupress_first_install' );
	}
	// already installed but got updated
	elseif ( SECUPRESS_VERSION != $actual_version ) {
		do_action( 'wp_secupress_upgrade', SECUPRESS_VERSION, $actual_version );
	}
	// If any upgrade has been done, we flush and update version #
	if ( did_action( 'wp_secupress_first_install' ) || did_action( 'wp_secupress_upgrade' ) ) {
		// flush_secupress_htaccess(); ////

		secupress_renew_all_boxes( 0, array( 'secupress_warning_plugin_modification' ) );

		$options = get_option( SECUPRESS_SETTINGS_SLUG ); // do not use secupress_get_option() here
		$options['version'] = SECUPRESS_VERSION;

		$keys = secupress_check_key( 'live' );
		if ( is_array( $keys ) ) {
			$options = array_merge( $keys, $options );
		}

		update_option( SECUPRESS_SETTINGS_SLUG, $options );
	} elseif ( empty( $_POST ) && secupress_valid_key() ) {
		secupress_check_key( 'transient_30' );
	}
	/** This filter is documented in inc/admin-bar.php */
	if ( ! secupress_valid_key() && current_user_can( apply_filters( 'secupress_capacity', 'manage_options' ) ) && ( ! isset( $_GET['page'] ) || 'secupress' != $_GET['page'] ) ) {
		add_action( 'admin_notices', 'secupress_need_api_key' );
	}
}


/* BEGIN UPGRADER'S HOOKS */

/**
 * Keeps this function up to date at each version
 *
 * @since 1.0
 */
add_action( 'wp_secupress_first_install', 'secupress_install_modules' );

function secupress_install_modules( $module = 'all' ) {
	if ( 'all' === $module ) {
		// Generate an random key
		// $secret_cache_key = secupress_create_uniqid();

		// secupress_dismiss_box( 'secupress_warning_plugin_modification' );
		//// secupress_reset_white_label_values( false );

		// Create Options
		add_option( SECUPRESS_SETTINGS_SLUG,
			array(

			)
		);
	}

	// users_login
	if ( 'all' === $module || 'users_login' === $module ) {
		update_option( 'secupress_users_login_settings',
			array(
				'double-auth_type'  => '-1',
				//// pas fini
			)
		);
	}
	
	// firewall
	if ( 'all' === $module || 'firewall' === $module ) {
		update_option( 'secupress_firewall_settings',
			array(
				'bbq-headers_user-agents-header' => '1',
				'bbq-headers_user-agents-list'  => 'ADSARobot,ah-ha,almaden,aktuelles,Anarchie,amzn_assoc,ASPSeek,ASSORT,ATHENS,Atomz,attach,attache,autoemailspider,BackWeb,Bandit,BatchFTP,bdfetch,big.brother,BlackWidow,bmclient,Boston Project,BravoBrian SpiderEngine MarcoPolo,Bot mailto:craftbot@yahoo.com,Buddy,Bullseye,bumblebee,capture,CherryPicker,ChinaClaw,CICC,clipping,Collector,Copier,Crescent,Crescent Internet ToolPak,Custo,cyberalert,DA$,Deweb,diagem,Digger,Digimarc,DIIbot,DISCo,DISCo Pump,DISCoFinder,Download Demon,Download Wonder,Downloader,Drip,DSurf15a,DTS.Agent,EasyDL,eCatch,ecollector,efp@gmx.net,Email Extractor,EirGrabber,email,EmailCollector,EmailSiphon,EmailWolf,Express WebPictures,ExtractorPro,EyeNetIE,FavOrg,fastlwspider,Favorites Sweeper,Fetch,FEZhead,FileHound,FlashGet WebWasher,FlickBot,fluffy,FrontPage,GalaxyBot,Generic,Getleft,GetRight,GetSmart,GetWeb!,GetWebPage,gigabaz,Girafabot,Go!Zilla,Go!Zilla,Go-Ahead-Got-It,GornKer,gotit,Grabber,GrabNet,Grafula,Green Research,grub-client,Harvest,hhjhj@yahoo,hloader,HMView,HomePageSearch,http generic,HTTrack,httpdown,httrack,ia_archiver,IBM_Planetwide,Image Stripper,Image Sucker,imagefetch,IncyWincy,Indy*Library,Indy Library,informant,Ingelin,InterGET,Internet Ninja,InternetLinkagent,Internet Ninja,InternetSeer.com,Iria,Irvine,JBH*agent,JetCar,JOC,JOC Web Spider,JustView,KWebGet,Lachesis,larbin,LeechFTP,LexiBot,lftp,libwww,likse,Link,Link*Sleuth,LINKS ARoMATIZED,LinkWalker,LWP,lwp-trivial,Mag-Net,Magnet,Mac Finder,Mag-Net,Mass Downloader,MCspider,Memo,Microsoft.URL,MIDown tool,Mirror,Missigua Locator,Mister PiX,MMMtoCrawl/UrlDispatcherLLL,^Mozilla$,Mozilla.*Indy,Mozilla.*NEWT,Mozilla*MSIECrawler,MS FrontPage*,MSFrontPage,MSIECrawler,MSProxy,multithreaddb,nationaldirectory,Navroad,NearSite,NetAnts,NetCarta,NetMechanic,netprospector,NetResearchServer,NetSpider,Net Vampire,NetZIP,NetZip Downloader,NetZippy,NEWT,NICErsPRO,Ninja,NPBot,Octopus,Offline Explorer,Offline Navigator,OpaL,Openfind,OpenTextSiteCrawler,OrangeBot,PageGrabber,Papa Foto,PackRat,pavuk,pcBrowser,PersonaPilot,Ping,PingALink,Pockey,Proxy,psbot,PSurf,puf,Pump,PushSite,QRVA,RealDownload,Reaper,Recorder,ReGet,replacer,RepoMonkey,Robozilla,Rover,RPT-HTTPClient,Rsync,Scooter,SearchExpress,searchhippo,searchterms.it,Second Street Research,Seeker,Shai,Siphon,sitecheck,sitecheck.internetseer.com,SiteSnagger,SlySearch,SmartDownload,snagger,Snake,SpaceBison,Spegla,SpiderBot,sproose,SqWorm,Stripper,Sucker,SuperBot,SuperHTTP,Surfbot,SurfWalker,Szukacz,tAkeOut,tarspider,Teleport Pro,Templeton,TrueRobot,TV33_Mercator,UIowaCrawler,UtilMind,URLSpiderPro,URL_Spider_Pro,Vacuum,vagabondo,vayala,visibilitygap,VoidEYE,vspider,Web Downloader,w3mir,Web Data Extractor,Web Image Collector,Web Sucker,Wweb,WebAuto,WebBandit,web.by.mail,Webclipping,webcollage,webcollector,WebCopier,webcraft@bea,webdevil,webdownloader,Webdup,WebEMailExtrac,WebFetch,WebGo IS,WebHook,Webinator,WebLeacher,WEBMASTERS,WebMiner,WebMirror,webmole,WebReaper,WebSauger,Website,Website eXtractor,Website Quester,WebSnake,Webster,WebStripper,websucker,webvac,webwalk,webweasel,WebWhacker,WebZIP,Wget,Whacker,whizbang,WhosTalking,Widow,WISEbot,WWWOFFLE,x-Tractor,^Xaldon WebSpider,WUMPUS,Xenu,XGET,Zeus.*Webster,Zeus',
			)
		);
	}

}


/**
 * What to do when secupress is updated, depending on versions
 *
 * @since 1.0
 */
add_action( 'wp_secupress_upgrade', 'secupress_new_upgrade', 10, 2 );

function secupress_new_upgrade( $wp_secupress_version, $actual_version ) {
	//
}
/* END UPGRADER'S HOOKS */
