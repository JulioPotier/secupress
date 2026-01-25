<?php
defined( 'ABSPATH' ) or die( 'Something went wrong.' );


/**
 * Get file extensions that are forbidden in the uploads folder.
 *
 * @since 1.0
 * @see http://www.file-extensions.org/filetype/extension/name/dangerous-malicious-files
 *
 * @return (array)
 */
function secupress_bad_file_extensions_get_forbidden_extensions() {
	// Build a regex pattern with the allowed extensions.
	$allowed = wp_get_mime_types();
	$allowed = array_keys( $allowed );
	$allowed = implode( '|', $allowed );
	$allowed = "#,($allowed),#i";

	$exts = array(
		'.9',
		'73i87a', '386',
		'aaa', 'abc', 'aepl', 'aru', 'atm', 'aut',
		'bat', 'bhx', 'bin', 'bkd', 'blf', 'bll', 'bmw', 'boo', 'bps', 'bqf', 'breaking_bad', 'btc', 'buk', 'bup', 'bxz',
		'cc', 'ccc', 'ce0', 'ceo', 'cfxxe', 'chm', 'cih', 'cla', 'class', 'cmd', 'com', 'coverton', 'cpl', 'crinf', 'crjoker', 'crypt', 'crypted', 'cryptolocker', 'cryptowall', 'ctbl', 'cxq', 'cyw', 'czvxce',
		'darkness', 'dbd', 'delf', 'dev', 'dlb', 'dli', 'dll', 'dllx', 'dom', 'drv', 'dx', 'dxz', 'dyv', 'dyz',
		'ecc', 'enciphered', 'encrypt', 'encrypted', 'enigma', 'exe', 'exe1', 'exe_renamed', 'exx', 'ezt', 'ezz',
		'fag', 'fjl', 'fnr', 'fuj', 'fun',
		'good', 'gzquar',
		'ha3', 'hlp', 'hlw', 'hsq', 'hts',
		'iva', 'iws',
		'jar', 'js',
		'kcd', 'kernel_complete', 'kernel_pid', 'kernel_time', 'keybtc@inbox_com', 'kimcilware', 'kkk', 'kraken',
		'lechiffre', 'let', 'lik', 'lkh', 'lnk', 'locked', 'locky', 'lok', 'lol!', 'lpaq5',
		'magic', 'mfu', 'micro', 'mjg', 'mjz',
		'nls',
		'oar', 'ocx', 'osa', 'ozd',
		'p5tkjw', 'pcx', 'pdcr', 'pgm', 'php', 'php2', 'php3', 'pid', 'pif', 'plc', 'poar2w', 'pr', 'pzdc',
		'qit', 'qrn',
		'r5a', 'rdm', 'rhk', 'rna', 'rokku', 'rrk', 'rsc_tmp',
		's7p', 'scr', 'scr', 'shs', 'ska', 'smm', 'smtmp', 'sop', 'spam', 'ssy', 'surprise', 'swf', 'sys',
		'tko', 'tps', 'tsa', 'tti', 'ttt', 'txs',
		'upa', 'uzy',
		'vb', 'vba', 'vbe', 'vbs', 'vbx', 'vexe', 'vxd', 'vzr',
		'wlpginstall', 'wmf', 'ws', 'wsc', 'wsf', 'wsh', 'wss',
		'xdu', 'xir', 'xlm', 'xlv', 'xnt', 'xnxx', 'xtbl', 'xxx', 'xyz',
		'zix', 'zvz', 'zzz',
	);

	// Remove the allowed extensions from the forbidden ones.
	$exts = implode( ',', $exts );
	$exts = ",$exts,";
	$exts = preg_replace( $allowed, ',', $exts );
	$exts = trim( $exts, ',' );
	$exts = explode( ',', $exts );

	/**
	 * Filter the forbidden file extensions.
	 *
	 * @since 1.0
	 *
	 * @param (array) $all_exts The file extensions.
	 */
	$out = apply_filters( 'secupress.plugin.bad_file_extensions.forbidden_extenstions', $exts );
	/**
	 * Filter the forbidden file extensions.
	 *
	 * @since 2.3.13
	 *
	 * @param (array) $all_exts The file extensions.
	 */
	$out = apply_filters( 'secupress.plugin.bad_file_extensions.forbidden_extensions', $out ); // typo...
	$out = array_filter( $out );
	return $out ? $out : $exts;
}

/**
 * Tell if a `robots.txt` file is in use.
 * WordPress does not create a rewrite rule for the `robots.txt` file if it is installed in a folder.
 * If a constant `SECUPRESS_FORCE_ROBOTS_TXT` is defined to `true`, the field will be available.
 *
 * @since 1.0
 * @author Grégory Viguier
 *
 * @see `WP_Rewrite::rewrite_rules()`.
 *
 * @return (bool)
 */
function secupress_blackhole_is_robots_txt_enabled() {
	$home_path = wp_parse_url( home_url() );
	return empty( $home_path['path'] ) || '/' === $home_path['path'] || defined( 'SECUPRESS_author_base_FORCE_ROBOTS_TXT' ) && SECUPRESS_FORCE_ROBOTS_TXT;
}


/**
 * Get a regex pattern matching the files.
 *
 * @since 2.3.17 $rules_mode param
 * @since 2.2.6 Invert the behaviour
 * @author Julio Potier
 * 
 * @since 1.0.3
 * @author Grégory Viguier
 *
 * @param (string) $rules_mode
 * @return (string)
 */
function secupress_bad_url_access_get_regex_pattern( $rules_mode = 'disallowed' ) {
	switch( $rules_mode ) {
		case 'allowed':
			$patterns                = [];
			$patterns['root']        = '(index|wp-activate|wp-comments-post|wp-cron|wp-links-opml|wp-load|wp-login|wp-mail|wp-pass|wp-signup|wp-trackback|xmlrpc)\.php';
			$patterns['wp-admin']    = 'wp-admin/(about|admin-ajax|admin-footer|admin-post|admin|async-upload|authorize-application|comment|contribute|credits|customize|edit-comments|edit-form-advanced|edit-form-blocks|edit-form-comment|edit-link-form|edit-tag-form|edit-tags|edit|erase-personal-data|export-personal-data|export|freedoms|import|index|link-add|link-manager|link|load-scripts|load-styles|maint/repair|media-new|media-upload|media|moderation|ms-admin|ms-delete-site|ms-edit|ms-options|ms-sites|ms-themes|ms-upgrade-network|ms-users|my-sites|nav-menus|network/about|network/admin|network/contribute|network/credits|network/edit|network/freedoms|network/index|network/plugin-editor|network/plugin-install|network/plugins|network/privacy|network/profile|network/settings|network/setup|network/site-info|network/site-new|network/site-settings|network/site-themes|network/site-users|network/sites|network/theme-editor|network/theme-install|network/themes|network/update-core|network/update|network/upgrade|network/user-edit|network/user-new|network/users|network|options-discussion|options-general|options-media|options-permalink|options-privacy|options-reading|options-writing|options|plugin-editor|plugin-install|plugins|post-new|post|press-this|privacy-policy-guide|privacy|profile|revision|site-editor|site-health|term|theme-editor|theme-install|themes|tools|update-core|update|upgrade|upload|user/about|user/admin|user/credits|user/freedoms|user/index|user/privacy|user/profile|user/user-edit|user-edit|user-new|users|widgets-form-blocks|widgets-form|widgets)\.php';
			$patterns['wp-includes'] = 'wp-includes/js/tinymce/wp-tinymce\.php';
		break;

		default: // legacy
		case 'disallowed':
			$bases                   = secupress_get_rewrite_bases();
			$patterns                = '^(' . $bases['home_from'] . 'php\.ini|' . $bases['site_from'] . 'wp-config\.php|' . $bases['site_from'] . WPINC . '/.+\.php|' . $bases['site_from'] . 'wp-admin/(admin-functions|install|menu-header|setup-config|([^/]+/)?menu|upgrade-functions|includes/.+)\.php)$';
		break;
	}
	/**
	 * Filter the URLs allowed to be reached
	 * 
	 * @since 2.6 Add "rules_mode" and bring down the hook later
	 * @since 2.2.6
	 * 
	 * @param (array) $patterns
	 * @param (string) $rules_mode
	 */
	$patterns                = apply_filters( 'secupress.plugins.bad_url_access.regex_pattern', $patterns, $rules_mode );
	return $patterns;
}

/**
 * Used in an array_filter to only keep the local ones.
 *
 * @since 2.2.6
 * @author Julio Potier
 * 
 * @param (string) $url
 * 
 * @return (bool)
 */
function _secupress_bad_url_access_allowed_url_filter( $url ) {
	$url = wp_http_validate_url( trim( $url ) );
	return 0 === strpos( $url, home_url() );
}

/**
 * 
 *
 * @since 2.2.6
 * @author Julio Potier
 * 
 * @param (array) $urls
 * 
 * @return (string) $_urls
 */
function _secupress_bad_url_access_allowed_urls_sanitize( $urls ) {
	$_urls     = [];
	if ( ! is_array( $urls ) ) {
		$urls  = array_map( 'trim', explode( "\n", $urls ) );
	}
	foreach ( $urls as $url ) {
		$joker = strpos( $url, '*' );
		$url   = explode( '?', $url );
		$url   = rtrim( reset( $url ), '*' );
		$path  = ABSPATH . str_replace( home_url( '/' ), '', $url );

		if ( ! $joker && is_dir( $path ) && file_exists( $path . '/index.php' ) && ! in_array( $url . '/index.php', $urls ) ) {
			$_urls[] = $url . 'index.php';
		}
		$is_index    = substr( $url, -10 ) === '/index.php';
		if ( is_file( $path ) && $is_index && ! in_array( str_replace( '/index.php', '/', $url ), $urls ) && ! in_array( str_replace( '/index.php', '/*', $url ), $urls ) ) {
			$_urls[] = str_replace( '/index.php', '', $url ) . '/';
		}
		$_urls[]     = $url . ( $joker ? '*' : '' );
	}
	$_urls           = array_filter( array_flip( array_flip( $_urls ) ) );
	
	return implode( "\n", $_urls );
}

/**
 * Sort the given URLs in different cat for htaccess protection
 *
 * @since 2.2.6
 * @author Julio Potier
 * 
 * @return (array) $_urls
 */
function secupress_bad_url_access_sort_urls() {
	global $contentprotectbadurlaccessallowedurls;

	if ( ! is_null( $contentprotectbadurlaccessallowedurls ) && false !== $contentprotectbadurlaccessallowedurls ) {
		$urls  = $contentprotectbadurlaccessallowedurls;
	} else {
		$urls  = secupress_get_module_option( 'content-protect_bad-url-access_allowed-urls', [], 'sensitive-data' );
	}
	if ( ! is_array( $urls ) ) {
		$urls  = array_map( 'trim', explode( "\n", $urls ) );
	}
	if ( empty( $urls ) ) {
		return [ 'files' => [], 'content' => [], 'folders' => [] ];
	}
	$_urls     = [ 'files' => [], 'content' => [], 'folders' => [] ];
	$_content  = secupress_server_is_ssl() ? str_replace( 'http://', 'https://', WP_CONTENT_URL ) : WP_CONTENT_URL;
	foreach ( $urls as $url ) {
		$joker = strpos( $url, '*' );
		$url   = rtrim( $url, '*' );
		$path  = realpath( ABSPATH . str_replace( home_url( '/' ), '', $url ) );
		if ( is_file( $path ) ) {
			$_urls['files'][] = '/' . $url;
			if ( 0 === strpos( $url, $_content ) ) {
				$_urls['content'][] = $url;
			}
			continue;
		}
		if ( is_dir( $path ) ) {
			$_urls['folders'][] = $url;
			if ( 0 === strpos( $url, $_content ) ) {
				$_urls['content'][] = $url;
			}
			if ( $joker ) {
				$_urls['files'][] = trailingslashit( $url ) . '.*';
			}
			continue;
		}
	}
	$_urls = apply_filters( 'secupress.bad-url-access.urls', $_urls );
	return $_urls;
}

add_filter( 'secupress.bad-url-access.urls', 'secupress_bad_url_access_add_third_party_urls' );
/**
 * Add some possible URLs needed by plugins
 *
 * @since 2.3.13
 * @author Julio Potier
 * 
 * @param (array) $urls
 * 
 * @return (array) $urls
 **/
function secupress_bad_url_access_add_third_party_urls( $urls ) {
	// MEMBERPRESS
	if ( is_plugin_active( 'memberpress/memberpress.php' ) ) {
		$urls['files'][] = '/' . plugins_url( 'memberpress/lock.php' );
	}
	
	return $urls;
}

/**
 * Set the author page base and flush the rules
 *
 * @since 2.2.6
 * @author Grégory Viguier, Julio Potier
 * 
 * @param (string) $author_base
 */
function secupress_set_author_base( $author_base = '' ) {
	global $wp_rewrite;

	if ( trim( secupress_get_module_option( 'author_base', 'author', 'sensitive-data' ), '/' ) === $author_base ) {
		return;
	}

	if ( $author_base ) {
		$wp_rewrite->author_base = $author_base;
	} else {
		$wp_rewrite->author_base = 'author';
	}

	$wp_rewrite->init();
	flush_rewrite_rules();
}

/**
 * Return the actual author base.
 *
 * @since 2.2.6
 * @author Grégory Viguier
 * 
 * @return (string) $author_base
 */
function secupress_get_author_base() {
	global $wp_rewrite;

	$front       = ! empty( $wp_rewrite ) ? trim( $wp_rewrite->front, '/' ) . '/' : 'blog/';
	$author_base = trim( secupress_get_module_option( 'wp-endpoints_author_base', 'author', 'sensitive-data' ), '/' );
	$author_base = sanitize_title( $author_base );
	$author_base = $author_base && trim( $front, '/' ) !== $author_base ? $author_base : 'author';

	return $author_base;
}

add_action( 'init', 'secupress_author_base_init' );
/**
 * Set the actual author base on init.
 *
 * @since 2.2.6
 * @author Grégory Viguier
 */
function secupress_author_base_init() {
	global $wp_rewrite;

	if ( ! $wp_rewrite || ! is_object( $wp_rewrite ) ) {
		return;
	}

	$wp_rewrite->author_base = secupress_get_author_base();
}

add_action( 'show_user_profile', 'secupress_author_base_edit_user_options' );
add_action( 'edit_user_profile', 'secupress_author_base_edit_user_options' );
/**
 * Add the field.
 *
 * @since 2.2.6
 * @author Grégory Viguier, Julio Potier
 */
function secupress_author_base_edit_user_options() {
	global $user_id, $wp_rewrite;

	$user_id = isset( $user_id ) ? (int) $user_id : 0;

	if ( ! ( $userdata = get_userdata( $user_id ) ) ) {
		return;
	}

	$def_user_nicename = sanitize_title( $userdata->display_name );
	$blog_prefix       = is_multisite() && ! is_subdomain_install() && is_main_site() ? '/blog/' : '/';
	$author_base       = $wp_rewrite->author_base;
	?>
	<table class="form-table">
		<tr>
		<th><label for="user_nicename"><?php _e( 'Profile URL Slug', 'secupress' ); ?></label></th>
			<td>
				<?php echo $blog_prefix . $author_base . '/'; ?>
				<input id="user_nicename" name="user_nicename" class="regular-text code" type="text" value="<?php echo esc_attr( sanitize_title( $userdata->user_nicename, $def_user_nicename ) ); ?>"/>
				<span class="description"><?php printf( __( 'Leave empty for default value: %s', 'secupress' ), secupress_tag_me( $def_user_nicename, 'strong' ) ); ?></span>
			</td>
		</tr>
	</table>
	<?php
}

add_action( 'personal_options_update',  'secupress_author_base_save_user_options' );
add_action( 'edit_user_profile_update', 'secupress_author_base_save_user_options' );
/**
 * Save the user nicename and display error notices.
 *
 * @since 2.2.6
 * @author Grégory Viguier, Julio Potier
 */
function secupress_author_base_save_user_options() {
	if ( empty( $_POST['user_id'] ) || ! isset( $_POST['user_nicename'] ) ) {
		return;
	}
	$user_id = (int) $_POST['user_id'];

	check_admin_referer( 'update-user_' . $user_id );

	if ( ! ( $userdata = get_userdata( $user_id ) ) ) {
		return;
	}

	$def_user_nicename = sanitize_title( $userdata->user_login );
	$new_nicename      = sanitize_title( $_POST['user_nicename'], $def_user_nicename );

	if ( 0 === strcmp( $new_nicename, $userdata->user_nicename ) ) {
		return;
	}

	// "wp_admin_notice_markup" hook is 6.4
	if ( secupress_get_user_by( $new_nicename ) ) {
		if ( secupress_wp_version_is( '6.4' ) ) {
			add_action( 'user_profile_update_errors', 'secupress_author_base_user_add_fake_error' );
		}
		secupress_add_transient_notice( sprintf( __( 'Sorry, the slug %s is already in use!', 'secupress' ), secupress_tag_me( esc_html( $new_nicename ), 'strong' ) ), 'error', '', 'exist' );
	} else {
		$updated = wp_update_user( array(
			'ID'            => $user_id,
			'user_nicename' => $new_nicename,
		) );

		if ( ! $updated ) {
			if ( secupress_wp_version_is( '6.4' ) ) {
				add_action( 'user_profile_update_errors', 'secupress_author_base_user_add_fake_error' );
			}
			secupress_add_transient_notice( __( 'Unexpected issue updating the author profile URL slug. Please try again.', 'secupress' ), 'error', '', 'exist' );
		}
	}

	function secupress_author_base_user_add_fake_error( $errors ) {
		$errors->add( '###SECUPRESS-DO-NOT-SHOW-ME###', '###SECUPRESS-DO-NOT-SHOW-ME###' );
	}

	add_filter( 'wp_admin_notice_markup', 'secupress_author_base_remove_fake_error', 10, 2 ); // WP 6.4
	/**
	 * Maybe remove the markup, the error is set just to not show the "Profile updated" msg
	 *
	 * @since 2.3.19
	 * @author Julio Potier
	 * 
	 * @param (string) $markup
	 * @param (string) $message
	 * 
	 * @return (string) $markup
	 **/
	function secupress_author_base_remove_fake_error( $markup, $message ) {
		if ( strpos( $message, '###SECUPRESS-DO-NOT-SHOW-ME###' ) !== false ) {
			return '';
		}
		return $markup;
	}
}

add_filter( 'template_include', 'secupress_blackhole_please_click_me', 1 );
/**
 * Use a custom template for our trap.
 *
 * @since 2.4.1 Moved here so we can use it for other cases
 * @since 2.2.6 Manage the ban from here with a nonce now
 * @author Julio Potier
 *
 * @since 1.0
 * @author Grégory Viguier
 *
 * @param (string) $template Template path.
 *
 * @return (string) Template path.
 */
function secupress_blackhole_please_click_me( $template ) {
	if ( is_user_logged_in() ) {
		return $template;
	}

	$url     = trailingslashit( secupress_get_current_url() );
	$dirname = secupress_get_hashed_folder_name( basename( __FILE__, '.php' ) );

	if ( isset( $_REQUEST['token'] ) && wp_verify_nonce( $_REQUEST['token'], 'ban_me_please-' . date( 'ymdhi' ) ) ) {
		$ip      = secupress_get_ip( 'REMOTE_ADDR' );
		$ban_ips = get_site_option( SECUPRESS_BAN_IP );

		if ( ! is_array( $ban_ips ) ) {
			$ban_ips = array();
		}

		$ban_ips[ $ip ] = time() + MONTH_IN_SECONDS;

		update_site_option( SECUPRESS_BAN_IP, $ban_ips );

		/* This hook is documented in /inc/functions/admin.php */
		do_action( 'secupress.ban.ip_banned', $ip, $ban_ips );

		switch ( $_SERVER['REQUEST_METHOD'] ) {
			case 'GET':
				secupress_log_attack( 'bad_robots' );
			break;
			case 'POST':
				secupress_log_attack( 'honeypot' );
			break;
		}

		wp_die( 'Something went wrong.' ); // Do not use secupress_die() here.
	}

	if ( substr( $url, - strlen( $dirname ) ) === $dirname ) {
		add_filter( 'nonce_user_logged_out', 'secupress_modify_userid_for_nonces' );
		return dirname( __FILE__ ) . '/inc/php/blackhole/warning-template.php';
	}

	return $template;
}
