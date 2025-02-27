<?php
defined( 'ABSPATH' ) or die( 'Something went wrong.' );


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
 * @since 2.2.6 Invert the behaviour
 * @author Julio Potier
 * 
 * @since 1.0.3
 * @author Grégory Viguier
 *
 * @return (string)
 */
function secupress_bad_url_access_get_regex_pattern() {
	$patterns                = [];
    $patterns['root']        = '(index|wp-activate|wp-comments-post|wp-cron|wp-links-opml|wp-load|wp-login|wp-mail|wp-pass|wp-signup|wp-trackback|xmlrpc)\.php';
    $patterns['wp-admin']    = 'wp-admin/(about|admin-ajax|admin-footer|admin-post|admin|async-upload|authorize-application|comment|contribute|credits|customize|edit-comments|edit-form-advanced|edit-form-blocks|edit-form-comment|edit-link-form|edit-tag-form|edit-tags|edit|erase-personal-data|export-personal-data|export|freedoms|import|index|link-add|link-manager|link|maint/repair|media-new|media-upload|media|moderation|ms-admin|ms-delete-site|ms-edit|ms-options|ms-sites|ms-themes|ms-upgrade-network|ms-users|my-sites|nav-menus|network/about|network/admin|network/contribute|network/credits|network/edit|network/freedoms|network/index|network/plugin-editor|network/plugin-install|network/plugins|network/privacy|network/profile|network/settings|network/setup|network/site-info|network/site-new|network/site-settings|network/site-themes|network/site-users|network/sites|network/theme-editor|network/theme-install|network/themes|network/update-core|network/update|network/upgrade|network/user-edit|network/user-new|network/users|network|options-discussion|options-general|options-media|options-permalink|options-privacy|options-reading|options-writing|options|plugin-editor|plugin-install|plugins|post-new|post|press-this|privacy-policy-guide|privacy|profile|revision|site-editor|site-health|term|theme-editor|theme-install|themes|tools|update-core|update|upgrade|upload|user/about|user/admin|user/credits|user/freedoms|user/index|user/privacy|user/profile|user/user-edit|user-edit|user-new|users|widgets-form-blocks|widgets-form|widgets)\.php';
    $patterns['wp-includes'] = 'wp-includes/js/tinymce/wp-tinymce\.php';
    /**
     * Filter the URLs allowed to be reached
     * 
     * @since 2.2.6
     * @param (array) $patterns
     */
    $patterns                = apply_filters( 'secupress.plugins.bad_url_access.regex_pattern', $patterns );
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
		$path  = realpath( ABSPATH . str_replace( home_url( '/' ), '', $url ) );
		if ( ! file_exists( $path ) || is_link( $path ) ) {
			continue;
		}
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
		return $urls;
	}
	$_urls     = [];
	$_content  = secupress_server_is_ssl() ? str_replace( 'http://', 'https://', WP_CONTENT_URL ) : WP_CONTENT_URL;
	foreach ( $urls as $url ) {
		$joker = strpos( $url, '*' );
		$url   = rtrim( $url, '*' );
		$path  = realpath( ABSPATH . str_replace( home_url( '/' ), '', $url ) );
		if ( is_file( $path ) ) {
			$_urls['files'][] = $url;
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
	return $_urls;
}

if ( ! secupress_is_plugin_active( 'sf-author-url-control/sf-author-url-control.php' ) ) { // Grégory Viguier first ;)
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
	 * @author Grégory Viguier
	 */
	function secupress_author_base_edit_user_options() {
		global $user_id, $wp_rewrite;

		$user_id = isset( $user_id ) ? (int) $user_id : 0;

		if ( ! ( $userdata = get_userdata( $user_id ) ) ) {
			return;
		}

		if ( ! secupress_author_base_user_can_edit_user_slug() ) {
			return;
		}

		$def_user_nicename = sanitize_title( $userdata->user_login );
		$blog_prefix       = is_multisite() && ! is_subdomain_install() && is_main_site() ? '/blog/' : '/';
		$author_base       = $wp_rewrite->author_base;

		echo '<table class="form-table">' . "\n";
			echo '<tr>' . "\n";
				echo '<th><label for="user_nicename">' . __( 'Profile URL Slug', 'secupress' ) . "</label></th>\n";
				echo '<td>';
					echo $blog_prefix . $author_base . '/';
					echo '<input id="user_nicename" name="user_nicename" class="regular-text code" type="text" value="' . esc_attr( sanitize_title( $userdata->user_nicename, $def_user_nicename ) ) . '"/> ';
					echo '<span class="description">' . sprintf( __( 'Leave empty for default value: %s', 'secupress' ), secupress_tag_me( $def_user_nicename, 'strong' ) ) . '</span> ';
				echo '</td>' . "\n";
			echo '</tr>' . "\n";
		echo '</table>' . "\n";
	}

	add_action( 'personal_options_update',  'secupress_author_base_save_user_options' );
	add_action( 'edit_user_profile_update', 'secupress_author_base_save_user_options' );
	/**
	 * Save the user nicename and display error notices.
	 *
	 * @since 2.2.6
	 * @author Grégory Viguier
	 */
	function secupress_author_base_save_user_options() {
		if ( empty( $_POST['user_id'] ) || ! isset( $_POST['user_nicename'] ) || ! secupress_author_base_user_can_edit_user_slug() ) {
			return;
		}

		$user_id = (int) $_POST['user_id'];

		check_admin_referer( 'update-user_' . $user_id );

		if ( ! ( $userdata = get_userdata( $user_id ) ) ) {
			return;
		}

		$def_user_nicename = sanitize_title( $userdata->user_login );
		$new_nicename      = sanitize_title( $_POST['user_nicename'], $def_user_nicename );

		if ( $new_nicename === $userdata->user_nicename ) {
			return;
		}

		if ( ! get_user_by( 'slug', $new_nicename ) ) {
			$updated = wp_update_user( array(
				'ID'            => $user_id,
				'user_nicename' => $new_nicename,
			) );

			if ( ! $updated ) {
				add_action( 'user_profile_update_errors', 'secupress_author_base_user_profile_slug_generic_error' );
			}
		} else {
			add_action( 'user_profile_update_errors', 'secupress_author_base_user_profile_slug_error' );
		}

		function secupress_author_base_user_profile_slug_generic_error( $errors ) {
			$errors->add( 'user_nicename', __( '<strong>Error</strong>: There was an error updating the author slug. Please try again.', 'secupress' ) );
		}

		function secupress_author_base_user_profile_slug_error( $errors ) {
			$errors->add( 'user_nicename', __( '<strong>Error</strong>: This profile URL slug is already registered. Please choose another one.', 'secupress' ) );
		}
	}


	/**
	 * Return true if the current user can edit the user slug.
	 *
	 * @since 2.2.6
	 * @author Grégory Viguier
	 * 
	 * @param (int) $user_id
	 * 
	 * @return (bool)
	 */
	function secupress_author_base_user_can_edit_user_slug( $user_id = 0 ) {
		return current_user_can( 'edit_users' ) || ( ( ( defined( 'IS_PROFILE_PAGE' ) && IS_PROFILE_PAGE ) || ( $user_id && get_current_user_id() === $user_id ) ) && apply_filters( 'secupress.plugins.user_can_edit_user_slug', false ) );
	}
}