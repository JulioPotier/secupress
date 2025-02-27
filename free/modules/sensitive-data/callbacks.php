<?php
defined( 'ABSPATH' ) or	die( 'Something went wrong.' );

/** --------------------------------------------------------------------------------------------- */
/** ON MODULE SETTINGS SAVE ===================================================================== */
/** --------------------------------------------------------------------------------------------- */

/**
 * Callback to filter, sanitize, validate and de/activate submodules.
 *
 * @since 1.0
 *
 * @param (array) $settings The module settings.
 *
 * @return (array) The sanitized and validated settings.
 */
function secupress_sensitive_data_settings_callback( $settings ) {
	$modulenow = 'sensitive-data';
	$activate  = secupress_get_submodule_activations( $modulenow );
	$settings  = $settings && is_array( $settings ) ? $settings : array();

	if ( isset( $settings['sanitized'] ) ) {
		return $settings;
	}
	$settings['sanitized'] = 1;

	/*
	 * Each submodule has its own sanitization function.
	 * The `$settings` parameter is passed by reference.
	 */

	// Content Protection.
	secupress_content_protection_settings_callback( $modulenow, $settings, $activate );

	// WordPress Endpoints.
	secupress_wp_endpoints_settings_callback( $modulenow, $settings, $activate );

	/**
	 * Filter the settings before saving.
	 *
	 * @since 1.4.9
	 *
	 * @param (array)      $settings The module settings.
	 * @param (array\bool) $activate Contains the activation rules for the different modules
	 */
	$settings = apply_filters( "secupress_{$modulenow}_settings_callback", $settings, $activate );

	return $settings;
}


/**
 * Content Protection plugins.
 *
 * @since 1.0
 *
 * @param (string)     $modulenow Current module.
 * @param (bool|array) $activate  Used to (de)activate plugins.
 */
function secupress_content_protection_settings_callback( $modulenow, &$settings, $activate ) {
	if ( false === $activate ) {
		return;
	}
	// (De)Activation.
	secupress_manage_submodule( $modulenow,  '404guess', ! empty( $activate['content-protect_404guess'] ) && secupress_is_pro() );
	secupress_manage_submodule( $modulenow,  'hotlink', ! empty( $activate['content-protect_hotlink'] ) && secupress_is_pro() );
	secupress_manage_submodule( $modulenow,  'blackhole', ! empty( $activate['content-protect_blackhole'] ) && secupress_blackhole_is_robots_txt_enabled() );
	secupress_manage_submodule( $modulenow,  'directory-listing', ! empty( $activate['content-protect_directory-listing'] ) );
	secupress_manage_submodule( $modulenow,  'php-easter-egg', ! empty( $activate['content-protect_php-disclosure'] ) );
	secupress_manage_submodule( 'discloses', 'no-x-powered-by', ! empty( $activate['content-protect_php-version'] ) );
	secupress_manage_submodule( 'discloses', 'wp-version', ! empty( $activate['content-protect_wp-version'] ) );
	secupress_manage_submodule( 'discloses', 'readmes', ! empty( $activate['content-protect_readmes'] ) );
	if ( secupress_is_pro() ) {
		if ( ! empty( $settings['content-protect_bad-url-access_allowed-urls'] ) ) {
			$settings['content-protect_bad-url-access_allowed-urls'] = implode( "\n", array_filter( explode( "\n", $settings['content-protect_bad-url-access_allowed-urls'] ), '_secupress_bad_url_access_allowed_url_filter' ) );
			$settings['content-protect_bad-url-access_allowed-urls'] = _secupress_bad_url_access_allowed_urls_sanitize( $settings['content-protect_bad-url-access_allowed-urls'] );
		}
		$GLOBALS['contentprotectbadurlaccessallowedurls'] = isset( $settings['content-protect_bad-url-access_allowed-urls'] ) ? $settings['content-protect_bad-url-access_allowed-urls'] : false;
		secupress_manage_submodule( $modulenow,  'bad-url-access', ! empty( $activate['content-protect_bad-url-access'] ) );
	}

	$plugin_disclose = ! empty( $activate['content-protect_plugin-version-discloses'] ) && is_array( $activate['content-protect_plugin-version-discloses'] ) ? array_flip( $activate['content-protect_plugin-version-discloses'] ) : array();
	$wp_plugins      = array( 'woocommerce', 'wpml' );

	foreach ( $wp_plugins as $wp_plugin ) {
		secupress_manage_submodule( 'discloses', $wp_plugin . '-version', isset( $plugin_disclose[ $wp_plugin ] ) );
	}
}


/**
 * WordPress Endpoints plugins.
 *
 * @since 1.0
 *
 * @param (string)     $modulenow Current module.
 * @param (array)      $settings  The module settings, passed by reference.
 * @param (bool|array) $activate  Used to (de)activate plugins.
 */
function secupress_wp_endpoints_settings_callback( $modulenow, &$settings, $activate ) {
	global $wp_rewrite;
	// Settings.
	if ( ! empty( $settings['wp-endpoints_xmlrpc'] ) && is_array( $settings['wp-endpoints_xmlrpc'] ) ) {
		$xmlrpc = array(
			'block-all',
			'block-multi',
		);
		$settings['wp-endpoints_xmlrpc'] = array_intersect( $xmlrpc, $settings['wp-endpoints_xmlrpc'] );
		$settings['wp-endpoints_xmlrpc'] = array_slice( $settings['wp-endpoints_xmlrpc'], 0, 1 ); // Only one choice.
	} else {
		unset( $settings['wp-endpoints_xmlrpc'] );
	}

	// (De)Activation.
	secupress_manage_submodule( $modulenow, 'xmlrpc', ! empty( $settings['wp-endpoints_xmlrpc'] ) ); // `$settings`, not `$activate`.

	if ( ! empty( $settings['wp-endpoints_author_base'] ) ){
		$old_author_base = trim( secupress_get_module_option( 'wp-endpoints_author_base', 'author', 'sensitive-data' ), '/' );
		$new_author_base = sanitize_title( $settings['wp-endpoints_author_base'] );
		$message         = '';

		if ( $settings['wp-endpoints_author_base'] !== $old_author_base ) {

			if ( 'author' === $new_author_base || ! $new_author_base ) { // back to WP default, no need to check
				$settings['wp-endpoints_author_base'] = 'author';
				secupress_set_author_base( 'author' );
				return $settings;
			}

			$is_first_blog = is_multisite() && ! is_subdomain_install() && is_main_site();

			// Get all the available slugs
			$bases = array(); // slug => what

			// The "obvious" ones
			$bases['blog']                         = 'blog';
			$bases['date']                         = 'date';
			$bases[ $wp_rewrite->search_base ]     = 'search_base';
			$bases[ $wp_rewrite->comments_base ]   = 'comments_base';
			$bases[ $wp_rewrite->pagination_base ] = 'pagination_base';
			$bases[ $wp_rewrite->feed_base ]       = 'feed_base';

			// RSS
			if ( $wp_rewrite->feeds ) {
				foreach ( $wp_rewrite->feeds as $item ) {
					$bases[ $item  ] = $item;
				}
			}

			// Post types and taxos
			$post_types = get_post_types( array( 'public' => true ), 'objects' );
			$taxos      = get_taxonomies( array( 'public' => true ), 'objects' );
			$whatever   = array_merge( $taxos, $post_types );

			if ( $whatever ) {
				foreach ( $whatever as $what ) {
					// Singular
					if ( ! empty( $what->rewrite['slug'] ) ) {
						$bases[ $what->rewrite['slug'] ] = $what->name;
					} else {
						$bases[ $what->name ] = $what->name;
					}
					// Archive
					if ( ! empty( $what->has_archive ) && true !== $what->has_archive ) {
						$bases[ $what->has_archive ] = $what->name;
					}
				}
			}

			if ( ! empty( $bases[ $new_author_base ] ) ) {
				$message = '';
				if ( taxonomy_exists( $bases[ $new_author_base ] ) ) {
					$message = __( 'a taxonomy', 'secupress' );
				} elseif ( post_type_exists( $bases[ $new_author_base ] ) ) {
					$message = __( 'a custom post type', 'secupress' );
				}
			} elseif ( get_page_by_path( $new_author_base ) ) {
				$message = __( 'a page', 'secupress' );

			} elseif ( trim( get_option( 'permalink_structure' ), '/' ) === trim( $wp_rewrite->front . '%postname%', '/' ) && get_page_by_path( $new_author_base, 'OBJECT', 'post' ) ) {
				$message = __( 'a post', 'secupress' );
			}

			if ( $message ) {
				$settings['wp-endpoints_author_base'] = $old_author_base;
				$message = sprintf( __( '<strong>Error</strong>: This author page base is already used for %s. Please choose another one.', 'secupress' ), $message );
				secupress_add_transient_notice( $message, 'error', '' );
				return $settings;
			}

			$settings['wp-endpoints_author_base'] = $new_author_base;
			secupress_set_author_base( $new_author_base );
		}
	}

}
