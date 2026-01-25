<?php
defined( 'ABSPATH' ) or die( 'Something went wrong.' );

# DEPRECATED CONSTANTS
/**
 * Be aware that they are not defined as soon as the plugin loads anymore.
 */

define( 'SECUPRESS_SCAN_SLUG',           'secupress_scanners' );  // Since 1.3.
define( 'SECUPRESS_FIX_SLUG',            'secupress_fixes' );     // Since 1.3.
define( 'SECUPRESS_SCAN_FIX_SITES_SLUG', 'secupress_fix_sites' ); // Since 1.3.

# DEPRECATED FUNCTIONS

/**
 * @since 1.1.4 Deprecated.
 */
function secupress_send_support_request( $summary, $description, $data ) {
	_deprecated_function( __FUNCTION__, '1.1.4', 'secupress_pro_send_support_request()' );
}


/**
 * @since 1.3 Deprecated.
 */
function secupress_display_transient_notices() {
	_deprecated_function( __FUNCTION__, '1.3', 'SecuPress_Admin_Notices::get_instance()->add_transient_notices()' );
}


/**
 * @since 1.3 Deprecated.
 */
function secupress_warning_no_license() {
	_deprecated_function( __FUNCTION__, '1.3', 'SecuPress_Pro_Admin_Free_Downgrade::get_instance()->maybe_warn_no_license()' );
}


/**
 * @since 1.1.4 Deprecated.
 */
function secupress_get_user_full_name( $user ) {
	_deprecated_function( __FUNCTION__, '1.1.4' );
}


/**
 * @since 1.1.4 Deprecated.
 */
function secupress_get_active_plugins() {
	_deprecated_function( __FUNCTION__, '1.1.4' );
}

/**
 * @since 1.4.9 Deprecated.
 */
function secupress_get_htaccess_ban_ip() {
	_deprecated_function( __FUNCTION__, '1.4.9' );
}


/**
 * Update the 2 files for GeoIP database on demand
 *
 * @since 2.1 Deprecated.
 * @since 1.4.9
 * @author Julio Potier
 **/
function secupress_geoips_update_datafiles() {
	_deprecated_function( __FUNCTION__, '2.1', 'secupress_geoips_update_datafile' );
	secupress_geoips_update_datafile();
}

/**
 * @since 2.2.5.2 Deprecated
 */
function secupress_blackhole_ban_ip() {
	_deprecated_function( __FUNCTION__, '2.2.5.2' );
}

/**
 * Clean the unzipped files
 *
 * @since 2.3.13 Deprecated.
 * @since 2.1
 * @author Julio Potier
 **/
function secupress_geoip_clean_zip() { // deprecated
	_deprecated_function( __FUNCTION__, '2.3.13' );
}

/**
 * @since 2.3.13 Deprecated.
 **/
function secupress_geoips_parse_file() {
	_deprecated_function( __FUNCTION__, '2.3.13' );
}

/**
 * Has been renamed to secupress_find_mu_plugin
 * @since 2.3.16 Deprecated.
*/
function secupress_find_muplugin( $filename ) {
	_deprecated_function( __FUNCTION__, '2.3.16', 'secupress_find_mu_plugin' );
	 return secupress_find_mu_plugin( $filename );
}

/**
  * @since 2.3.17 Deprecated
  */
function secupress_usernames_lexicomatisation() {
	_deprecated_function( __FUNCTION__, '2.3.17', '__return_empty_string' );
	return '';
}

/**
  * @since 2.3.19 Deprecated
  */
function secupress_author_base_user_can_edit_user_slug() {
	_deprecated_function( __FUNCTION__, '2.3.19', '__return_true' );
	return true;
}

/**
 * @since 2.3.19 Deprecated
 */
function secupress_authenticate_cookie( $user ) {
	_deprecated_function( __FUNCTION__, '2.3.19', '' );
	return $user;
}

/**
 * @since 2.3.19 Deprecated
 */
function secupress_blackhole_is_whitelisted() {
	_deprecated_function( __FUNCTION__, '2.3.19', '__return_true' );
	return true;
}