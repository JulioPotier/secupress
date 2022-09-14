<?php
defined( 'ABSPATH' ) or die( 'Something went wrong.' );

/*
3rd party plugins compat/help
*/

/**
* SecuPress_Scan_Easy_Login
*/

// https://plugins.svn.wordpress.org/miniorange-2-factor-authentication/trunk/miniorange_2_factor_settings.php .
add_filter( 'secupress.scan.SecuPress_Scan_Easy_Login.activated', 'secupress_3rd_compat__miniorange_2_factor_authentication' );
function secupress_3rd_compat__miniorange_2_factor_authentication( $activated ) {
	if ( ! $activated && defined( 'MO2F_VERSION' ) ) {
		return 'Miniorange 2 Factor Authentication';
	}
	return $activated;
}

// https://plugins.svn.wordpress.org/jetpack/trunk/modules/sso.php .
add_filter( 'secupress.scan.SecuPress_Scan_Easy_Login.activated', 'secupress_3rd_compat__jetpack_sso' );
function secupress_3rd_compat__jetpack_sso( $activated ) {
	if ( class_exists( 'Jetpack' ) && Jetpack::is_active() && Jetpack::is_module_active( 'sso' ) ) {
		return 'Jetpack Secure Sign On';
	}
	return $activated;
}

// https://plugins.svn.wordpress.org/unikname-connect/trunk/unikname_connect.php
add_filter( 'secupress.scan.SecuPress_Scan_Easy_Login.activated', 'secupress_3rd_compat__unikname_connect' );
function secupress_3rd_compat__unikname_connect( $activated ) {
	if ( ! $activated && defined( 'UNIKNAME_VERSION' ) ) {
		return 'Unikname – Authentication (2FA) Passwordless Login';
	}
	return $activated;
}

// https://plugins.svn.wordpress.org/two-factor-authentication/trunk/two-factor-login.php .
add_filter( 'secupress.scan.SecuPress_Scan_Easy_Login.activated', 'secupress_3rd_compat__two_factor_authentication' );
function secupress_3rd_compat__two_factor_authentication( $activated ) {
	if ( ! $activated && defined( 'SIMBA_TFA_TEXT_DOMAIN' ) ) {
		return 'Two Factor Authentication';
	}
	return $activated;
}

// https://plugins.svn.wordpress.org/two-factor/trunk/two-factor.php .
add_filter( 'secupress.scan.SecuPress_Scan_Easy_Login.activated', 'secupress_3rd_compat__two_factor' );
function secupress_3rd_compat__two_factor( $activated ) {
	if ( ! $activated && defined( 'TWO_FACTOR_VERSION' ) ) {
		return 'Two Factor';
	}
	return $activated;
}

// https://plugins.svn.wordpress.org/2fas/trunk/constants.php .
add_filter( 'secupress.scan.SecuPress_Scan_Easy_Login.activated', 'secupress_3rd_compat__2fas' );
function secupress_3rd_compat__2fas( $activated ) {
	if ( ! $activated && defined( 'TWOFAS_PLUGIN_VERSION' ) ) {
		return '2fas';
	}
	return $activated;
}

// https://plugins.svn.wordpress.org/rublon/trunk/rublon2factor.php .
add_filter( 'secupress.scan.SecuPress_Scan_Easy_Login.activated', 'secupress_3rd_compat__rublon' );
function secupress_3rd_compat__rublon( $activated ) {
	if ( ! $activated && defined( 'RUBLON2FACTOR_PLUGIN_PATH' ) ) {
		return 'Rublon';
	}
	return $activated;
}

// https://plugins.svn.wordpress.org/loginizer/trunk/loginizer.php .
add_filter( 'secupress.scan.SecuPress_Scan_Easy_Login.activated', 'secupress_3rd_compat__loginizer' );
function secupress_3rd_compat__loginizer( $activated ) {
	if ( ! $activated && defined( 'LOGINIZER_VERSION' ) ) {
		return 'Loginizer';
	}
	return $activated;
}

// https://plugins.svn.wordpress.org/unloq/trunk/unloq.php .
add_filter( 'secupress.scan.SecuPress_Scan_Easy_Login.activated', 'secupress_3rd_compat__unloq' );
function secupress_3rd_compat__unloq( $activated ) {
	if ( ! $activated && defined( 'UQ_VERSION' ) ) {
		return 'Unloq';
	}
	return $activated;
}

// https://plugins.svn.wordpress.org/duo-wordpress/trunk/duo_web/duo_web.php .
add_filter( 'secupress.scan.SecuPress_Scan_Easy_Login.activated', 'secupress_3rd_compat__duo_wordpress' );
function secupress_3rd_compat__duo_wordpress( $activated ) {
	if ( ! $activated && class_exists( 'Duo' ) ) {
		return 'Duo WordPress';
	}
	return $activated;
}

// https://plugins.svn.wordpress.org/google-authenticator-per-user-prompt/trunk/google-authenticator-per-user-prompt.php .
add_filter( 'secupress.scan.SecuPress_Scan_Easy_Login.activated', 'secupress_3rd_compat__google_authenticator_per_user_prompt' );
function secupress_3rd_compat__google_authenticator_per_user_prompt( $activated ) {
	if ( ! $activated && class_exists( 'Google_Authenticator_Per_User_Prompt' ) ) {
		return 'Google Authenticator Per User Prompt';
	}
	return $activated;
}

// https://plugins.svn.wordpress.org/snapid-two-factor-authentication/trunk/snapid.php .
add_filter( 'secupress.scan.SecuPress_Scan_Easy_Login.activated', 'secupress_3rd_compat__snapid_two_factor_authentication' );
function secupress_3rd_compat__snapid_two_factor_authentication( $activated ) {
	if ( ! $activated && class_exists( 'WP_SnapID_Setup' ) ) {
		return 'SnapID Two Factor Authentication';
	}
	return $activated;
}

// https://plugins.svn.wordpress.org/google-authenticator/trunk/google-authenticator.php .
add_filter( 'secupress.scan.SecuPress_Scan_Easy_Login.activated', 'secupress_3rd_compat__google_authenticator' );
function secupress_3rd_compat__google_authenticator( $activated ) {
	if ( ! $activated && class_exists( 'GoogleAuthenticator' ) ) {
		return 'Google Authenticator';
	}
	return $activated;
}

// https://plugins.svn.wordpress.org/wp-google-authenticator/trunk/wp-google-authenticator.php .
add_filter( 'secupress.scan.SecuPress_Scan_Easy_Login.activated', 'secupress_3rd_compat__wp_google_authenticator' );
function secupress_3rd_compat__wp_google_authenticator( $activated ) {
	if ( ! $activated && class_exists( 'WPGA_VERSION' ) ) {
		return 'WP Google Authenticator';
	}
	return $activated;
}

// https://plugins.svn.wordpress.org/keyy/trunk/keyy.php .
add_filter( 'secupress.scan.SecuPress_Scan_Easy_Login.activated', 'secupress_3rd_compat__keyy' );
function secupress_3rd_compat__keyy( $activated ) {
	if ( ! $activated && class_exists( 'Keyy_Login_Plugin' ) ) {
		return 'Keyy';
	}
	return $activated;
}

// https://plugins.svn.wordpress.org/2fas-light/trunk/twofas_light.php .
add_filter( 'secupress.scan.SecuPress_Scan_Easy_Login.activated', 'secupress_3rd_compat__2fas_light' );
function secupress_3rd_compat__2fas_light( $activated ) {
	if ( ! $activated && defined( 'TWOFAS_LIGHT_FULL_TWOFAS_PLUGIN_ACTIVE_FLAG' ) && TWOFAS_LIGHT_FULL_TWOFAS_PLUGIN_ACTIVE_FLAG ) {
		return '2FAS Light';
	}
	return $activated;
}

// https://plugins.svn.wordpress.org/wordpress-2-step-verification/trunk/wordpress-2-step-verification.php .
add_filter( 'secupress.scan.SecuPress_Scan_Easy_Login.activated', 'secupress_3rd_compat__wordpress_2_step_verification' );
function secupress_3rd_compat__wordpress_2_step_verification( $activated ) {
	if ( ! $activated && defined( 'WP2SV_ASSETS_VERSION' ) ) {
		return 'WordPress 2 Step Verification';
	}
	return $activated;
}

/*
For wpserveur.net
*/
// Auto approve those rules (already done by their own nginx rules provided from us).
if ( strpos( gethostname(), 'wps' ) === 0 ) {
	add_filter( 'secupress.pre_scan.SecuPress_Scan_Bad_File_Extensions', '__return_true' );
	add_filter( 'secupress.pre_scan.SecuPress_Scan_Bad_URL_Access',      '__return_true' );
	add_filter( 'secupress.pre_scan.SecuPress_Scan_Directory_Listing',   '__return_true' );
	add_filter( 'secupress.pre_scan.SecuPress_Scan_Discloses',           '__return_true' );
	add_filter( 'secupress.pre_scan.SecuPress_Scan_PHP_Disclosure',      '__return_true' );
	add_filter( 'secupress.pre_scan.SecuPress_Scan_Readme_Discloses',    '__return_true' );
	add_filter( 'secupress.nginx.notice',                                '__return_false' );
}

/**
* For everyone now
* @since 1.4.9
*/
add_filter( 'secupress.settings.field.bbq-headers_user-agents-list',      '__return_null' );
add_filter( 'secupress.settings.field.bbq-url-content_bad-contents-list', '__return_null' );
