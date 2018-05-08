<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );

/*
3rd party plugins compat/help
*/

/**
SecuPress_Scan_Easy_Login
*/

// https://plugins.svn.wordpress.org/miniorange-2-factor-authentication/trunk/miniorange_2_factor_settings.php .
add_filter( 'secupress.scan.SecuPress_Scan_Easy_Login.activated', 'secupress_3rd_compat__miniorange_2_factor_authentication' );
function secupress_3rd_compat__miniorange_2_factor_authentication( $activated ) {
	if ( ! $activated && defined( 'MOAUTH_PATH' ) ) {
		return 'Miniorange 2 Factor Authentication';
	}
	return $activated;
}

// https://plugins.svn.wordpress.org/two-factor-authentication/trunk/two-factor-login.php .
add_filter( 'secupress.scan.SecuPress_Scan_Easy_Login.activated', 'secupress_3rd_compat__two_factor_authentication' );
function secupress_3rd_compat__two_factor_authentication( $activated ) {
	if ( ! $activated && defined( 'SIMBA_TFA_PLUGIN_DIR' ) ) {
		return 'Two Factor Authentication';
	}
	return $activated;
}

// https://plugins.svn.wordpress.org/two-factor/trunk/two-factor.php .
add_filter( 'secupress.scan.SecuPress_Scan_Easy_Login.activated', 'secupress_3rd_compat__two_factor' );
function secupress_3rd_compat__two_factor( $activated ) {
	if ( ! $activated && defined( 'TWO_FACTOR_DIR' ) ) {
		return 'Two Factor';
	}
	return $activated;
}


// https://plugins.svn.wordpress.org/2fas/trunk/two-factor.php .
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

// https://plugins.svn.wordpress.org/wp-cerber/trunk/wp-cerber.php .
add_filter( 'secupress.scan.SecuPress_Scan_Easy_Login.activated', 'secupress_3rd_compat__cerber' );
function secupress_3rd_compat__cerber( $activated ) {
	if ( ! $activated && defined( 'CERBER_VER' ) ) {
		return 'Cerber';
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

// https://plugins.svn.wordpress.org/wordpress-2-step-verification/trunk/wordpress-2-step-verification.php .
add_filter( 'secupress.scan.SecuPress_Scan_Easy_Login.activated', 'secupress_3rd_compat__wordpress_2_step_verification' );
function secupress_3rd_compat__wordpress_2_step_verification( $activated ) {
	if ( ! $activated && class_exists( 'Wordpress2StepVerification' ) ) {
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
	add_filter( 'secupress.pre_scan.SecuPress_Scan_Bad_Url_Access',      '__return_true' );
	add_filter( 'secupress.pre_scan.SecuPress_Scan_Directory_Listing',   '__return_true' );
	add_filter( 'secupress.pre_scan.SecuPress_Scan_Discloses',           '__return_true' );
	add_filter( 'secupress.pre_scan.SecuPress_Scan_PHP_Disclosure',      '__return_true' );
	add_filter( 'secupress.pre_scan.SecuPress_Scan_Readme_Discloses',    '__return_true' );
	add_filter( 'secupress.nginx.notice',                                '__return_false' );
}

/*
For o2switch.net + HostPapa
*/
// Remove the textarea fields since they are already protecting it, leading our page to be caught.
if ( isset( $_SERVER['SERVER_ADDR'] ) && ( 0 === strpos( $_SERVER['SERVER_ADDR'], '109.234.' ) || 0 === strpos( $_SERVER['SERVER_ADDR'], '64.34.157.' ) ) ) {
	add_filter( 'secupress.settings.field.bbq-headers_user-agents-list',      '__return_null' );
	add_filter( 'secupress.settings.field.bbq-url-content_bad-contents-list', '__return_null' );
}
